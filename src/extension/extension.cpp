#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <richedit.h>

#include <Zydis/Zydis.h>
#include <dbghelp.h>
#include <dbgeng.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <cctype>
#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "decomp/analyzer.h"
#include "decomp/json.h"
#include "decomp/llm_client.h"
#include "decomp/pseudo_tokens.h"
#include "decomp/protocol.h"
#include "decomp/string_utils.h"
#include "decomp/verifier.h"

using Microsoft::WRL::ComPtr;

#ifndef EM_SETEDITSTYLE
#define EM_SETEDITSTYLE (WM_USER + 204)
#endif

#ifndef SES_EXTENDBACKCOLOR
#define SES_EXTENDBACKCOLOR 0x00000004
#endif

namespace
{
struct DebugApi
{
    ComPtr<IDebugClient> Client;
    ComPtr<IDebugControl> Control;
    ComPtr<IDebugControl4> Control4;
    ComPtr<IDebugAdvanced2> Advanced2;
    ComPtr<IDebugSymbols3> Symbols;
    ComPtr<IDebugSymbols5> Symbols5;
    ComPtr<IDebugDataSpaces4> DataSpaces;
    ComPtr<IDebugRegisters2> Registers;
};

struct DecodedInstructionContext
{
    uint64_t Address = 0;
    uint64_t EndAddress = 0;
    std::string Mnemonic;
    std::vector<std::string> Operands;
    bool HasRipRelativeMemory = false;
    uint64_t RipRelativeTarget = 0;
    bool HasBranchTarget = false;
    uint64_t BranchTarget = 0;
    bool IsCall = false;
    bool IsUnconditionalBranch = false;
    bool IsIndirect = false;
};

struct FunctionRegionBytes
{
    decomp::FunctionRegion Region;
    std::vector<uint8_t> Bytes;
};

struct SymbolLookupResult
{
    std::string Name;
    uint64_t Displacement = 0;
    bool Exact = false;
};

struct ScopedPdbSymbolRecord
{
    std::string Name;
    std::string TypeName;
    uint64_t ModuleBase = 0;
    ULONG TypeId = 0;
    ULONG Flags = 0;
    uint64_t Site = 0;
};

struct TypedBaseCandidate
{
    std::string Name;
    std::string TypeName;
    std::string BaseRegister;
    uint64_t ModuleBase = 0;
    ULONG TypeId = 0;
    double Confidence = 0.0;
};

struct EnumeratedFieldInfo
{
    std::string Name;
    std::string TypeName;
    uint64_t ModuleBase = 0;
    ULONG TypeId = 0;
    uint32_t Offset = 0;
};

std::wstring Utf8ToWide(const std::string& text)
{
    if (text.empty())
    {
        return std::wstring();
    }

    const int count = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);

    if (count <= 0)
    {
        return std::wstring();
    }

    std::wstring wide(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), count);
    return wide;
}

std::string WideToUtf8(const std::wstring& text)
{
    if (text.empty())
    {
        return std::string();
    }

    const int count = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);

    if (count <= 0)
    {
        return std::string();
    }

    std::string utf8(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), utf8.data(), count, nullptr, nullptr);
    return utf8;
}

std::vector<std::string> SplitOperands(const std::string& operandText)
{
    std::vector<std::string> operands;
    std::string current;
    int bracketDepth = 0;

    for (const char ch : operandText)
    {
        if (ch == '[')
        {
            ++bracketDepth;
        }
        else if (ch == ']' && bracketDepth > 0)
        {
            --bracketDepth;
        }

        if (ch == ',' && bracketDepth == 0)
        {
            operands.push_back(decomp::TrimCopy(current));
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty())
    {
        operands.push_back(decomp::TrimCopy(current));
    }

    return operands;
}

std::string ExtractOperandTextFromFormattedInstruction(const std::string& text)
{
    const std::string trimmed = decomp::TrimCopy(text);
    const size_t firstSpace = trimmed.find(' ');

    if (firstSpace == std::string::npos)
    {
        return std::string();
    }

    return decomp::TrimCopy(trimmed.substr(firstSpace + 1));
}

bool TryGetPreferredUiLocaleName(std::wstring& localeName)
{
    ULONG languageCount = 0;
    ULONG bufferChars = 0;

    if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &languageCount, nullptr, &bufferChars) != FALSE && bufferChars > 1)
    {
        std::wstring buffer(static_cast<size_t>(bufferChars), L'\0');

        if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &languageCount, buffer.data(), &bufferChars) != FALSE)
        {
            localeName.assign(buffer.c_str());

            if (!localeName.empty())
            {
                return true;
            }
        }
    }

    const LANGID uiLanguage = GetUserDefaultUILanguage();

    if (uiLanguage != 0)
    {
        std::array<wchar_t, LOCALE_NAME_MAX_LENGTH> buffer = {};

        if (LCIDToLocaleName(MAKELCID(uiLanguage, SORT_DEFAULT), buffer.data(), static_cast<int>(buffer.size()), 0) > 0)
        {
            localeName = buffer.data();
            return !localeName.empty();
        }
    }

    std::array<wchar_t, LOCALE_NAME_MAX_LENGTH> fallback = {};

    if (GetUserDefaultLocaleName(fallback.data(), static_cast<int>(fallback.size())) > 0)
    {
        localeName = fallback.data();
        return !localeName.empty();
    }

    return false;
}

std::string QueryLocaleInfoUtf8(const std::wstring& localeName, LCTYPE type)
{
    if (localeName.empty())
    {
        return std::string();
    }

    const int count = GetLocaleInfoEx(localeName.c_str(), type, nullptr, 0);

    if (count <= 1)
    {
        return std::string();
    }

    std::wstring buffer(static_cast<size_t>(count), L'\0');

    if (GetLocaleInfoEx(localeName.c_str(), type, buffer.data(), count) <= 0)
    {
        return std::string();
    }

    return WideToUtf8(buffer.c_str());
}

void ApplyPreferredNaturalLanguage(const decomp::LlmClientConfig& config, decomp::AnalysisFacts& facts)
{
    const std::string mode = decomp::ToLowerAscii(decomp::TrimCopy(config.DisplayLanguage.Mode));

    if (mode == "fixed")
    {
        const std::string configuredTag = decomp::TrimCopy(config.DisplayLanguage.Tag);
        std::string configuredName = decomp::TrimCopy(config.DisplayLanguage.Name);

        facts.PreferredNaturalLanguageTag.clear();

        if (!configuredTag.empty())
        {
            facts.PreferredNaturalLanguageTag = configuredTag;
        }

        if (configuredName.empty() && !configuredTag.empty())
        {
            configuredName = QueryLocaleInfoUtf8(Utf8ToWide(configuredTag), LOCALE_SENGLISHDISPLAYNAME);
        }

        if (!configuredName.empty())
        {
            facts.PreferredNaturalLanguageName = configuredName;
        }
        else if (!configuredTag.empty())
        {
            facts.PreferredNaturalLanguageName = configuredTag;
        }

        return;
    }

    std::wstring localeName;

    if (!TryGetPreferredUiLocaleName(localeName))
    {
        return;
    }

    const std::string localeTag = WideToUtf8(localeName);

    if (!localeTag.empty())
    {
        facts.PreferredNaturalLanguageTag = localeTag;
    }

    const std::string englishDisplayName = QueryLocaleInfoUtf8(localeName, LOCALE_SENGLISHDISPLAYNAME);

    if (!englishDisplayName.empty())
    {
        facts.PreferredNaturalLanguageName = englishDisplayName;
    }
}

void OutputLine(IDebugControl* control, IDebugControl4* control4, const char* format, ...)
{
    std::array<char, 4096> buffer = {};
    va_list args;
    va_start(args, format);
    std::vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);

    if (control4 != nullptr)
    {
        const std::wstring wide = Utf8ToWide(buffer.data());

        if (!wide.empty())
        {
            control4->OutputWide(DEBUG_OUTPUT_NORMAL, L"%s", wide.c_str());
            return;
        }
    }

    if (control != nullptr)
    {
        control->Output(DEBUG_OUTPUT_NORMAL, "%s", buffer.data());
    }
}

void OutputVerbose(IDebugControl* control, IDebugControl4* control4, const decomp::DecompOptions& options, const char* format, ...)
{
    if (!options.VerboseOutput)
    {
        return;
    }

    std::array<char, 4096> buffer = {};
    va_list args;
    va_start(args, format);
    std::vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);

    OutputLine(control, control4, "[decomp] %s\n", buffer.data());
}

bool ShouldShowProgress(const decomp::DecompOptions& options)
{
    return !options.VerboseOutput
        && !options.JsonOutput
        && !options.FactsOnlyOutput
        && !options.DebugPromptOutput
        && !options.DataModelOutput
        && !options.LastExplainOutput
        && !options.LastFactsOutput
        && !options.LastJsonOutput
        && !options.LastDataModelOutput
        && !options.LastDebugPromptOutput
        && !options.PlanOutput;
}

void OutputProgress(IDebugControl* control, IDebugControl4* control4, const decomp::DecompOptions& options, const char* format, ...)
{
    if (!ShouldShowProgress(options))
    {
        return;
    }

    std::array<char, 4096> buffer = {};
    va_list args;
    va_start(args, format);
    std::vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);

    OutputLine(control, control4, "[decomp] %s\n", buffer.data());
}

bool IsUserInterruptRequested(IDebugControl* control)
{
    return control != nullptr && control->GetInterrupt() == S_OK;
}

bool AbortIfUserInterrupted(IDebugControl* control, IDebugControl4* control4, const decomp::DecompOptions& options, const char* stage)
{
    if (!IsUserInterruptRequested(control))
    {
        return false;
    }

    OutputVerbose(control, control4, options, "cancel requested during %s", stage);
    OutputLine(control, control4, "decomp cancelled by user\n");
    return true;
}

struct AsyncLlmRunState
{
    std::mutex Mutex;
    std::deque<std::string> VerboseMessages;
    std::atomic<bool> CancelRequested{ false };
    std::atomic<bool> Done{ false };
    bool Success = false;
    decomp::AnalyzeResponse Response;
    std::string Error;
};

void DrainAsyncVerboseMessages(
    const std::shared_ptr<AsyncLlmRunState>& state,
    IDebugControl* control,
    IDebugControl4* control4)
{
    std::deque<std::string> messages;

    {
        std::lock_guard<std::mutex> lock(state->Mutex);
        messages.swap(state->VerboseMessages);
    }

    for (const auto& message : messages)
    {
        OutputLine(control, control4, "[decomp] %s\n", message.c_str());
    }
}

bool AnalyzeWithLlmInterruptible(
    const decomp::AnalyzeRequest& request,
    decomp::LlmClientConfig config,
    IDebugControl* control,
    IDebugControl4* control4,
    const decomp::DecompOptions& options,
    decomp::AnalyzeResponse& response,
    std::string& error,
    bool& cancelled)
{
    cancelled = false;
    const auto state = std::make_shared<AsyncLlmRunState>();

    config.ShouldCancel = [state]()
    {
        return state->CancelRequested.load();
    };

    if (options.VerboseOutput)
    {
        config.VerboseLog = [state](const std::string& message)
        {
            std::lock_guard<std::mutex> lock(state->Mutex);
            state->VerboseMessages.push_back(message);
        };
    }
    else if (ShouldShowProgress(options))
    {
        config.ProgressLog = [state](const std::string& message)
        {
            std::lock_guard<std::mutex> lock(state->Mutex);
            state->VerboseMessages.push_back(message);
        };
    }

    std::thread worker([state, request, config]() mutable
    {
        try
        {
            state->Success = decomp::AnalyzeWithLlm(request, config, state->Response, state->Error);
        }
        catch (const std::exception& ex)
        {
            state->Success = false;
            state->Error = ex.what();
        }
        catch (...)
        {
            state->Success = false;
            state->Error = "unknown LLM worker failure";
        }

        state->Done.store(true);
    });

    while (!state->Done.load())
    {
        DrainAsyncVerboseMessages(state, control, control4);

        if (IsUserInterruptRequested(control))
        {
            cancelled = true;
            state->CancelRequested.store(true);
            OutputLine(control, control4, "decomp cancellation requested; stopping LLM wait\n");
            CancelSynchronousIo(worker.native_handle());

            for (uint32_t waitAttempt = 0; waitAttempt < 50 && !state->Done.load(); ++waitAttempt)
            {
                DrainAsyncVerboseMessages(state, control, control4);
                Sleep(100);
            }

            break;
        }

        Sleep(100);
    }

    if (worker.joinable())
    {
        if (cancelled && !state->Done.load())
        {
            OutputLine(control, control4, "decomp cancellation returned before the LLM worker fully stopped\n");
            worker.detach();
        }
        else
        {
            worker.join();
        }
    }

    DrainAsyncVerboseMessages(state, control, control4);

    if (cancelled)
    {
        error = state->Error.empty() ? "operation cancelled by user" : state->Error;
        return false;
    }

    response = std::move(state->Response);
    error = std::move(state->Error);
    return state->Success;
}

void OutputTextRaw(IDebugControl* control, IDebugControl4* control4, const std::string& text)
{
    if (text.empty())
    {
        return;
    }

    if (control4 != nullptr)
    {
        const std::wstring wide = Utf8ToWide(text);

        if (!wide.empty())
        {
            control4->OutputWide(DEBUG_OUTPUT_NORMAL, L"%s", wide.c_str());
            return;
        }
    }

    if (control != nullptr)
    {
        control->Output(DEBUG_OUTPUT_NORMAL, "%s", text.c_str());
    }
}

bool AreOutputCallbacksDmlAware(IDebugAdvanced2* advanced2)
{
    return advanced2 != nullptr
        && advanced2->Request(DEBUG_REQUEST_CURRENT_OUTPUT_CALLBACKS_ARE_DML_AWARE, nullptr, 0, nullptr, 0, nullptr) == S_OK;
}

void OutputDmlRaw(IDebugControl* control, IDebugControl4* control4, const std::string& text)
{
    if (text.empty())
    {
        return;
    }

    if (control4 != nullptr)
    {
        const std::wstring wide = Utf8ToWide(text);

        if (!wide.empty())
        {
            control4->ControlledOutputWide(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, L"%s", wide.c_str());
            return;
        }
    }

    if (control != nullptr)
    {
        control->ControlledOutput(DEBUG_OUTCTL_AMBIENT_DML, DEBUG_OUTPUT_NORMAL, "%s", text.c_str());
    }
}

std::string EscapeDmlText(const std::string& text)
{
    std::string escaped;
    escaped.reserve(text.size() + 16);

    for (const char ch : text)
    {
        switch (ch)
        {
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        case '"':
            escaped += "&quot;";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

std::string BuildDmlLink(const std::string& text, const std::string& command)
{
    return "<link cmd=\"" + EscapeDmlText(command) + "\">" + EscapeDmlText(text) + "</link>";
}

std::string QuoteCommandArgument(const std::string& value)
{
    if (value.find_first_of(" \t\r\n\"") == std::string::npos)
    {
        return value;
    }

    std::string quoted = "\"";

    for (const char ch : value)
    {
        if (ch == '"')
        {
            continue;
        }

        quoted.push_back(ch);
    }

    quoted.push_back('"');
    return quoted;
}

class ResponseOutputSink
{
public:
    virtual ~ResponseOutputSink() = default;

    virtual bool SupportsDmlMarkup() const
    {
        return false;
    }

    virtual bool SupportsLinks() const
    {
        return false;
    }

    virtual void WriteText(const std::string& text) = 0;

    virtual void WriteDmlMarkup(const std::string& text)
    {
        WriteText(text);
    }

    virtual void WriteLink(const std::string& text, const std::string& command)
    {
        WriteText(text);

        if (!command.empty())
        {
            WriteText(" [cmd: " + command + "]");
        }
    }
};

class ConsoleResponseOutputSink final : public ResponseOutputSink
{
public:
    ConsoleResponseOutputSink(
        IDebugControl* control,
        IDebugControl4* control4,
        IDebugAdvanced2* advanced2)
        : Control(control),
          Control4(control4),
          DmlAware(AreOutputCallbacksDmlAware(advanced2))
    {
    }

    bool SupportsDmlMarkup() const override
    {
        return DmlAware;
    }

    bool SupportsLinks() const override
    {
        return DmlAware;
    }

    void WriteText(const std::string& text) override
    {
        OutputTextRaw(Control, Control4, text);
    }

    void WriteDmlMarkup(const std::string& text) override
    {
        if (DmlAware)
        {
            OutputDmlRaw(Control, Control4, text);
            return;
        }

        WriteText(text);
    }

    void WriteLink(const std::string& text, const std::string& command) override
    {
        if (DmlAware)
        {
            OutputDmlRaw(Control, Control4, BuildDmlLink(text, command));
            return;
        }

        WriteText(text);
    }

private:
    IDebugControl* Control = nullptr;
    IDebugControl4* Control4 = nullptr;
    bool DmlAware = false;
};

class PlainTextResponseOutputSink final : public ResponseOutputSink
{
public:
    explicit PlainTextResponseOutputSink(bool supportsLinks = true)
        : LinkSupport(supportsLinks)
    {
    }

    bool SupportsLinks() const override
    {
        return LinkSupport;
    }

    void WriteText(const std::string& text) override
    {
        Text += text;
    }

    void WriteLink(const std::string& text, const std::string& command) override
    {
        Text += text;

        if (!command.empty())
        {
            Text += " [cmd: ";
            Text += command;
            Text += "]";
        }
    }

    const std::string& GetText() const
    {
        return Text;
    }

private:
    bool LinkSupport = true;
    std::string Text;
};

void SinkOutputLine(ResponseOutputSink& sink, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    const int required = _vscprintf(format, args);
    va_end(args);

    if (required < 0)
    {
        return;
    }

    std::vector<char> buffer(static_cast<size_t>(required) + 1U, '\0');
    va_start(args, format);
    std::vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);
    sink.WriteText(buffer.data());
}

void OutputLinkInline(ResponseOutputSink& sink, const std::string& text, const std::string& command)
{
    if (sink.SupportsLinks())
    {
        sink.WriteLink(text, command);
        return;
    }

    sink.WriteText(text);
}

void OutputLinkLine(ResponseOutputSink& sink, const std::string& text, const std::string& command)
{
    OutputLinkInline(sink, text, command);
    sink.WriteText("\n");
}

const decomp::BasicBlock* FindBlockById(const decomp::AnalysisFacts& facts, const std::string& id)
{
    for (const auto& block : facts.Blocks)
    {
        if (block.Id == id)
        {
            return &block;
        }
    }

    return nullptr;
}

std::string BuildDisassembleCommand(uint64_t start, uint64_t end)
{
    if (end > start)
    {
        return "u " + decomp::HexU64(start) + " " + decomp::HexU64(end);
    }

    return "u " + decomp::HexU64(start);
}

std::string BuildDisassembleAddressCommand(uint64_t address)
{
    return BuildDisassembleCommand(address, address + 0x30);
}

void AppendUniqueString(std::vector<std::string>& values, const std::string& value)
{
    const std::string trimmed = decomp::TrimCopy(value);

    if (trimmed.empty())
    {
        return;
    }

    const auto duplicate = std::find_if(
        values.begin(),
        values.end(),
        [&trimmed](const std::string& existing)
        {
            return decomp::ToLowerAscii(decomp::TrimCopy(existing)) == decomp::ToLowerAscii(trimmed);
        });

    if (duplicate == values.end())
    {
        values.push_back(trimmed);
    }
}

std::vector<std::string> SplitCorrectionPair(const std::string& text, char separator)
{
    const size_t index = text.find(separator);

    if (index == std::string::npos)
    {
        return {};
    }

    return { decomp::TrimCopy(text.substr(0, index)), decomp::TrimCopy(text.substr(index + 1)) };
}

bool IsIdentifierBoundary(char ch)
{
    return std::isalnum(static_cast<unsigned char>(ch)) == 0 && ch != '_';
}

void ReplaceIdentifier(std::string& text, const std::string& from, const std::string& to)
{
    if (from.empty() || to.empty() || from == to)
    {
        return;
    }

    size_t index = 0;

    while ((index = text.find(from, index)) != std::string::npos)
    {
        const bool leftOk = index == 0 || IsIdentifierBoundary(text[index - 1]);
        const size_t rightIndex = index + from.size();
        const bool rightOk = rightIndex >= text.size() || IsIdentifierBoundary(text[rightIndex]);

        if (leftOk && rightOk)
        {
            text.replace(index, from.size(), to);
            index += to.size();
        }
        else
        {
            index += from.size();
        }
    }
}

struct PseudoCodeTokenStyle
{
    std::string Foreground;
    bool Bold = false;
    bool Italic = false;
    bool Underline = false;
};

PseudoCodeTokenStyle GetPseudoCodeTokenStyle(const std::string& kind, const decomp::PseudoCodeHighlightConfig& highlight)
{
    if (kind == "keyword")
    {
        return { highlight.KeywordColor, true, false, false };
    }

    if (kind == "type")
    {
        return { highlight.TypeColor, true, false, false };
    }

    if (kind == "function_name")
    {
        return { highlight.FunctionNameColor, false, false, true };
    }

    if (kind == "identifier")
    {
        return { highlight.IdentifierColor, false, false, false };
    }

    if (kind == "number")
    {
        return { highlight.NumberColor, false, false, false };
    }

    if (kind == "string")
    {
        return { highlight.StringColor, false, false, false };
    }

    if (kind == "char")
    {
        return { highlight.CharColor, false, false, false };
    }

    if (kind == "comment")
    {
        return { highlight.CommentColor, false, true, false };
    }

    if (kind == "preprocessor")
    {
        return { highlight.PreprocessorColor, true, false, false };
    }

    if (kind == "operator")
    {
        return { highlight.OperatorColor, false, false, false };
    }

    if (kind == "punctuation")
    {
        return { highlight.PunctuationColor, false, false, false };
    }

    return {};
}

void PrintPseudoCodeHighlighted(
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& config,
    ResponseOutputSink& sink)
{
    if (response.PseudoC.empty())
    {
        return;
    }

    if (!sink.SupportsDmlMarkup() || response.PseudoCTokens.empty())
    {
        sink.WriteText(response.PseudoC);
        return;
    }

    for (const auto& token : response.PseudoCTokens)
    {
        if (token.Text.empty())
        {
            continue;
        }

        if (token.Kind == "newline" || token.Kind == "whitespace")
        {
            sink.WriteDmlMarkup(token.Text);
            continue;
        }

        const PseudoCodeTokenStyle style = GetPseudoCodeTokenStyle(token.Kind, config.Highlight);
        const std::string escapedText = EscapeDmlText(token.Text);

        if (style.Foreground.empty())
        {
            sink.WriteDmlMarkup(escapedText);
            continue;
        }

        std::string markup = "<col fg=\"";
        markup += style.Foreground;
        markup += "\">";

        if (style.Bold)
        {
            markup += "<b>";
        }

        if (style.Italic)
        {
            markup += "<i>";
        }

        if (style.Underline)
        {
            markup += "<u>";
        }

        markup += escapedText;

        if (style.Underline)
        {
            markup += "</u>";
        }

        if (style.Italic)
        {
            markup += "</i>";
        }

        if (style.Bold)
        {
            markup += "</b>";
        }

        markup += "</col>";
        sink.WriteDmlMarkup(markup);
    }
}

bool AcquireDebugApi(PDEBUG_CLIENT client, DebugApi& api)
{
    bool success = false;

    do
    {
        if (client == nullptr)
        {
            break;
        }

        if (FAILED(client->QueryInterface(__uuidof(IDebugClient), reinterpret_cast<void**>(api.Client.GetAddressOf()))))
        {
            break;
        }

        if (FAILED(client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(api.Control.GetAddressOf()))))
        {
            break;
        }

        client->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<void**>(api.Control4.GetAddressOf()));
        client->QueryInterface(__uuidof(IDebugAdvanced2), reinterpret_cast<void**>(api.Advanced2.GetAddressOf()));

        if (FAILED(client->QueryInterface(__uuidof(IDebugSymbols3), reinterpret_cast<void**>(api.Symbols.GetAddressOf()))))
        {
            break;
        }

        client->QueryInterface(__uuidof(IDebugSymbols5), reinterpret_cast<void**>(api.Symbols5.GetAddressOf()));

        if (FAILED(client->QueryInterface(__uuidof(IDebugDataSpaces4), reinterpret_cast<void**>(api.DataSpaces.GetAddressOf()))))
        {
            break;
        }

        client->QueryInterface(__uuidof(IDebugRegisters2), reinterpret_cast<void**>(api.Registers.GetAddressOf()));

        success = true;
    }
    while (false);

    return success;
}

bool ParseU32Value(const std::string& text, uint32_t& value)
{
    uint64_t parsed = 0;

    if (!decomp::TryParseUnsigned(text, parsed) || parsed > 0xFFFFFFFFULL)
    {
        return false;
    }

    value = static_cast<uint32_t>(parsed);
    return true;
}

bool ApplyViewOption(const std::string& rawValue, decomp::DecompOptions& options, std::string& error)
{
    const std::string value = decomp::ToLowerAscii(decomp::TrimCopy(rawValue));

    if (value == "default" || value == "normal" || value == "full")
    {
        return true;
    }

    if (value == "brief")
    {
        options.BriefOutput = true;
        return true;
    }

    if (value == "explain")
    {
        options.ExplainOutput = true;
        return true;
    }

    if (value == "json")
    {
        options.JsonOutput = true;
        return true;
    }

    if (value == "facts" || value == "facts-only")
    {
        options.FactsOnlyOutput = true;
        options.DisableLlm = true;
        return true;
    }

    if (value == "prompt" || value == "debug-prompt")
    {
        options.DebugPromptOutput = true;
        options.DisableLlm = true;
        return true;
    }

    if (value == "data" || value == "data-model" || value == "datamodel" || value == "dx")
    {
        options.DataModelOutput = true;
        return true;
    }

    if (value == "window" || value == "viewer")
    {
        options.WindowOutput = true;
        return true;
    }

    if (value == "analyzer" || value == "no-llm")
    {
        options.DisableLlm = true;
        return true;
    }

    if (value == "plan" || value == "dry-run" || value == "dryrun")
    {
        options.PlanOutput = true;
        options.DisableLlm = true;
        return true;
    }

    error = "unknown view: " + rawValue;
    return false;
}

bool ApplyLastOption(const std::string& rawValue, decomp::DecompOptions& options, std::string& error)
{
    std::string modeText = decomp::TrimCopy(rawValue);
    const size_t indexSeparator = modeText.find(':');

    if (indexSeparator != std::string::npos)
    {
        uint64_t parsedIndex = 0;
        const std::string indexText = modeText.substr(0, indexSeparator);

        if (decomp::TryParseUnsigned(indexText, parsedIndex))
        {
            if (parsedIndex == 0 || parsedIndex > 64)
            {
                error = "invalid cached artifact index: " + indexText;
                return false;
            }

            options.LastCacheIndex = static_cast<uint32_t>(parsedIndex);
            modeText = modeText.substr(indexSeparator + 1);
        }
    }

    const std::string value = decomp::ToLowerAscii(decomp::TrimCopy(modeText));

    if (value == "explain")
    {
        options.LastExplainOutput = true;
        return true;
    }

    if (value == "facts" || value == "facts-only")
    {
        options.LastFactsOutput = true;
        return true;
    }

    if (value == "json")
    {
        options.LastJsonOutput = true;
        return true;
    }

    if (value == "data" || value == "data-model" || value == "datamodel" || value == "dx")
    {
        options.LastDataModelOutput = true;
        return true;
    }

    if (value == "prompt" || value == "debug-prompt")
    {
        options.LastDebugPromptOutput = true;
        return true;
    }

    error = "unknown cached artifact: " + rawValue;
    return false;
}

bool ApplyLimitOption(const std::string& rawValue, decomp::DecompOptions& options, std::string& error)
{
    const std::string value = decomp::ToLowerAscii(decomp::TrimCopy(rawValue));

    if (value == "deep")
    {
        options.MaxInstructions = 8192;
        return true;
    }

    if (value == "huge")
    {
        options.MaxInstructions = 16384;
        return true;
    }

    if (ParseU32Value(rawValue, options.MaxInstructions))
    {
        return true;
    }

    error = "invalid limit value";
    return false;
}

bool ApplyFixOption(const std::string& rawValue, decomp::DecompOptions& options, std::string& error)
{
    const size_t separator = rawValue.find(':');
    const std::string kind = decomp::ToLowerAscii(decomp::TrimCopy(separator == std::string::npos ? rawValue : rawValue.substr(0, separator)));
    const std::string value = separator == std::string::npos ? std::string() : rawValue.substr(separator + 1);

    if (kind == "clear" || kind == "reset")
    {
        options.ClearUserOverrides = true;
        return true;
    }

    if (value.empty())
    {
        error = "missing fix value";
        return false;
    }

    if (kind == "noreturn" || kind == "no-return")
    {
        options.NoReturnOverrides.push_back(value);
        return true;
    }

    if (kind == "type")
    {
        options.TypeOverrides.push_back(value);
        return true;
    }

    if (kind == "field")
    {
        options.FieldOverrides.push_back(value);
        return true;
    }

    if (kind == "rename")
    {
        options.RenameOverrides.push_back(value);
        return true;
    }

    error = "unknown fix kind: " + kind;
    return false;
}

std::string ExtractOperationText(const std::string& line)
{
    const std::string trimmed = decomp::TrimCopy(line);
    const size_t colon = trimmed.find(':');

    if (colon != std::string::npos && colon + 1 < trimmed.size())
    {
        const std::string afterColon = decomp::TrimCopy(trimmed.substr(colon + 1));

        if (!afterColon.empty() && std::isalpha(static_cast<unsigned char>(afterColon[0])) != 0)
        {
            return afterColon;
        }
    }

    std::string best = trimmed;
    size_t index = 0;

    while (index < trimmed.size())
    {
        size_t runStart = index;

        while (index < trimmed.size() && trimmed[index] == ' ')
        {
            ++index;
        }

        const size_t runLength = index - runStart;

        if (runLength >= 2 && index < trimmed.size())
        {
            const std::string candidate = decomp::TrimCopy(trimmed.substr(index));

            if (!candidate.empty() && std::isalpha(static_cast<unsigned char>(candidate[0])) != 0)
            {
                best = candidate;
            }
        }

        while (index < trimmed.size() && trimmed[index] != ' ')
        {
            ++index;
        }
    }

    return best;
}

std::string ExtractMnemonic(const std::string& operationText)
{
    const std::string trimmed = decomp::TrimCopy(operationText);
    const size_t firstSpace = trimmed.find(' ');

    if (firstSpace == std::string::npos)
    {
        return decomp::ToLowerAscii(trimmed);
    }

    return decomp::ToLowerAscii(trimmed.substr(0, firstSpace));
}

std::string ExtractOperandText(const std::string& operationText)
{
    const std::string trimmed = decomp::TrimCopy(operationText);
    const size_t firstSpace = trimmed.find(' ');

    if (firstSpace == std::string::npos)
    {
        return std::string();
    }

    return decomp::TrimCopy(trimmed.substr(firstSpace + 1));
}

bool IsReturnMnemonic(const std::string& mnemonic)
{
    return mnemonic == "ret" || mnemonic == "retn" || mnemonic == "retf";
}

bool IsCallMnemonic(const std::string& mnemonic)
{
    return mnemonic == "call";
}

bool IsUnconditionalJumpMnemonic(const std::string& mnemonic)
{
    return mnemonic == "jmp";
}

bool IsTrapMnemonic(const std::string& mnemonic)
{
    return mnemonic == "int3"
        || mnemonic == "ud2"
        || mnemonic == "icebp"
        || mnemonic == "hlt";
}

bool IsNoReturnTarget(const std::string& target)
{
    if (decomp::ContainsInsensitive(target, "__fastfail")
        || decomp::ContainsInsensitive(target, "RtlFailFast")
        || decomp::ContainsInsensitive(target, "RaiseFailFastException")
        || decomp::ContainsInsensitive(target, "TerminateProcess")
        || decomp::ContainsInsensitive(target, "ExitProcess"))
    {
        return true;
    }

    const char* overrideValue = std::getenv("DECOMP_NORETURN_OVERRIDES");
    const std::string overrides = overrideValue == nullptr ? std::string() : overrideValue;
    std::string current;

    for (char ch : overrides)
    {
        if (ch == ',' || ch == ';')
        {
            const std::string token = decomp::TrimCopy(current);

            if (!token.empty() && decomp::ContainsInsensitive(target, token))
            {
                return true;
            }

            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    const std::string token = decomp::TrimCopy(current);
    return !token.empty() && decomp::ContainsInsensitive(target, token);
}

bool ShouldStopFallbackDisassembly(const std::string& line)
{
    const std::string operationText = ExtractOperationText(line);
    const std::string mnemonic = ExtractMnemonic(operationText);

    if (IsReturnMnemonic(mnemonic) || IsUnconditionalJumpMnemonic(mnemonic) || IsTrapMnemonic(mnemonic))
    {
        return true;
    }

    if (IsCallMnemonic(mnemonic))
    {
        return IsNoReturnTarget(ExtractOperandText(operationText));
    }

    return false;
}

bool ParseCommandLine(const char* args, decomp::DecompOptions& options, std::string& target, std::string& error)
{
    bool success = false;
    const std::string argText = (args == nullptr) ? std::string() : std::string(args);
    const std::vector<std::string> tokens = decomp::TokenizeCommandLine(argText);

    do
    {
        for (const auto& token : tokens)
        {
            if (token.empty())
            {
                continue;
            }

            if (token[0] != '/' && token[0] != '-')
            {
                target = token;
                continue;
            }

            const std::string rawOption = token.substr(1);
            const std::string option = decomp::ToLowerAscii(rawOption);

            if (option == "live")
            {
                options.UseLiveMemory = true;
            }
            else if (option == "brief")
            {
                options.BriefOutput = true;
            }
            else if (option == "json")
            {
                options.JsonOutput = true;
            }
            else if (option == "explain")
            {
                options.ExplainOutput = true;
            }
            else if (option == "facts-only")
            {
                options.FactsOnlyOutput = true;
                options.DisableLlm = true;
            }
            else if (option == "debug-prompt")
            {
                options.DebugPromptOutput = true;
                options.DisableLlm = true;
            }
            else if (option == "data-model" || option == "datamodel" || option == "dx")
            {
                options.DataModelOutput = true;
            }
            else if (option == "last-json")
            {
                options.LastJsonOutput = true;
            }
            else if (option == "last-explain")
            {
                options.LastExplainOutput = true;
            }
            else if (option == "last-facts" || option == "last-facts-only")
            {
                options.LastFactsOutput = true;
            }
            else if (option == "last-data-model" || option == "last-dx")
            {
                options.LastDataModelOutput = true;
            }
            else if (option == "last-prompt")
            {
                options.LastDebugPromptOutput = true;
            }
            else if (option == "clear-overrides")
            {
                options.ClearUserOverrides = true;
            }
            else if (option == "verbose")
            {
                options.VerboseOutput = true;
            }
            else if (option == "history")
            {
                options.HistoryOutput = true;
            }
            else if (option == "doctor")
            {
                options.DoctorOutput = true;
            }
            else if (option == "doctor:net")
            {
                options.DoctorOutput = true;
                options.DoctorNetwork = true;
            }
            else if (option == "no-llm")
            {
                options.DisableLlm = true;
            }
            else if (option == "dry-run" || option == "dryrun" || option == "plan")
            {
                options.PlanOutput = true;
                options.DisableLlm = true;
            }
            else if (option == "deep")
            {
                options.MaxInstructions = 8192;
            }
            else if (option == "huge")
            {
                options.MaxInstructions = 16384;
            }
            else if (decomp::StartsWithInsensitive(option, "view:") || decomp::StartsWithInsensitive(option, "mode:"))
            {
                const size_t separator = rawOption.find(':');

                if (separator == std::string::npos || !ApplyViewOption(rawOption.substr(separator + 1), options, error))
                {
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "last:"))
            {
                if (!ApplyLastOption(rawOption.substr(5), options, error))
                {
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "limit:"))
            {
                if (!ApplyLimitOption(rawOption.substr(6), options, error))
                {
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "fix:"))
            {
                if (!ApplyFixOption(rawOption.substr(4), options, error))
                {
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "timeout:"))
            {
                if (!ParseU32Value(rawOption.substr(8), options.TimeoutMs))
                {
                    error = "invalid timeout value";
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "maxinsn:"))
            {
                if (!ParseU32Value(rawOption.substr(8), options.MaxInstructions))
                {
                    error = "invalid maxinsn value";
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "noreturn:"))
            {
                options.NoReturnOverrides.push_back(rawOption.substr(9));
            }
            else if (decomp::StartsWithInsensitive(option, "type:"))
            {
                options.TypeOverrides.push_back(rawOption.substr(5));
            }
            else if (decomp::StartsWithInsensitive(option, "field:"))
            {
                options.FieldOverrides.push_back(rawOption.substr(6));
            }
            else if (decomp::StartsWithInsensitive(option, "rename:"))
            {
                options.RenameOverrides.push_back(rawOption.substr(7));
            }
            else
            {
                error = "unknown option: " + token;
                break;
            }
        }
        if (!error.empty())
        {
            break;
        }

        if (target.empty()
            && !options.LastExplainOutput
            && !options.LastFactsOutput
            && !options.LastJsonOutput
            && !options.LastDataModelOutput
            && !options.LastDebugPromptOutput
            && !options.DoctorOutput
            && !options.HistoryOutput
            && !options.WindowOutput
            && !options.ClearUserOverrides)
        {
            error = "missing target";
            break;
        }
        success = true;
    }
    while (false);

    return success;
}

decomp::DebugSessionKind GetSessionKind(IDebugControl* control)
{
    ULONG debugClass = 0;
    ULONG qualifier = 0;

    if (control != nullptr && SUCCEEDED(control->GetDebuggeeType(&debugClass, &qualifier)))
    {
        if (debugClass == DEBUG_CLASS_KERNEL)
        {
            return decomp::DebugSessionKind::Kernel;
        }

        if (debugClass == DEBUG_CLASS_USER_WINDOWS)
        {
            return decomp::DebugSessionKind::User;
        }
    }

    return decomp::DebugSessionKind::Unknown;
}

std::string DebugClassToString(ULONG debugClass)
{
    switch (debugClass)
    {
    case DEBUG_CLASS_KERNEL:
        return "kernel";
    case DEBUG_CLASS_USER_WINDOWS:
        return "user_windows";
    default:
        return "unknown(" + std::to_string(debugClass) + ")";
    }
}

std::string DebugQualifierToString(ULONG debugClass, ULONG qualifier)
{
    if (debugClass == DEBUG_CLASS_USER_WINDOWS)
    {
        switch (qualifier)
        {
        case DEBUG_USER_WINDOWS_PROCESS:
            return "user_process";
        case DEBUG_USER_WINDOWS_PROCESS_SERVER:
            return "user_process_server";
        case DEBUG_USER_WINDOWS_IDNA:
            return "user_idna";
        case DEBUG_USER_WINDOWS_SMALL_DUMP:
            return "user_small_dump";
        case DEBUG_USER_WINDOWS_DUMP:
            return "user_dump";
        default:
            return "user_unknown(" + std::to_string(qualifier) + ")";
        }
    }

    if (debugClass == DEBUG_CLASS_KERNEL)
    {
        switch (qualifier)
        {
        case DEBUG_KERNEL_CONNECTION:
            return "kernel_connection";
        case DEBUG_KERNEL_LOCAL:
            return "kernel_local";
        case DEBUG_KERNEL_EXDI_DRIVER:
            return "kernel_exdi_driver";
        case DEBUG_KERNEL_IDNA:
            return "kernel_idna";
        case DEBUG_KERNEL_SMALL_DUMP:
            return "kernel_small_dump";
        case DEBUG_KERNEL_DUMP:
            return "kernel_dump";
        case DEBUG_KERNEL_FULL_DUMP:
            return "kernel_full_dump";
        default:
            return "kernel_unknown(" + std::to_string(qualifier) + ")";
        }
    }

    return "unknown(" + std::to_string(qualifier) + ")";
}

bool IsDumpQualifier(ULONG qualifier)
{
    return qualifier == DEBUG_USER_WINDOWS_SMALL_DUMP
        || qualifier == DEBUG_USER_WINDOWS_DUMP
        || qualifier == DEBUG_KERNEL_SMALL_DUMP
        || qualifier == DEBUG_KERNEL_DUMP
        || qualifier == DEBUG_KERNEL_FULL_DUMP;
}

decomp::SessionPolicyFacts BuildSessionPolicyFacts(IDebugControl* control)
{
    decomp::SessionPolicyFacts policy;
    ULONG debugClass = 0;
    ULONG qualifier = 0;

    if (control != nullptr && SUCCEEDED(control->GetDebuggeeType(&debugClass, &qualifier)))
    {
        policy.DebugClass = DebugClassToString(debugClass);
        policy.Qualifier = DebugQualifierToString(debugClass, qualifier);
        policy.IsKernel = debugClass == DEBUG_CLASS_KERNEL;
        policy.IsDump = IsDumpQualifier(qualifier);
        policy.IsLive = !policy.IsDump
            && (qualifier == DEBUG_USER_WINDOWS_PROCESS
                || qualifier == DEBUG_USER_WINDOWS_PROCESS_SERVER
                || qualifier == DEBUG_KERNEL_CONNECTION
                || qualifier == DEBUG_KERNEL_LOCAL
                || qualifier == DEBUG_KERNEL_EXDI_DRIVER);
    }
    else
    {
        policy.DebugClass = "unknown";
        policy.Qualifier = "unknown";
        policy.Notes.push_back("DbgEng did not report debuggee type");
    }

    policy.TtdAvailable = GetModuleHandleA("ttdext.dll") != nullptr || GetModuleHandleA("TTDReplay.dll") != nullptr;
    policy.IsTraceLike = policy.TtdAvailable;

    if (policy.TtdAvailable)
    {
        policy.ExecutionKind = "ttd_trace";
        policy.AnalysisStrategy = "merge static facts with optional TTD observation queries";
        policy.Notes.push_back("TTD extension/runtime appears loaded; observed_behavior.ttd_queries are safe query suggestions");
    }
    else if (policy.IsDump)
    {
        policy.ExecutionKind = policy.IsKernel ? "kernel_dump" : "user_dump";
        policy.AnalysisStrategy = "prefer static facts and current-frame register samples; avoid assuming live execution";
        policy.Notes.push_back("dump session; dynamic call history is unavailable unless TTD data is loaded");
    }
    else if (policy.IsLive)
    {
        policy.ExecutionKind = policy.IsKernel ? "kernel_live" : "user_live";
        policy.AnalysisStrategy = "prefer fast static analysis plus current-frame observations";
    }
    else
    {
        policy.ExecutionKind = policy.IsKernel ? "kernel_unknown" : "unknown";
        policy.AnalysisStrategy = "use conservative static analysis";
        policy.Notes.push_back("session qualifier is not recognized by the extension");
    }

    if (policy.IsKernel)
    {
        policy.Notes.push_back("kernel session; user-mode pointer interpretation may be unsafe");
    }

    return policy;
}

bool ResolveTargetAddress(IDebugSymbols3* symbols, const std::string& target, uint64_t& address)
{
    if (decomp::TryParseUnsigned(target, address))
    {
        return true;
    }

    return symbols != nullptr && SUCCEEDED(symbols->GetOffsetByName(target.c_str(), &address));
}

std::string ReadModuleNameString(IDebugSymbols3* symbols, ULONG which, ULONG index, uint64_t base)
{
    std::array<char, 1024> buffer = {};
    ULONG nameSize = 0;

    if (symbols != nullptr
        && SUCCEEDED(symbols->GetModuleNameString(which, index, base, buffer.data(), static_cast<ULONG>(buffer.size()), &nameSize)))
    {
        return buffer.data();
    }

    return std::string();
}

bool CollectModuleInfo(IDebugSymbols3* symbols, uint64_t address, decomp::ModuleInfo& moduleInfo)
{
    bool success = false;
    ULONG index = 0;
    ULONG64 base = 0;

    do
    {
        if (symbols == nullptr)
        {
            break;
        }

        if (FAILED(symbols->GetModuleByOffset(address, 0, &index, &base)))
        {
            break;
        }

        DEBUG_MODULE_PARAMETERS parameters = {};
        ULONG64 bases[1] = { base };

        if (FAILED(symbols->GetModuleParameters(1, bases, 0, &parameters)))
        {
            break;
        }

        moduleInfo.Base = base;
        moduleInfo.Size = parameters.Size;
        moduleInfo.SymbolType = parameters.SymbolType;
        moduleInfo.ImageName = ReadModuleNameString(symbols, DEBUG_MODNAME_IMAGE, index, base);
        moduleInfo.ModuleName = ReadModuleNameString(symbols, DEBUG_MODNAME_MODULE, index, base);
        moduleInfo.LoadedImageName = ReadModuleNameString(symbols, DEBUG_MODNAME_LOADED_IMAGE, index, base);
        success = true;
    }
    while (false);

    return success;
}

#if DECOMP_USE_SYMBOL_ENTRY_APIS
std::string ReadSymbolEntryName(IDebugSymbols3* symbols, const DEBUG_MODULE_AND_ID& id)
{
    std::array<char, 1024> buffer = {};
    ULONG nameSize = 0;
    DEBUG_MODULE_AND_ID localId = id;

    if (symbols != nullptr
        && SUCCEEDED(symbols->GetSymbolEntryString(&localId, 0, buffer.data(), static_cast<ULONG>(buffer.size()), &nameSize)))
    {
        return buffer.data();
    }

    return std::string();
}
#endif

void NormalizeRegions(std::vector<decomp::FunctionRegion>& regions)
{
    regions.erase(
        std::remove_if(
            regions.begin(),
            regions.end(),
            [](const decomp::FunctionRegion& region)
            {
                return region.End <= region.Start;
            }),
        regions.end());

    std::sort(
        regions.begin(),
        regions.end(),
        [](const decomp::FunctionRegion& left, const decomp::FunctionRegion& right)
        {
            if (left.Start != right.Start)
            {
                return left.Start < right.Start;
            }

            return left.End < right.End;
        });

    std::vector<decomp::FunctionRegion> merged;

    for (const auto& region : regions)
    {
        if (merged.empty() || region.Start > merged.back().End)
        {
            merged.push_back(region);
            continue;
        }

        merged.back().End = (std::max)(merged.back().End, region.End);
    }

    regions = std::move(merged);
}

#if DECOMP_USE_SYMBOL_ENTRY_APIS
bool TryRecoverSymbolRegions(
    IDebugSymbols3* symbols,
    uint64_t queryAddress,
    uint64_t& entryAddress,
    std::vector<decomp::FunctionRegion>& regions,
    std::string& symbolName)
{
    if (symbols == nullptr)
    {
        return false;
    }

    std::array<DEBUG_MODULE_AND_ID, 8> ids = {};
    std::array<ULONG64, 8> displacements = {};
    ULONG entries = 0;

    if (FAILED(symbols->GetSymbolEntriesByOffset(
            queryAddress,
            0,
            ids.data(),
            displacements.data(),
            static_cast<ULONG>(ids.size()),
            &entries))
        || entries == 0)
    {
        return false;
    }

    size_t bestIndex = 0;
    ULONG64 bestDisplacement = displacements[0];
    const size_t candidates = std::min<size_t>(entries, ids.size());

    for (size_t index = 1; index < candidates; ++index)
    {
        if (displacements[index] < bestDisplacement)
        {
            bestDisplacement = displacements[index];
            bestIndex = index;
        }
    }

    DEBUG_MODULE_AND_ID selectedId = ids[bestIndex];
    DEBUG_SYMBOL_ENTRY symbolInfo = {};

    if (FAILED(symbols->GetSymbolEntryInformation(&selectedId, &symbolInfo)))
    {
        return false;
    }

    entryAddress = (symbolInfo.Offset != 0) ? symbolInfo.Offset : (queryAddress - bestDisplacement);
    symbolName = ReadSymbolEntryName(symbols, selectedId);

    std::array<DEBUG_OFFSET_REGION, 16> scratch = {};
    ULONG regionsAvail = 0;
    HRESULT regionHr = symbols->GetSymbolEntryOffsetRegions(
        &selectedId,
        0,
        scratch.data(),
        static_cast<ULONG>(scratch.size()),
        &regionsAvail);

    if (SUCCEEDED(regionHr) && regionsAvail > 0)
    {
        const ULONG copyCount = (regionsAvail > scratch.size()) ? static_cast<ULONG>(scratch.size()) : regionsAvail;

        for (ULONG index = 0; index < copyCount; ++index)
        {
            regions.push_back({ scratch[index].Base, scratch[index].Base + scratch[index].Size });
        }

        if (regionsAvail > scratch.size())
        {
            std::vector<DEBUG_OFFSET_REGION> expanded(regionsAvail);

            if (SUCCEEDED(symbols->GetSymbolEntryOffsetRegions(
                    &selectedId,
                    0,
                    expanded.data(),
                    static_cast<ULONG>(expanded.size()),
                    &regionsAvail)))
            {
                regions.clear();

                for (ULONG index = 0; index < regionsAvail; ++index)
                {
                    regions.push_back({ expanded[index].Base, expanded[index].Base + expanded[index].Size });
                }
            }
        }
    }

    if (regions.empty() && symbolInfo.Size != 0)
    {
        regions.push_back({ entryAddress, entryAddress + symbolInfo.Size });
    }

    NormalizeRegions(regions);
    return !regions.empty();
}
#else
bool TryRecoverSymbolRegions(
    IDebugSymbols3*,
    uint64_t,
    uint64_t&,
    std::vector<decomp::FunctionRegion>&,
    std::string&)
{
    return false;
}
#endif

bool TryRecoverRuntimeFunction(IDebugSymbols3* symbols, uint64_t queryAddress, uint64_t moduleBase, uint64_t& entryAddress, std::vector<decomp::FunctionRegion>& regions)
{
    if (symbols == nullptr || moduleBase == 0)
    {
        return false;
    }

    RUNTIME_FUNCTION runtimeFunction = {};
    ULONG needed = 0;

    if (FAILED(symbols->GetFunctionEntryByOffset(queryAddress, 0, &runtimeFunction, sizeof(runtimeFunction), &needed)))
    {
        return false;
    }

    if (runtimeFunction.BeginAddress >= runtimeFunction.EndAddress)
    {
        return false;
    }

    entryAddress = moduleBase + runtimeFunction.BeginAddress;
    regions.push_back({ moduleBase + runtimeFunction.BeginAddress, moduleBase + runtimeFunction.EndAddress });
    NormalizeRegions(regions);
    return true;
}

uint64_t DisassembleUntilTerminal(IDebugControl* control, uint64_t entryAddress, uint32_t maxInstructions, std::vector<decomp::DisassembledInstruction>& instructions)
{
    uint64_t current = entryAddress;
    uint64_t lastEnd = entryAddress;

    for (uint32_t index = 0; index < maxInstructions; ++index)
    {
        std::array<char, 1024> buffer = {};
        ULONG disassemblySize = 0;
        ULONG64 nextAddress = 0;

        if (control == nullptr
            || FAILED(control->Disassemble(current, 0, buffer.data(), static_cast<ULONG>(buffer.size()), &disassemblySize, &nextAddress)))
        {
            break;
        }

        if (nextAddress <= current)
        {
            break;
        }

        decomp::DisassembledInstruction instruction;
        instruction.Address = current;
        instruction.EndAddress = nextAddress;
        instruction.Text = buffer.data();
        instructions.push_back(instruction);
        lastEnd = nextAddress;

        if (ShouldStopFallbackDisassembly(instruction.Text))
        {
            break;
        }

        current = nextAddress;
    }

    return lastEnd;
}

bool IsConditionalJumpMnemonic(const std::string& mnemonic)
{
    return mnemonic.size() >= 2 && mnemonic[0] == 'j' && mnemonic != "jmp";
}

bool TryParseFallbackBranchTarget(const std::string& operandText, uint64_t& target)
{
    if (operandText.empty() || operandText.find('[') != std::string::npos)
    {
        return false;
    }

    std::vector<std::string> tokens;
    std::string current;

    auto flush = [&]()
    {
        const std::string token = decomp::TrimCopy(current);
        current.clear();

        if (!token.empty())
        {
            tokens.push_back(token);
        }
    };

    for (char ch : operandText)
    {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0 || ch == ',')
        {
            flush();
            continue;
        }

        current.push_back(ch);
    }

    flush();

    for (auto it = tokens.rbegin(); it != tokens.rend(); ++it)
    {
        std::string token = *it;

        while (!token.empty() && (token.back() == ':' || token.back() == ')' || token.back() == '('))
        {
            token.pop_back();
        }

        if (decomp::StartsWithInsensitive(token, "short")
            || decomp::StartsWithInsensitive(token, "near")
            || decomp::StartsWithInsensitive(token, "far"))
        {
            continue;
        }

        if (decomp::TryParseUnsigned(token, target))
        {
            return true;
        }
    }

    return false;
}

bool IsFallbackTraversalAddressAllowed(
    const decomp::ModuleInfo& moduleInfo,
    uint64_t entryAddress,
    uint64_t address)
{
    if (address == 0)
    {
        return false;
    }

    const uint64_t lowerBound = entryAddress > 0x10000ULL ? entryAddress - 0x10000ULL : 0;
    const uint64_t upperBound = entryAddress > (std::numeric_limits<uint64_t>::max)() - 0x100000ULL
        ? (std::numeric_limits<uint64_t>::max)()
        : entryAddress + 0x100000ULL;

    if (address < lowerBound || address >= upperBound)
    {
        return false;
    }

    if (moduleInfo.Base != 0 && moduleInfo.Size != 0)
    {
        const uint64_t moduleEnd = moduleInfo.Base > (std::numeric_limits<uint64_t>::max)() - moduleInfo.Size
            ? (std::numeric_limits<uint64_t>::max)()
            : moduleInfo.Base + moduleInfo.Size;
        return address >= moduleInfo.Base && address < moduleEnd;
    }

    return true;
}

bool TryDisassembleFallbackInstruction(
    IDebugControl* control,
    uint64_t address,
    decomp::DisassembledInstruction& instruction)
{
    std::array<char, 1024> buffer = {};
    ULONG disassemblySize = 0;
    ULONG64 nextAddress = 0;

    if (control == nullptr
        || FAILED(control->Disassemble(address, 0, buffer.data(), static_cast<ULONG>(buffer.size()), &disassemblySize, &nextAddress))
        || nextAddress <= address)
    {
        return false;
    }

    instruction.Address = address;
    instruction.EndAddress = nextAddress;
    instruction.Text = buffer.data();
    instruction.OperationText = ExtractOperationText(buffer.data());
    instruction.Mnemonic = ExtractMnemonic(instruction.OperationText);
    instruction.OperandText = ExtractOperandText(instruction.OperationText);
    instruction.IsConditionalBranch = IsConditionalJumpMnemonic(instruction.Mnemonic);
    instruction.IsUnconditionalBranch = IsUnconditionalJumpMnemonic(instruction.Mnemonic);
    instruction.IsCall = IsCallMnemonic(instruction.Mnemonic);
    instruction.IsReturn = IsReturnMnemonic(instruction.Mnemonic);
    instruction.IsIndirect = instruction.OperandText.find('[') != std::string::npos
        && (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch);
    instruction.HasBranchTarget = TryParseFallbackBranchTarget(instruction.OperandText, instruction.BranchTarget);
    return true;
}

bool TryRecoverBranchFollowRegions(
    IDebugControl* control,
    uint64_t entryAddress,
    const decomp::ModuleInfo& moduleInfo,
    uint32_t maxInstructions,
    std::vector<decomp::FunctionRegion>& regions)
{
    regions.clear();

    if (control == nullptr || maxInstructions == 0)
    {
        return false;
    }

    std::deque<uint64_t> pending;
    std::set<uint64_t> queued;
    std::set<uint64_t> visited;
    std::vector<decomp::FunctionRegion> ranges;
    pending.push_back(entryAddress);
    queued.insert(entryAddress);

    while (!pending.empty() && visited.size() < maxInstructions)
    {
        const uint64_t address = pending.front();
        pending.pop_front();

        if (visited.find(address) != visited.end()
            || !IsFallbackTraversalAddressAllowed(moduleInfo, entryAddress, address))
        {
            continue;
        }

        decomp::DisassembledInstruction instruction;

        if (!TryDisassembleFallbackInstruction(control, address, instruction))
        {
            continue;
        }

        visited.insert(address);
        ranges.push_back({ instruction.Address, instruction.EndAddress });

        auto enqueue = [&](uint64_t target)
        {
            if (visited.size() + pending.size() >= maxInstructions)
            {
                return;
            }

            if (queued.find(target) == queued.end()
                && visited.find(target) == visited.end()
                && IsFallbackTraversalAddressAllowed(moduleInfo, entryAddress, target))
            {
                queued.insert(target);
                pending.push_back(target);
            }
        };

        if (instruction.IsConditionalBranch)
        {
            if (instruction.HasBranchTarget)
            {
                enqueue(instruction.BranchTarget);
            }

            enqueue(instruction.EndAddress);
            continue;
        }

        if (instruction.IsUnconditionalBranch)
        {
            if (instruction.HasBranchTarget && !instruction.IsIndirect)
            {
                enqueue(instruction.BranchTarget);
            }

            continue;
        }

        if (instruction.IsReturn || IsTrapMnemonic(instruction.Mnemonic))
        {
            continue;
        }

        if (instruction.IsCall && IsNoReturnTarget(instruction.OperandText))
        {
            continue;
        }

        enqueue(instruction.EndAddress);
    }

    if (ranges.empty())
    {
        return false;
    }

    std::sort(
        ranges.begin(),
        ranges.end(),
        [](const decomp::FunctionRegion& left, const decomp::FunctionRegion& right)
        {
            return left.Start < right.Start;
        });

    for (const decomp::FunctionRegion& range : ranges)
    {
        if (!regions.empty() && range.Start <= regions.back().End)
        {
            regions.back().End = (std::max)(regions.back().End, range.End);
        }
        else
        {
            regions.push_back(range);
        }
    }

    NormalizeRegions(regions);
    return !regions.empty();
}

std::vector<decomp::FunctionRegion> RecoverFunctionRegions(
    IDebugSymbols3* symbols,
    IDebugControl* control,
    uint64_t queryAddress,
    const decomp::ModuleInfo& moduleInfo,
    uint64_t& entryAddress,
    uint32_t maxInstructions,
    std::string* resolvedSymbolName)
{
    std::vector<decomp::FunctionRegion> regions;
    std::string symbolName;
    entryAddress = queryAddress;

    if (resolvedSymbolName != nullptr)
    {
        resolvedSymbolName->clear();
    }

    if (TryRecoverSymbolRegions(symbols, queryAddress, entryAddress, regions, symbolName))
    {
        if (resolvedSymbolName != nullptr && !symbolName.empty())
        {
            *resolvedSymbolName = symbolName;
        }

        return regions;
    }

    if (TryRecoverRuntimeFunction(symbols, queryAddress, moduleInfo.Base, entryAddress, regions))
    {
        return regions;
    }

    std::array<char, 1024> nameBuffer = {};
    ULONG nameSize = 0;
    ULONG64 displacement = 0;

    if (symbols != nullptr
        && SUCCEEDED(symbols->GetNameByOffset(queryAddress, nameBuffer.data(), static_cast<ULONG>(nameBuffer.size()), &nameSize, &displacement)))
    {
        entryAddress = queryAddress - displacement;
    }

    if (!TryRecoverBranchFollowRegions(control, entryAddress, moduleInfo, maxInstructions, regions))
    {
        std::vector<decomp::DisassembledInstruction> probe;
        const uint64_t endAddress = DisassembleUntilTerminal(control, entryAddress, maxInstructions, probe);

        if (endAddress > entryAddress)
        {
            regions.push_back({ entryAddress, endAddress });
        }
    }

    NormalizeRegions(regions);
    return regions;
}

bool ReadVirtualRange(IDebugDataSpaces4* dataSpaces, uint64_t start, uint64_t end, std::vector<uint8_t>& bytes)
{
    bool success = false;

    do
    {
        if (dataSpaces == nullptr || end <= start)
        {
            break;
        }

        const uint64_t size = end - start;
        bytes.resize(static_cast<size_t>(size));
        uint64_t offset = 0;

        while (offset < size)
        {
            const ULONG chunk = static_cast<ULONG>(std::min<uint64_t>(0x1000, size - offset));
            ULONG read = 0;

            if (FAILED(dataSpaces->ReadVirtual(start + offset, bytes.data() + offset, chunk, &read)) || read == 0)
            {
                bytes.clear();
                break;
            }

            offset += read;
        }

        success = !bytes.empty();
    }
    while (false);

    return success;
}

std::vector<FunctionRegionBytes> ReadFunctionRegionBytes(IDebugDataSpaces4* dataSpaces, const std::vector<decomp::FunctionRegion>& regions)
{
    std::vector<FunctionRegionBytes> regionBytes;

    for (const auto& region : regions)
    {
        std::vector<uint8_t> part;

        if (!ReadVirtualRange(dataSpaces, region.Start, region.End, part))
        {
            continue;
        }

        FunctionRegionBytes item;
        item.Region = region;
        item.Bytes = std::move(part);
        regionBytes.push_back(std::move(item));
    }

    return regionBytes;
}

std::vector<uint8_t> FlattenFunctionRegionBytes(const std::vector<FunctionRegionBytes>& regionBytes)
{
    std::vector<uint8_t> combined;

    for (const FunctionRegionBytes& item : regionBytes)
    {
        combined.insert(combined.end(), item.Bytes.begin(), item.Bytes.end());
    }

    return combined;
}

bool TryDecodeInstructionWithZydis(
    uint64_t address,
    const uint8_t* buffer,
    size_t length,
    decomp::DisassembledInstruction& instruction,
    DecodedInstructionContext& context)
{
    ZydisDisassembledInstruction decoded = {};

    if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, buffer, length, &decoded)))
    {
        return false;
    }

    instruction.Address = address;
    instruction.EndAddress = address + decoded.info.length;
    instruction.Text = decoded.text;
    instruction.OperationText = decoded.text;
    instruction.Mnemonic = decomp::ToLowerAscii(ZydisMnemonicGetString(decoded.info.mnemonic));
    instruction.OperandText = ExtractOperandTextFromFormattedInstruction(decoded.text);
    instruction.IsConditionalBranch = instruction.Mnemonic.size() >= 2 && instruction.Mnemonic[0] == 'j' && instruction.Mnemonic != "jmp";
    instruction.IsUnconditionalBranch = instruction.Mnemonic == "jmp";
    instruction.IsCall = instruction.Mnemonic == "call";
    instruction.IsReturn = instruction.Mnemonic == "ret" || instruction.Mnemonic == "retn" || instruction.Mnemonic == "retf";
    instruction.IsIndirect = false;
    instruction.HasBranchTarget = false;
    instruction.BranchTarget = 0;

    context.Address = instruction.Address;
    context.EndAddress = instruction.EndAddress;
    context.Mnemonic = instruction.Mnemonic;
    context.Operands = SplitOperands(instruction.OperandText);
    context.IsCall = instruction.IsCall;
    context.IsUnconditionalBranch = instruction.IsUnconditionalBranch;
    context.IsIndirect = false;
    context.HasBranchTarget = false;
    context.BranchTarget = 0;
    context.HasRipRelativeMemory = false;
    context.RipRelativeTarget = 0;

    for (uint8_t operandIndex = 0; operandIndex < decoded.info.operand_count_visible; ++operandIndex)
    {
        const ZydisDecodedOperand& operand = decoded.operands[operandIndex];

        if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            instruction.IsIndirect = instruction.IsIndirect || instruction.IsCall || instruction.IsUnconditionalBranch || instruction.IsConditionalBranch;
            context.IsIndirect = instruction.IsIndirect;

            if (operand.mem.base == ZYDIS_REGISTER_RIP)
            {
                ZyanU64 absoluteAddress = 0;

                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&decoded.info, &operand, address, &absoluteAddress)))
                {
                    context.HasRipRelativeMemory = true;
                    context.RipRelativeTarget = absoluteAddress;
                }
            }
        }
        else if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            instruction.IsIndirect = instruction.IsIndirect || instruction.IsCall || instruction.IsUnconditionalBranch || instruction.IsConditionalBranch;
            context.IsIndirect = instruction.IsIndirect;
        }
        else if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE
            && (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch))
        {
            ZyanU64 absoluteAddress = 0;

            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&decoded.info, &operand, address, &absoluteAddress)))
            {
                instruction.HasBranchTarget = true;
                instruction.BranchTarget = absoluteAddress;
                context.HasBranchTarget = true;
                context.BranchTarget = absoluteAddress;
            }
        }
    }

    return true;
}

std::vector<decomp::DisassembledInstruction> DisassembleRegions(
    IDebugControl* control,
    const std::vector<FunctionRegionBytes>& regionBytes,
    uint32_t maxInstructions,
    std::vector<DecodedInstructionContext>& decodedContexts)
{
    std::vector<decomp::DisassembledInstruction> instructions;
    uint32_t remaining = maxInstructions;

    for (const FunctionRegionBytes& regionData : regionBytes)
    {
        if (regionData.Bytes.empty())
        {
            continue;
        }

        uint64_t current = regionData.Region.Start;
        size_t offset = 0;

        while (current < regionData.Region.End && remaining > 0 && offset < regionData.Bytes.size())
        {
            decomp::DisassembledInstruction instruction;
            DecodedInstructionContext context;

            if (TryDecodeInstructionWithZydis(current, regionData.Bytes.data() + offset, regionData.Bytes.size() - offset, instruction, context))
            {
                instructions.push_back(instruction);
                decodedContexts.push_back(context);
                --remaining;
                current = instruction.EndAddress;
                offset += instruction.EndAddress - instruction.Address;
                continue;
            }

            std::array<char, 1024> buffer = {};
            ULONG disassemblySize = 0;
            ULONG64 nextAddress = 0;

            if (control == nullptr
                || FAILED(control->Disassemble(current, 0, buffer.data(), static_cast<ULONG>(buffer.size()), &disassemblySize, &nextAddress))
                || nextAddress <= current)
            {
                break;
            }

            instruction.Address = current;
            instruction.EndAddress = nextAddress;
            instruction.Text = buffer.data();
            instruction.OperationText = ExtractOperationText(buffer.data());
            instruction.Mnemonic = ExtractMnemonic(instruction.OperationText);
            instruction.OperandText = ExtractOperandText(instruction.OperationText);
            instruction.IsConditionalBranch = IsConditionalJumpMnemonic(instruction.Mnemonic);
            instruction.IsUnconditionalBranch = IsUnconditionalJumpMnemonic(instruction.Mnemonic);
            instruction.IsCall = IsCallMnemonic(instruction.Mnemonic);
            instruction.IsReturn = IsReturnMnemonic(instruction.Mnemonic);
            instruction.IsIndirect = instruction.OperandText.find('[') != std::string::npos
                && (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch);
            instruction.HasBranchTarget = TryParseFallbackBranchTarget(instruction.OperandText, instruction.BranchTarget);
            context.Address = current;
            context.EndAddress = nextAddress;
            context.Mnemonic = instruction.Mnemonic;
            context.Operands = SplitOperands(instruction.OperandText);
            context.IsCall = instruction.IsCall;
            context.IsUnconditionalBranch = instruction.IsUnconditionalBranch;
            context.IsIndirect = instruction.IsIndirect;
            context.HasBranchTarget = instruction.HasBranchTarget;
            context.BranchTarget = instruction.BranchTarget;
            instructions.push_back(instruction);
            decodedContexts.push_back(context);
            --remaining;
            const uint64_t advance = nextAddress - current;
            current = nextAddress;
            offset += static_cast<size_t>(advance);
        }
    }

    return instructions;
}

bool ReadVirtualPrefix(IDebugDataSpaces4* dataSpaces, uint64_t address, ULONG size, std::vector<uint8_t>& bytes)
{
    bytes.clear();

    if (dataSpaces == nullptr || size == 0)
    {
        return false;
    }

    bytes.resize(size);
    ULONG read = 0;

    if (FAILED(dataSpaces->ReadVirtual(address, bytes.data(), size, &read)) || read == 0)
    {
        bytes.clear();
        return false;
    }

    bytes.resize(read);
    return true;
}

bool TryLookupSymbolByOffset(IDebugSymbols3* symbols, uint64_t address, SymbolLookupResult& result)
{
    std::array<char, 1024> buffer = {};
    ULONG nameSize = 0;
    ULONG64 displacement = 0;

    if (symbols == nullptr
        || FAILED(symbols->GetNameByOffset(address, buffer.data(), static_cast<ULONG>(buffer.size()), &nameSize, &displacement)))
    {
        return false;
    }

    result.Name = buffer.data();
    result.Displacement = displacement;
    result.Exact = displacement == 0;
    return !result.Name.empty();
}

bool TryGetTypeNameFromIds(IDebugSymbols3* symbols, ULONG64 moduleBase, ULONG typeId, std::string& typeName)
{
    std::array<char, 1024> buffer = {};
    ULONG nameSize = 0;

    if (symbols == nullptr
        || FAILED(symbols->GetTypeName(moduleBase, typeId, buffer.data(), static_cast<ULONG>(buffer.size()), &nameSize)))
    {
        return false;
    }

    typeName = buffer.data();
    return !typeName.empty();
}

bool TryGetTypeNameForOffset(IDebugSymbols3* symbols, uint64_t address, std::string& typeName)
{
    ULONG typeId = 0;
    ULONG64 moduleBase = 0;

    if (symbols == nullptr || FAILED(symbols->GetOffsetTypeId(address, &typeId, &moduleBase)))
    {
        return false;
    }

    return TryGetTypeNameFromIds(symbols, moduleBase, typeId, typeName);
}

bool TryGetTypeNameForSymbol(IDebugSymbols3* symbols, const std::string& symbolName, std::string& typeName)
{
    ULONG typeId = 0;
    ULONG64 moduleBase = 0;

    if (symbols == nullptr
        || symbolName.empty()
        || FAILED(symbols->GetSymbolTypeId(symbolName.c_str(), &typeId, &moduleBase)))
    {
        return false;
    }

    return TryGetTypeNameFromIds(symbols, moduleBase, typeId, typeName);
}

bool TryReadPointerValue(IDebugDataSpaces4* dataSpaces, uint64_t address, uint64_t& value)
{
    std::vector<uint8_t> bytes;

    if (!ReadVirtualPrefix(dataSpaces, address, sizeof(uint64_t), bytes) || bytes.size() < sizeof(uint64_t))
    {
        return false;
    }

    value = 0;

    for (size_t index = 0; index < sizeof(uint64_t); ++index)
    {
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8U);
    }

    return true;
}

bool TryReadAsciiString(IDebugDataSpaces4* dataSpaces, uint64_t address, std::string& text)
{
    std::vector<uint8_t> bytes;

    if (!ReadVirtualPrefix(dataSpaces, address, 96, bytes))
    {
        return false;
    }

    std::string candidate;

    for (const uint8_t byte : bytes)
    {
        if (byte == 0)
        {
            break;
        }

        if (byte < 0x20 || byte > 0x7E)
        {
            return false;
        }

        candidate.push_back(static_cast<char>(byte));
    }

    if (candidate.size() < 4)
    {
        return false;
    }

    text = candidate;
    return true;
}

bool TryReadUtf16String(IDebugDataSpaces4* dataSpaces, uint64_t address, std::string& text)
{
    std::vector<uint8_t> bytes;

    if (!ReadVirtualPrefix(dataSpaces, address, 96, bytes) || bytes.size() < 4)
    {
        return false;
    }

    std::wstring wide;

    for (size_t index = 0; index + 1 < bytes.size(); index += 2)
    {
        const uint16_t codeUnit = static_cast<uint16_t>(bytes[index]) | (static_cast<uint16_t>(bytes[index + 1]) << 8U);

        if (codeUnit == 0)
        {
            break;
        }

        if (codeUnit < 0x20 || codeUnit > 0x7E)
        {
            return false;
        }

        wide.push_back(static_cast<wchar_t>(codeUnit));
    }

    if (wide.size() < 4)
    {
        return false;
    }

    text = WideToUtf8(wide);
    return true;
}

std::string SimplifySymbolDisplay(std::string name)
{
    name = decomp::TrimCopy(name);
    const size_t bang = name.rfind('!');
    std::string prefix;
    std::string symbol = name;

    if (bang != std::string::npos)
    {
        prefix = name.substr(0, bang + 1);
        symbol = name.substr(bang + 1);
    }

    if (decomp::StartsWithInsensitive(symbol, "__imp_"))
    {
        symbol = symbol.substr(6);
    }
    else if (decomp::StartsWithInsensitive(symbol, "_imp_"))
    {
        symbol = symbol.substr(5);
    }

    return prefix + symbol;
}

bool IsAddressInRegions(uint64_t address, const std::vector<decomp::FunctionRegion>& regions)
{
    for (const auto& region : regions)
    {
        if (address >= region.Start && address < region.End)
        {
            return true;
        }
    }

    return false;
}

bool TryAddSwitchTargetRegions(
    IDebugControl* control,
    const decomp::ModuleInfo& moduleInfo,
    const decomp::AnalysisFacts& facts,
    uint32_t maxInstructions,
    std::vector<decomp::FunctionRegion>& regions,
    size_t& addedRegions)
{
    addedRegions = 0;

    if (control == nullptr || maxInstructions == 0)
    {
        return false;
    }

    std::vector<uint64_t> targets;

    for (const decomp::SwitchInfo& switchInfo : facts.Switches)
    {
        for (const uint64_t target : switchInfo.CaseTargets)
        {
            if (target == 0
                || IsAddressInRegions(target, regions)
                || !IsFallbackTraversalAddressAllowed(moduleInfo, facts.EntryAddress, target)
                || std::find(targets.begin(), targets.end(), target) != targets.end())
            {
                continue;
            }

            targets.push_back(target);
        }
    }

    if (targets.empty())
    {
        return false;
    }

    std::vector<decomp::FunctionRegion> expanded = regions;
    const uint32_t perTargetInstructionLimit = (std::max<uint32_t>)(16, (std::min<uint32_t>)(96, maxInstructions / 8U));

    for (const uint64_t target : targets)
    {
        std::vector<decomp::FunctionRegion> recovered;

        if (!TryRecoverBranchFollowRegions(control, target, moduleInfo, perTargetInstructionLimit, recovered))
        {
            continue;
        }

        for (const decomp::FunctionRegion& region : recovered)
        {
            if (region.Start >= region.End
                || IsAddressInRegions(region.Start, expanded)
                || !IsFallbackTraversalAddressAllowed(moduleInfo, facts.EntryAddress, region.Start))
            {
                continue;
            }

            expanded.push_back(region);
            ++addedRegions;
        }
    }

    if (addedRegions == 0)
    {
        return false;
    }

    NormalizeRegions(expanded);
    regions = std::move(expanded);
    return true;
}

const decomp::MemoryAccess* FindMemoryAccessAtSite(const decomp::AnalysisFacts& facts, uint64_t site)
{
    for (const decomp::MemoryAccess& access : facts.MemoryAccesses)
    {
        if (access.Site == site)
        {
            return &access;
        }
    }

    return nullptr;
}

const DecodedInstructionContext* FindDecodedContextAtSite(const std::vector<DecodedInstructionContext>& contexts, uint64_t site)
{
    for (const DecodedInstructionContext& context : contexts)
    {
        if (context.Address == site)
        {
            return &context;
        }
    }

    return nullptr;
}

bool TryReadU32Value(IDebugDataSpaces4* dataSpaces, uint64_t address, uint32_t& value)
{
    std::vector<uint8_t> bytes;

    if (!ReadVirtualPrefix(dataSpaces, address, sizeof(uint32_t), bytes) || bytes.size() < sizeof(uint32_t))
    {
        return false;
    }

    value = static_cast<uint32_t>(bytes[0])
        | (static_cast<uint32_t>(bytes[1]) << 8)
        | (static_cast<uint32_t>(bytes[2]) << 16)
        | (static_cast<uint32_t>(bytes[3]) << 24);
    return true;
}

bool IsLikelyCodeAddress(
    const decomp::ModuleInfo& moduleInfo,
    const std::vector<decomp::FunctionRegion>& regions,
    uint64_t address)
{
    if (IsAddressInRegions(address, regions))
    {
        return true;
    }

    return moduleInfo.Base != 0
        && moduleInfo.Size != 0
        && address >= moduleInfo.Base
        && address < moduleInfo.Base + moduleInfo.Size;
}

void AppendUniqueAddress(std::vector<uint64_t>& values, uint64_t value)
{
    if (value == 0)
    {
        return;
    }

    if (std::find(values.begin(), values.end(), value) == values.end())
    {
        values.push_back(value);
    }
}

std::string BuildSwitchIndexExpression(const decomp::MemoryAccess& access)
{
    std::string expression;

    if (!access.BaseRegister.empty() && access.BaseRegister != "rip")
    {
        expression = access.BaseRegister;
    }

    if (!access.IndexRegister.empty())
    {
        if (!expression.empty())
        {
            expression += "+";
        }

        expression += access.IndexRegister;

        if (access.Scale > 1)
        {
            expression += "*" + std::to_string(access.Scale);
        }
    }

    return expression;
}

std::string BuildMemoryExpression(const decomp::MemoryAccess& access)
{
    if (access.StackFrameRelative)
    {
        return "[frame" + decomp::HexS64(access.FrameOffset) + "]";
    }

    std::string expression = access.BaseRegister.empty() ? "mem" : access.BaseRegister;

    if (!access.Displacement.empty() && access.Displacement != "0")
    {
        expression += access.Displacement.front() == '-' ? access.Displacement : ("+" + access.Displacement);
    }

    if (!access.IndexRegister.empty())
    {
        expression += "+" + access.IndexRegister;

        if (access.Scale > 1U)
        {
            expression += "*" + std::to_string(access.Scale);
        }
    }

    return "[" + expression + "]";
}

uint64_t AddSignedOffset(uint64_t base, int32_t offset)
{
    if (offset < 0)
    {
        const uint32_t magnitude = offset == INT32_MIN ? 0x80000000U : static_cast<uint32_t>(-offset);
        return base - magnitude;
    }

    return base + static_cast<uint32_t>(offset);
}

bool TryResolveSwitchEntryTarget(
    IDebugDataSpaces4* dataSpaces,
    const decomp::ModuleInfo& moduleInfo,
    const std::vector<decomp::FunctionRegion>& regions,
    uint64_t tableAddress,
    uint64_t contextEndAddress,
    size_t entryIndex,
    size_t entrySize,
    uint64_t& target)
{
    const uint64_t entryAddress = tableAddress + static_cast<uint64_t>(entryIndex * entrySize);

    if (entrySize == sizeof(uint64_t))
    {
        uint64_t value = 0;

        if (!TryReadPointerValue(dataSpaces, entryAddress, value))
        {
            return false;
        }

        if (IsLikelyCodeAddress(moduleInfo, regions, value))
        {
            target = value;
            return true;
        }

        if (moduleInfo.Base != 0 && moduleInfo.Size != 0 && value < moduleInfo.Size)
        {
            const uint64_t rvaTarget = moduleInfo.Base + value;

            if (IsLikelyCodeAddress(moduleInfo, regions, rvaTarget))
            {
                target = rvaTarget;
                return true;
            }
        }

        return false;
    }

    uint32_t raw = 0;

    if (!TryReadU32Value(dataSpaces, entryAddress, raw))
    {
        return false;
    }

    const int32_t relative = static_cast<int32_t>(raw);
    const std::array<uint64_t, 3> candidates = {
        AddSignedOffset(tableAddress, relative),
        AddSignedOffset(contextEndAddress, relative),
        static_cast<uint64_t>(raw)
    };

    for (const uint64_t candidate : candidates)
    {
        if (IsLikelyCodeAddress(moduleInfo, regions, candidate))
        {
            target = candidate;
            return true;
        }
    }

    if (moduleInfo.Base != 0 && moduleInfo.Size != 0 && raw < moduleInfo.Size)
    {
        const uint64_t rvaTarget = moduleInfo.Base + raw;

        if (IsLikelyCodeAddress(moduleInfo, regions, rvaTarget))
        {
            target = rvaTarget;
            return true;
        }
    }

    return false;
}

std::string FindBlockContainingAddress(const decomp::AnalysisFacts& facts, uint64_t address)
{
    for (const decomp::BasicBlock& block : facts.Blocks)
    {
        if (address >= block.StartAddress && address < block.EndAddress)
        {
            return block.Id;
        }
    }

    return std::string();
}

void RefreshSwitchControlFlowTargets(decomp::AnalysisFacts& facts)
{
    for (const decomp::SwitchInfo& switchInfo : facts.Switches)
    {
        const std::string headerBlock = FindBlockContainingAddress(facts, switchInfo.Site);

        if (headerBlock.empty())
        {
            continue;
        }

        for (decomp::BasicBlock& block : facts.Blocks)
        {
            if (block.Id != headerBlock)
            {
                continue;
            }

            if (switchInfo.DefaultTarget != 0)
            {
                const std::string defaultBlock = FindBlockContainingAddress(facts, switchInfo.DefaultTarget);

                if (!defaultBlock.empty())
                {
                    AppendUniqueString(block.Successors, defaultBlock);
                }
            }

            for (const uint64_t target : switchInfo.CaseTargets)
            {
                const std::string targetBlock = FindBlockContainingAddress(facts, target);

                if (!targetBlock.empty())
                {
                    AppendUniqueString(block.Successors, targetBlock);
                }
            }

            break;
        }

        for (decomp::ControlFlowRegion& region : facts.ControlFlow)
        {
            if (region.Kind != "switch_candidate" || region.HeaderBlock != headerBlock)
            {
                continue;
            }

            for (const uint64_t target : switchInfo.CaseTargets)
            {
                const std::string targetBlock = FindBlockContainingAddress(facts, target);

                if (!targetBlock.empty())
                {
                    AppendUniqueString(region.BodyBlocks, targetBlock);
                }
            }

            if (switchInfo.DefaultTarget != 0)
            {
                const std::string defaultBlock = FindBlockContainingAddress(facts, switchInfo.DefaultTarget);

                if (!defaultBlock.empty())
                {
                    AppendUniqueString(region.BodyBlocks, defaultBlock);
                }

                region.Evidence += "; default=" + decomp::HexU64(switchInfo.DefaultTarget);
                region.Confidence = decomp::Clamp01(region.Confidence + 0.04);
            }

            if (!switchInfo.CaseTargets.empty())
            {
                region.Evidence += "; recovered_targets=" + std::to_string(switchInfo.CaseTargets.size());
                region.Confidence = decomp::Clamp01(region.Confidence + 0.12);
            }
        }
    }
}

void RecoverSwitchTargetsFromDebugData(
    IDebugDataSpaces4* dataSpaces,
    const decomp::ModuleInfo& moduleInfo,
    const std::vector<decomp::FunctionRegion>& regions,
    const std::vector<DecodedInstructionContext>& decodedContexts,
    decomp::AnalysisFacts& facts)
{
    for (decomp::SwitchInfo& switchInfo : facts.Switches)
    {
        const DecodedInstructionContext* context = FindDecodedContextAtSite(decodedContexts, switchInfo.Site);
        const decomp::MemoryAccess* access = FindMemoryAccessAtSite(facts, switchInfo.Site);

        if (context == nullptr || access == nullptr || !context->HasRipRelativeMemory)
        {
            continue;
        }

        switchInfo.TableAddress = context->RipRelativeTarget;
        const std::string indexExpression = BuildSwitchIndexExpression(*access);

        if (!indexExpression.empty())
        {
            switchInfo.IndexExpression = indexExpression;
        }

        const size_t entrySize = (access->Scale == sizeof(uint32_t) || access->WidthBits == 32)
            ? sizeof(uint32_t)
            : sizeof(uint64_t);
        const size_t wantedEntries = switchInfo.CaseCount != 0
            ? (std::min<size_t>)(switchInfo.CaseCount, 64)
            : 16;
        size_t invalidRun = 0;

        for (size_t index = 0; index < wantedEntries && invalidRun < 3; ++index)
        {
            uint64_t target = 0;

            if (TryResolveSwitchEntryTarget(
                    dataSpaces,
                    moduleInfo,
                    regions,
                    switchInfo.TableAddress,
                    context->EndAddress,
                    index,
                    entrySize,
                    target))
            {
                AppendUniqueAddress(switchInfo.CaseTargets, target);
                invalidRun = 0;
            }
            else if (!switchInfo.CaseTargets.empty())
            {
                ++invalidRun;
            }
        }

        if (!switchInfo.CaseTargets.empty())
        {
            switchInfo.CaseCount = (std::max<uint32_t>)(switchInfo.CaseCount, static_cast<uint32_t>(switchInfo.CaseTargets.size()));
            switchInfo.Detail += " ; table=" + decomp::HexU64(switchInfo.TableAddress)
                + " recovered_targets=" + std::to_string(switchInfo.CaseTargets.size());
        }
    }

    decomp::ApplyRecoveredSwitchTargets(facts);
}

bool TryReadRegisterU64(IDebugRegisters2* registers, const char* name, uint64_t& value)
{
    if (registers == nullptr || name == nullptr)
    {
        return false;
    }

    ULONG index = 0;

    if (FAILED(registers->GetIndexByName(name, &index)))
    {
        return false;
    }

    DEBUG_VALUE debugValue = {};

    if (FAILED(registers->GetValue(index, &debugValue)))
    {
        return false;
    }

    switch (debugValue.Type)
    {
    case DEBUG_VALUE_INT8:
        value = debugValue.I8;
        return true;
    case DEBUG_VALUE_INT16:
        value = debugValue.I16;
        return true;
    case DEBUG_VALUE_INT32:
        value = debugValue.I32;
        return true;
    case DEBUG_VALUE_INT64:
        value = debugValue.I64;
        return true;
    default:
        return false;
    }
}

std::string FormatSymbolWithDisplacement(const SymbolLookupResult& symbol)
{
    if (symbol.Name.empty())
    {
        return std::string();
    }

    std::string text = SimplifySymbolDisplay(symbol.Name);

    if (symbol.Displacement != 0)
    {
        text += "+";
        text += decomp::HexU64(symbol.Displacement);
    }

    return text;
}

void AddObservedMemoryHotspots(const decomp::AnalysisFacts& facts, decomp::ObservedBehaviorFacts& observed)
{
    struct HotspotAccumulator
    {
        uint32_t Reads = 0;
        uint32_t Writes = 0;
        std::vector<uint64_t> Sites;
    };

    std::unordered_map<std::string, HotspotAccumulator> byExpression;

    for (const auto& access : facts.MemoryAccesses)
    {
        if (access.Implicit || access.Access.empty())
        {
            continue;
        }

        HotspotAccumulator& accumulator = byExpression[access.Access];

        if (access.Kind == "write")
        {
            ++accumulator.Writes;
        }
        else
        {
            ++accumulator.Reads;
        }

        if (accumulator.Sites.size() < 8)
        {
            accumulator.Sites.push_back(access.Site);
        }
    }

    for (const auto& item : byExpression)
    {
        if (item.second.Reads + item.second.Writes < 2)
        {
            continue;
        }

        decomp::ObservedMemoryHotspot hotspot;
        hotspot.Expression = item.first;
        hotspot.Kind =
            item.second.Reads != 0 && item.second.Writes != 0 ? "read_write"
            : item.second.Writes != 0 ? "write"
            : "read";
        hotspot.ReadCount = item.second.Reads;
        hotspot.WriteCount = item.second.Writes;
        hotspot.Sites = item.second.Sites;
        hotspot.Confidence = 0.58;
        observed.MemoryHotspots.push_back(std::move(hotspot));
    }
}

void AddTtdQuerySuggestions(const std::string& target, uint64_t entryAddress, decomp::ObservedBehaviorFacts& observed)
{
    auto escapeDebuggerString = [](const std::string& value)
    {
        std::string escaped;
        escaped.reserve(value.size() + 8);

        for (const char ch : value)
        {
            if (ch == '\\' || ch == '"')
            {
                escaped.push_back('\\');
            }

            escaped.push_back(ch);
        }

        return escaped;
    };

    const std::string escapedTarget = escapeDebuggerString(target.empty() ? decomp::HexU64(entryAddress) : target);
    observed.TtdQueries.push_back("dx @$cursession.TTD.Calls(\"" + escapedTarget + "\")");
    observed.TtdQueries.push_back("dx @$cursession.TTD.Calls(\"" + escapedTarget + "\").Take(20)");
    observed.TtdQueries.push_back("dx @$cursession.TTD.Calls(\"" + escapedTarget + "\").Select(c => new { c.TimeStart, c.TimeEnd, c.ReturnValue })");

    if (entryAddress != 0)
    {
        observed.TtdQueries.push_back("bp " + decomp::HexU64(entryAddress));
    }
}

void CollectObservedBehaviorFacts(
    IDebugRegisters2* registers,
    IDebugDataSpaces4* dataSpaces,
    IDebugSymbols3* symbols,
    const std::vector<decomp::FunctionRegion>& regions,
    decomp::AnalysisFacts& facts)
{
    decomp::ObservedBehaviorFacts observed;
    uint64_t rip = 0;
    uint64_t rsp = 0;

    if (TryReadRegisterU64(registers, "rip", rip))
    {
        observed.InstructionPointer = rip;
        observed.CurrentInstructionInFunction = IsAddressInRegions(rip, regions);
    }
    else
    {
        observed.Notes.push_back("current instruction pointer is unavailable");
    }

    if (TryReadRegisterU64(registers, "rsp", rsp))
    {
        observed.StackPointer = rsp;

        uint64_t returnAddress = 0;

        if (TryReadPointerValue(dataSpaces, rsp, returnAddress))
        {
            observed.ReturnAddress = returnAddress;
        }
    }

    const std::array<const char*, 4> argumentRegisters = { "rcx", "rdx", "r8", "r9" };

    for (size_t index = 0; index < argumentRegisters.size(); ++index)
    {
        uint64_t value = 0;

        if (!TryReadRegisterU64(registers, argumentRegisters[index], value))
        {
            continue;
        }

        decomp::ObservedArgumentValue argument;
        argument.Name = index < facts.RecoveredArguments.size() ? facts.RecoveredArguments[index].Name : ("arg" + std::to_string(index + 1));
        argument.Register = argumentRegisters[index];
        argument.Value = value;
        argument.Source = observed.CurrentInstructionInFunction ? "current_frame" : "current_context";
        argument.Confidence = observed.CurrentInstructionInFunction ? 0.74 : 0.48;

        SymbolLookupResult symbol;

        if (value != 0 && TryLookupSymbolByOffset(symbols, value, symbol) && symbol.Displacement <= 0x1000)
        {
            argument.Symbol = FormatSymbolWithDisplacement(symbol);
            argument.Confidence = std::min(0.92, argument.Confidence + 0.10);
        }

        observed.ArgumentSamples.push_back(std::move(argument));
    }

    AddObservedMemoryHotspots(facts, observed);

    if (facts.SessionPolicy.TtdAvailable)
    {
        AddTtdQuerySuggestions(facts.QueryText, facts.EntryAddress, observed);
    }

    if (observed.CurrentInstructionInFunction)
    {
        observed.Notes.push_back("current frame instruction pointer is inside the analyzed function");
    }
    else if (observed.InstructionPointer != 0)
    {
        observed.Notes.push_back("current frame is outside the analyzed function; argument samples are contextual hints only");
    }

    observed.Confidence =
        (observed.CurrentInstructionInFunction ? 0.35 : 0.15)
        + (!observed.ArgumentSamples.empty() ? 0.25 : 0.0)
        + (!observed.MemoryHotspots.empty() ? 0.15 : 0.0)
        + (facts.SessionPolicy.TtdAvailable ? 0.10 : 0.0);
    observed.Confidence = decomp::Clamp01(observed.Confidence);

    facts.ObservedBehavior = std::move(observed);

    if (!facts.ObservedBehavior.ArgumentSamples.empty())
    {
        facts.Facts.push_back("observed argument samples: " + std::to_string(facts.ObservedBehavior.ArgumentSamples.size()));
    }

    if (!facts.ObservedBehavior.MemoryHotspots.empty())
    {
        facts.Facts.push_back("observed/static memory hotspots: " + std::to_string(facts.ObservedBehavior.MemoryHotspots.size()));
    }

    if (facts.SessionPolicy.TtdAvailable)
    {
        facts.Facts.push_back("TTD query suggestions available: " + std::to_string(facts.ObservedBehavior.TtdQueries.size()));
    }
}

std::string ExtractReturnTypeFromPrototype(const std::string& prototype, const std::string& displayName)
{
    const std::string trimmed = decomp::TrimCopy(prototype);

    if (!trimmed.empty())
    {
        const size_t firstParen = trimmed.find('(');

        if (firstParen != std::string::npos)
        {
            std::string prefix = decomp::TrimCopy(trimmed.substr(0, firstParen));
            std::vector<std::string> nameCandidates;
            nameCandidates.push_back(displayName);

            const size_t bang = displayName.rfind('!');
            if (bang != std::string::npos && bang + 1 < displayName.size())
            {
                nameCandidates.push_back(displayName.substr(bang + 1));
            }

            const size_t scope = displayName.rfind("::");
            if (scope != std::string::npos && scope + 2 < displayName.size())
            {
                nameCandidates.push_back(displayName.substr(scope + 2));
            }

            for (const std::string& candidate : nameCandidates)
            {
                if (candidate.empty() || prefix.size() < candidate.size())
                {
                    continue;
                }

                const std::string suffix = prefix.substr(prefix.size() - candidate.size());

                if (decomp::ToLowerAscii(suffix) == decomp::ToLowerAscii(candidate))
                {
                    prefix = decomp::TrimCopy(prefix.substr(0, prefix.size() - candidate.size()));
                    break;
                }
            }

            while (!prefix.empty() && (prefix.back() == '!' || prefix.back() == ':'))
            {
                const size_t lastSpace = prefix.find_last_of(" \t");

                if (lastSpace == std::string::npos)
                {
                    prefix.clear();
                    break;
                }

                prefix = decomp::TrimCopy(prefix.substr(0, lastSpace));
            }

            if (!prefix.empty())
            {
                return prefix;
            }
        }

        return trimmed;
    }

    const std::string lowerName = decomp::ToLowerAscii(displayName);

    if (lowerName.find("hresult") != std::string::npos)
    {
        return "HRESULT";
    }

    if (lowerName.find("ntstatus") != std::string::npos || decomp::StartsWithInsensitive(lowerName, "nt"))
    {
        return "NTSTATUS";
    }

    if (decomp::StartsWithInsensitive(lowerName, "is")
        || decomp::StartsWithInsensitive(lowerName, "has")
        || lowerName.find("check") != std::string::npos)
    {
        return "BOOL";
    }

    return "UNKNOWN_TYPE";
}

std::vector<std::string> SplitTopLevelCommaList(const std::string& text)
{
    std::vector<std::string> values;
    std::string current;
    int parenDepth = 0;
    int angleDepth = 0;
    int bracketDepth = 0;

    for (const char ch : text)
    {
        if (ch == '(')
        {
            ++parenDepth;
        }
        else if (ch == ')' && parenDepth > 0)
        {
            --parenDepth;
        }
        else if (ch == '<')
        {
            ++angleDepth;
        }
        else if (ch == '>' && angleDepth > 0)
        {
            --angleDepth;
        }
        else if (ch == '[')
        {
            ++bracketDepth;
        }
        else if (ch == ']' && bracketDepth > 0)
        {
            --bracketDepth;
        }

        if (ch == ',' && parenDepth == 0 && angleDepth == 0 && bracketDepth == 0)
        {
            values.push_back(decomp::TrimCopy(current));
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    const std::string tail = decomp::TrimCopy(current);

    if (!tail.empty())
    {
        values.push_back(tail);
    }

    return values;
}

bool IsPrototypeTypeWord(const std::string& token)
{
    static const std::array<const char*, 31> words = {
        "char", "short", "int", "long", "void", "bool", "float", "double",
        "signed", "unsigned", "const", "volatile", "struct", "class", "enum",
        "union", "auto", "register", "__int8", "__int16", "__int32", "__int64",
        "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t",
        "uint32_t", "uint64_t", "size_t"
    };
    const std::string lower = decomp::ToLowerAscii(decomp::TrimCopy(token));

    return std::find_if(
               words.begin(),
               words.end(),
               [&lower](const char* value)
               {
                   return lower == value;
               })
        != words.end();
}

std::string LastIdentifierToken(const std::string& text, size_t& start)
{
    start = std::string::npos;
    size_t end = text.size();

    while (end > 0 && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0)
    {
        --end;
    }

    size_t cursor = end;

    while (cursor > 0)
    {
        const unsigned char ch = static_cast<unsigned char>(text[cursor - 1]);

        if (std::isalnum(ch) == 0 && ch != '_')
        {
            break;
        }

        --cursor;
    }

    if (cursor == end)
    {
        return std::string();
    }

    start = cursor;
    return text.substr(cursor, end - cursor);
}

bool IsFloatingPointPrototypeType(const std::string& type)
{
    const std::string lower = decomp::ToLowerAscii(type);

    if (lower.find('*') != std::string::npos || lower.find('&') != std::string::npos)
    {
        return false;
    }

    return lower.find("float") != std::string::npos
        || lower.find("double") != std::string::npos
        || lower.find("__m128") != std::string::npos
        || lower.find("__m256") != std::string::npos
        || lower.find("__m512") != std::string::npos
        || lower.find("xmm") != std::string::npos
        || lower.find("ymm") != std::string::npos
        || lower.find("zmm") != std::string::npos;
}

std::string PrototypeParameterLocation(uint32_t ordinal, const std::string& type)
{
    static const std::array<const char*, 4> integerRegisterLocations = { "rcx", "rdx", "r8", "r9" };
    static const std::array<const char*, 4> vectorRegisterLocations = { "xmm0", "xmm1", "xmm2", "xmm3" };

    if (ordinal >= 1U && ordinal <= 4U)
    {
        return IsFloatingPointPrototypeType(type)
            ? vectorRegisterLocations[ordinal - 1U]
            : integerRegisterLocations[ordinal - 1U];
    }

    return "stack+" + decomp::HexS64(0x20 + static_cast<int64_t>(ordinal - 5U) * 8);
}

std::vector<decomp::PrototypeParameter> ParsePrototypeParameters(const std::string& prototype)
{
    std::vector<decomp::PrototypeParameter> parameters;
    const std::string trimmed = decomp::TrimCopy(prototype);
    const size_t open = trimmed.find('(');
    const size_t close = trimmed.rfind(')');

    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        return parameters;
    }

    const std::string body = decomp::TrimCopy(trimmed.substr(open + 1, close - open - 1));

    const std::string lowerBody = decomp::ToLowerAscii(body);

    if (body.empty() || lowerBody == "void" || body == "...")
    {
        return parameters;
    }

    const std::vector<std::string> rawParameters = SplitTopLevelCommaList(body);

    for (const std::string& rawParameter : rawParameters)
    {
        std::string parameterText = decomp::TrimCopy(rawParameter);
        const size_t defaultValue = parameterText.find('=');

        if (defaultValue != std::string::npos)
        {
            parameterText = decomp::TrimCopy(parameterText.substr(0, defaultValue));
        }

        if (parameterText.empty())
        {
            continue;
        }

        decomp::PrototypeParameter parameter;
        parameter.Ordinal = static_cast<uint32_t>(parameters.size() + 1U);
        parameter.Confidence = 0.76;

        if (parameterText == "...")
        {
            if (parameters.empty())
            {
                continue;
            }

            parameter.Type = "...";
            parameter.Name = "varargs";
            parameter.Location = "varargs";
            parameter.Confidence = 0.58;
            parameters.push_back(std::move(parameter));
            continue;
        }

        size_t nameStart = std::string::npos;
        const std::string lastToken = LastIdentifierToken(parameterText, nameStart);

        if (!lastToken.empty()
            && nameStart != std::string::npos
            && nameStart > 0
            && !IsPrototypeTypeWord(lastToken))
        {
            parameter.Name = lastToken;
            parameter.Type = decomp::TrimCopy(parameterText.substr(0, nameStart));
        }

        if (parameter.Type.empty())
        {
            parameter.Type = parameterText;
            parameter.Name = "param" + std::to_string(parameter.Ordinal);
            parameter.Confidence = 0.66;
        }

        parameter.Location = PrototypeParameterLocation(parameter.Ordinal, parameter.Type);
        parameters.push_back(std::move(parameter));
    }

    return parameters;
}

std::string InferSideEffectsFromName(const std::string& displayName)
{
    const std::string lowerName = decomp::ToLowerAscii(displayName);

    if (lowerName.find("alloc") != std::string::npos
        || lowerName.find("create") != std::string::npos
        || lowerName.find("init") != std::string::npos)
    {
        return "allocates or initializes state";
    }

    if (lowerName.find("free") != std::string::npos
        || lowerName.find("close") != std::string::npos
        || lowerName.find("release") != std::string::npos)
    {
        return "releases or frees state";
    }

    if (lowerName.find("copy") != std::string::npos
        || lowerName.find("move") != std::string::npos
        || lowerName.find("mem") != std::string::npos
        || lowerName.find("str") != std::string::npos)
    {
        return "reads and writes buffer memory";
    }

    if (lowerName.find("write") != std::string::npos
        || lowerName.find("set") != std::string::npos
        || lowerName.find("store") != std::string::npos
        || lowerName.find("update") != std::string::npos)
    {
        return "writes or mutates state";
    }

    if (lowerName.find("read") != std::string::npos
        || lowerName.find("get") != std::string::npos
        || lowerName.find("query") != std::string::npos)
    {
        return "reads or queries state";
    }

    if (lowerName.find("send") != std::string::npos
        || lowerName.find("recv") != std::string::npos
        || lowerName.find("file") != std::string::npos
        || lowerName.find("socket") != std::string::npos)
    {
        return "performs I/O";
    }

    if (decomp::StartsWithInsensitive(lowerName, "is")
        || decomp::StartsWithInsensitive(lowerName, "has")
        || lowerName.find("check") != std::string::npos
        || lowerName.find("validate") != std::string::npos)
    {
        return "predicate or validation helper";
    }

    return "unknown side effects";
}

std::string InferMemoryEffectsFromName(const std::string& displayName)
{
    const std::string lowerName = decomp::ToLowerAscii(displayName);

    if (lowerName.find("memcpy") != std::string::npos
        || lowerName.find("memmove") != std::string::npos
        || lowerName.find("strcpy") != std::string::npos
        || lowerName.find("copy") != std::string::npos)
    {
        return "writes destination buffer and reads source buffer";
    }

    if (lowerName.find("memset") != std::string::npos
        || lowerName.find("zeromemory") != std::string::npos
        || lowerName.find("fillmemory") != std::string::npos)
    {
        return "writes destination buffer";
    }

    if (lowerName.find("read") != std::string::npos
        || lowerName.find("query") != std::string::npos
        || lowerName.find("get") != std::string::npos)
    {
        return "may read memory or external state";
    }

    if (lowerName.find("write") != std::string::npos
        || lowerName.find("set") != std::string::npos
        || lowerName.find("update") != std::string::npos)
    {
        return "may write memory or external state";
    }

    return "unknown";
}

std::string SimplifyApiNameKey(std::string name)
{
    name = decomp::ToLowerAscii(decomp::TrimCopy(name));
    const size_t bang = name.rfind('!');

    if (bang != std::string::npos && bang + 1 < name.size())
    {
        name = name.substr(bang + 1);
    }

    if (decomp::StartsWithInsensitive(name, "__imp_"))
    {
        name = name.substr(6);
    }

    return name;
}

decomp::PrototypeParameter MakeKnownApiParameter(
    uint32_t ordinal,
    const std::string& name,
    const std::string& type)
{
    decomp::PrototypeParameter parameter;
    parameter.Ordinal = ordinal;
    parameter.Name = name;
    parameter.Type = type;
    parameter.Location = PrototypeParameterLocation(ordinal, type);
    parameter.Confidence = 0.74;
    return parameter;
}

std::vector<decomp::PrototypeParameter> BuildKnownApiParameters(const std::string& displayName)
{
    const std::string key = SimplifyApiNameKey(displayName);

    if (key.find("memcpy") != std::string::npos
        || key.find("memmove") != std::string::npos
        || key.find("rtlcopymemory") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "dst", "void *"),
            MakeKnownApiParameter(2, "src", "const void *"),
            MakeKnownApiParameter(3, "size", "size_t")
        };
    }

    if (key.find("memset") != std::string::npos
        || key.find("rtlfillmemory") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "dst", "void *"),
            MakeKnownApiParameter(2, "value", "int"),
            MakeKnownApiParameter(3, "size", "size_t")
        };
    }

    if (key.find("rtlzeromemory") != std::string::npos
        || key.find("zeromemory") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "dst", "void *"),
            MakeKnownApiParameter(2, "size", "size_t")
        };
    }

    if (key.find("heapalloc") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "heap", "HANDLE"),
            MakeKnownApiParameter(2, "flags", "DWORD"),
            MakeKnownApiParameter(3, "size", "SIZE_T")
        };
    }

    if (key.find("exallocatepool") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "pool_type", "POOL_TYPE"),
            MakeKnownApiParameter(2, "size", "SIZE_T")
        };
    }

    if (key.find("malloc") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "size", "size_t")
        };
    }

    if (key.find("heapfree") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "heap", "HANDLE"),
            MakeKnownApiParameter(2, "flags", "DWORD"),
            MakeKnownApiParameter(3, "ptr", "void *")
        };
    }

    if (key.find("exfreepool") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "ptr", "void *")
        };
    }

    if (key.find("closehandle") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "handle", "HANDLE")
        };
    }

    if (key.find("free") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "ptr", "void *")
        };
    }

    return {};
}

void ApplyKnownApiSemantics(decomp::CallTargetInfo& call)
{
    const std::string key = SimplifyApiNameKey(call.DisplayName);
    bool recognized = false;

    if (key.find("memcpy") != std::string::npos
        || key.find("memmove") != std::string::npos
        || key.find("rtlcopymemory") != std::string::npos)
    {
        call.ReturnType = key.find("rtlcopymemory") != std::string::npos ? "void" : "void *";
        call.SideEffects = "copies bytes between caller-provided buffers";
        call.MemoryEffects = "writes dst[0..size) and reads src[0..size)";
        call.Ownership = "no_transfer";
        recognized = true;
    }
    else if (key.find("memset") != std::string::npos
        || key.find("rtlfillmemory") != std::string::npos
        || key.find("rtlzeromemory") != std::string::npos
        || key.find("zeromemory") != std::string::npos)
    {
        call.ReturnType = (key.find("rtl") != std::string::npos || key.find("zeromemory") != std::string::npos) ? "void" : "void *";
        call.SideEffects = key.find("zero") != std::string::npos ? "zeros caller-provided buffer" : "fills caller-provided buffer";
        call.MemoryEffects = "writes dst[0..size)";
        call.Ownership = "no_transfer";
        recognized = true;
    }
    else if (key.find("malloc") != std::string::npos
        || key.find("heapalloc") != std::string::npos
        || key.find("exallocatepool") != std::string::npos)
    {
        call.ReturnType = "void *";
        call.SideEffects = "allocates memory";
        call.MemoryEffects = "returns newly allocated storage on success";
        call.Ownership = "returns_owned_resource";
        recognized = true;
    }
    else if (key.find("free") != std::string::npos
        || key.find("heapfree") != std::string::npos
        || key.find("exfreepool") != std::string::npos
        || key.find("closehandle") != std::string::npos)
    {
        call.ReturnType = key.find("heapfree") != std::string::npos || key.find("closehandle") != std::string::npos ? "BOOL" : "void";
        call.SideEffects = "releases caller-owned resource";
        call.MemoryEffects = "invalidates released handle or pointer on success";
        call.Ownership = "releases_resource";
        recognized = true;
    }
    else if (decomp::StartsWithInsensitive(key, "nt") || decomp::StartsWithInsensitive(key, "zw"))
    {
        call.ReturnType = "NTSTATUS";
        call.SideEffects = "may update out parameters and returns NTSTATUS";
        call.MemoryEffects = "may read input buffers and write output buffers";
        call.Ownership = "api_contract";
        recognized = true;
    }

    if (recognized)
    {
        const std::vector<decomp::PrototypeParameter> parameters = BuildKnownApiParameters(call.DisplayName);

        if (!parameters.empty())
        {
            call.Parameters = parameters;
        }

        call.Confidence = decomp::Clamp01(call.Confidence + 0.12);
    }
}

void ApplyKnownApiSemantics(decomp::CalleeSummary& summary)
{
    decomp::CallTargetInfo call;
    call.Site = summary.Site;
    call.DisplayName = summary.Callee;
    call.ReturnType = summary.ReturnType;
    call.SideEffects = summary.SideEffects;
    call.MemoryEffects = summary.MemoryEffects;
    call.Ownership = summary.Ownership;
    call.Parameters = summary.Parameters;
    call.Confidence = summary.Confidence;

    ApplyKnownApiSemantics(call);

    summary.ReturnType = call.ReturnType;
    summary.SideEffects = call.SideEffects;
    summary.MemoryEffects = call.MemoryEffects;
    summary.Ownership = call.Ownership;
    summary.Parameters = call.Parameters;
    summary.Confidence = call.Confidence;

    if (!call.Parameters.empty())
    {
        summary.ParameterModel = "known_api_model";
        summary.Source = summary.Source.empty() || summary.Source == "symbol_type" || summary.Source == "symbol"
            ? "known_api_model"
            : summary.Source;
    }
}

bool ContainsAddressInRegions(const std::vector<decomp::FunctionRegion>& regions, const uint64_t address)
{
    return std::any_of(
        regions.begin(),
        regions.end(),
        [address](const decomp::FunctionRegion& region)
        {
            return address >= region.Start && address < region.End;
        });
}

bool TryParseSignedValue(const std::string& text, int64_t& value)
{
    std::string clean = decomp::TrimCopy(text);

    if (clean.empty())
    {
        return false;
    }

    bool negative = false;

    if (clean.front() == '+')
    {
        clean = clean.substr(1);
    }
    else if (clean.front() == '-')
    {
        negative = true;
        clean = clean.substr(1);
    }

    uint64_t parsed = 0;

    if (!decomp::TryParseUnsigned(clean, parsed))
    {
        return false;
    }

    value = negative ? -static_cast<int64_t>(parsed) : static_cast<int64_t>(parsed);
    return true;
}

std::string RemoveAllCopy(std::string text, const std::string& needle)
{
    size_t position = 0;

    while ((position = text.find(needle, position)) != std::string::npos)
    {
        text.erase(position, needle.size());
    }

    return text;
}

std::string NormalizeRegisterAlias(const std::string& token)
{
    const std::string lower = decomp::ToLowerAscii(decomp::TrimCopy(token));

    if (lower == "al" || lower == "ah" || lower == "ax" || lower == "eax" || lower == "rax")
    {
        return "rax";
    }

    if (lower == "bl" || lower == "bh" || lower == "bx" || lower == "ebx" || lower == "rbx")
    {
        return "rbx";
    }

    if (lower == "cl" || lower == "ch" || lower == "cx" || lower == "ecx" || lower == "rcx")
    {
        return "rcx";
    }

    if (lower == "dl" || lower == "dh" || lower == "dx" || lower == "edx" || lower == "rdx")
    {
        return "rdx";
    }

    if (lower == "sil" || lower == "si" || lower == "esi" || lower == "rsi")
    {
        return "rsi";
    }

    if (lower == "dil" || lower == "di" || lower == "edi" || lower == "rdi")
    {
        return "rdi";
    }

    if (lower == "bpl" || lower == "bp" || lower == "ebp" || lower == "rbp")
    {
        return "rbp";
    }

    if (lower == "spl" || lower == "sp" || lower == "esp" || lower == "rsp")
    {
        return "rsp";
    }

    if (decomp::StartsWithInsensitive(lower, "r8"))
    {
        return "r8";
    }

    if (decomp::StartsWithInsensitive(lower, "r9"))
    {
        return "r9";
    }

    if (decomp::StartsWithInsensitive(lower, "r10"))
    {
        return "r10";
    }

    if (decomp::StartsWithInsensitive(lower, "r11"))
    {
        return "r11";
    }

    if (decomp::StartsWithInsensitive(lower, "r12"))
    {
        return "r12";
    }

    if (decomp::StartsWithInsensitive(lower, "r13"))
    {
        return "r13";
    }

    if (decomp::StartsWithInsensitive(lower, "r14"))
    {
        return "r14";
    }

    if (decomp::StartsWithInsensitive(lower, "r15"))
    {
        return "r15";
    }

    return lower;
}

std::vector<std::string> ExtractOperandRegisterTokens(const std::string& operand)
{
    std::vector<std::string> registers;
    std::string current;

    auto flushToken = [&registers, &current]()
    {
        if (current.empty())
        {
            return;
        }

        const std::string canonical = NormalizeRegisterAlias(current);

        if (!canonical.empty()
            && std::find(registers.begin(), registers.end(), canonical) == registers.end())
        {
            registers.push_back(canonical);
        }

        current.clear();
    };

    for (const char ch : operand)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0)
        {
            current.push_back(ch);
        }
        else
        {
            flushToken();
        }
    }

    flushToken();
    return registers;
}

bool TryParseMemoryOperand(const std::string& operand, std::string& baseRegister, int64_t& displacement)
{
    const size_t open = operand.find('[');
    const size_t close = operand.rfind(']');

    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        return false;
    }

    std::string expression = operand.substr(open + 1, close - open - 1);
    expression = decomp::ToLowerAscii(expression);
    expression = RemoveAllCopy(expression, " ");
    expression = RemoveAllCopy(expression, "byteptr");
    expression = RemoveAllCopy(expression, "wordptr");
    expression = RemoveAllCopy(expression, "dwordptr");
    expression = RemoveAllCopy(expression, "qwordptr");
    expression = RemoveAllCopy(expression, "xmmwordptr");
    expression = RemoveAllCopy(expression, "ymmwordptr");
    expression = RemoveAllCopy(expression, "zmmwordptr");
    expression = RemoveAllCopy(expression, "tbyteptr");
    expression = RemoveAllCopy(expression, "ptr");

    if (expression.empty() || expression.find('*') != std::string::npos)
    {
        return false;
    }

    baseRegister.clear();
    displacement = 0;
    int sign = 1;
    std::string token;

    auto consumeToken = [&baseRegister, &displacement](const std::string& currentToken, int currentSign) -> bool
    {
        if (currentToken.empty())
        {
            return false;
        }

        const std::string canonical = NormalizeRegisterAlias(currentToken);

        if (canonical == "rax" || canonical == "rbx" || canonical == "rcx" || canonical == "rdx"
            || canonical == "rsi" || canonical == "rdi" || canonical == "rbp" || canonical == "rsp"
            || canonical == "r8" || canonical == "r9" || canonical == "r10" || canonical == "r11"
            || canonical == "r12" || canonical == "r13" || canonical == "r14" || canonical == "r15"
            || canonical == "rip")
        {
            if (!baseRegister.empty() && baseRegister != canonical)
            {
                return false;
            }

            baseRegister = canonical;
            return true;
        }

        uint64_t parsed = 0;

        if (!decomp::TryParseUnsigned(currentToken, parsed))
        {
            return false;
        }

        displacement += static_cast<int64_t>(parsed) * static_cast<int64_t>(currentSign);
        return true;
    };

    for (const char ch : expression)
    {
        if (ch == '+' || ch == '-')
        {
            if (!token.empty())
            {
                if (!consumeToken(token, sign))
                {
                    return false;
                }

                token.clear();
            }

            sign = (ch == '-') ? -1 : 1;
            continue;
        }

        token.push_back(ch);
    }

    if (!token.empty() && !consumeToken(token, sign))
    {
        return false;
    }

    return !baseRegister.empty();
}

std::string StripTypeQualifiers(std::string typeName)
{
    typeName = decomp::TrimCopy(typeName);
    typeName = RemoveAllCopy(typeName, "__ptr64");
    typeName = RemoveAllCopy(typeName, "__restrict");
    typeName = RemoveAllCopy(typeName, "const ");
    typeName = RemoveAllCopy(typeName, "volatile ");
    typeName = RemoveAllCopy(typeName, "struct ");
    typeName = RemoveAllCopy(typeName, "class ");
    typeName = RemoveAllCopy(typeName, "enum ");
    typeName = RemoveAllCopy(typeName, "union ");

    while (typeName.find("  ") != std::string::npos)
    {
        typeName = RemoveAllCopy(typeName, "  ");
    }

    return decomp::TrimCopy(typeName);
}

bool TryResolveContainerType(
    IDebugSymbols3* symbols,
    const uint64_t moduleBase,
    const std::string& typeName,
    ULONG& resolvedTypeId,
    std::string& resolvedTypeName)
{
    std::string candidate = StripTypeQualifiers(typeName);

    if (candidate.empty())
    {
        return false;
    }

    while (!candidate.empty() && (candidate.back() == '*' || candidate.back() == '&'))
    {
        candidate.pop_back();
        candidate = decomp::TrimCopy(candidate);
    }

    if (candidate.empty())
    {
        return false;
    }

    if (symbols == nullptr || FAILED(symbols->GetTypeId(moduleBase, candidate.c_str(), &resolvedTypeId)))
    {
        return false;
    }

    resolvedTypeName = candidate;
    return true;
}

bool TryGetFieldNameByIndex(IDebugSymbols3* symbols, const uint64_t moduleBase, const ULONG typeId, const ULONG fieldIndex, std::string& fieldName)
{
    std::array<char, 1024> buffer = {};
    ULONG nameSize = 0;

    if (symbols == nullptr
        || FAILED(symbols->GetFieldName(moduleBase, typeId, fieldIndex, buffer.data(), static_cast<ULONG>(buffer.size()), &nameSize)))
    {
        return false;
    }

    fieldName = buffer.data();
    return !fieldName.empty();
}

std::vector<EnumeratedFieldInfo> EnumerateTypeFields(IDebugSymbols3* symbols, const uint64_t moduleBase, const ULONG typeId)
{
    std::vector<EnumeratedFieldInfo> fields;

    for (ULONG fieldIndex = 0; fieldIndex < 128; ++fieldIndex)
    {
        std::string fieldName;

        if (!TryGetFieldNameByIndex(symbols, moduleBase, typeId, fieldIndex, fieldName))
        {
            break;
        }

        ULONG fieldTypeId = 0;
        ULONG fieldOffset = 0;

        if (FAILED(symbols->GetFieldTypeAndOffset(moduleBase, typeId, fieldName.c_str(), &fieldTypeId, &fieldOffset)))
        {
            continue;
        }

        EnumeratedFieldInfo field;
        field.Name = fieldName;
        field.ModuleBase = moduleBase;
        field.TypeId = fieldTypeId;
        field.Offset = fieldOffset;
        TryGetTypeNameFromIds(symbols, moduleBase, fieldTypeId, field.TypeName);
        fields.push_back(std::move(field));
    }

    return fields;
}

bool TryGetLineInfoByOffset(IDebugSymbols3* symbols, const uint64_t address, decomp::PdbSourceLocation& source)
{
    std::array<char, 1024> fileBuffer = {};
    ULONG line = 0;
    ULONG fileSize = 0;
    ULONG64 displacement = 0;

    if (symbols == nullptr
        || FAILED(symbols->GetLineByOffset(address, &line, fileBuffer.data(), static_cast<ULONG>(fileBuffer.size()), &fileSize, &displacement)))
    {
        return false;
    }

    source.Site = address;
    source.File = fileBuffer.data();
    source.Line = line;
    source.Displacement = displacement;
    source.Confidence = 0.80;
    return !source.File.empty() && source.Line != 0;
}

bool TryCollectScopeSymbolsFromGroup(
    IDebugSymbolGroup* group,
    IDebugSymbols3* symbols,
    std::vector<ScopedPdbSymbolRecord>& params,
    std::vector<ScopedPdbSymbolRecord>& locals)
{
    if (group == nullptr)
    {
        return false;
    }

    ULONG count = 0;

    if (FAILED(group->GetNumberSymbols(&count)) || count == 0)
    {
        return false;
    }

    std::vector<DEBUG_SYMBOL_PARAMETERS> parameters(count);

    if (FAILED(group->GetSymbolParameters(0, count, parameters.data())))
    {
        return false;
    }

    for (ULONG index = 0; index < count; ++index)
    {
        const DEBUG_SYMBOL_PARAMETERS& parameter = parameters[index];

        if ((parameter.Flags & (DEBUG_SYMBOL_IS_ARGUMENT | DEBUG_SYMBOL_IS_LOCAL)) == 0)
        {
            continue;
        }

        std::array<char, 1024> nameBuffer = {};
        ULONG nameSize = 0;

        if (FAILED(group->GetSymbolName(index, nameBuffer.data(), static_cast<ULONG>(nameBuffer.size()), &nameSize)))
        {
            continue;
        }

        ScopedPdbSymbolRecord symbol;
        symbol.Name = nameBuffer.data();
        symbol.ModuleBase = parameter.Module;
        symbol.TypeId = parameter.TypeId;
        symbol.Flags = parameter.Flags;
        TryGetTypeNameFromIds(symbols, symbol.ModuleBase, symbol.TypeId, symbol.TypeName);

        if ((parameter.Flags & DEBUG_SYMBOL_IS_ARGUMENT) != 0)
        {
            params.push_back(symbol);
        }
        else if ((parameter.Flags & DEBUG_SYMBOL_IS_LOCAL) != 0)
        {
            locals.push_back(symbol);
        }
    }

    return !params.empty() || !locals.empty();
}

bool TryCollectScopeSymbolsFromGroup2(
    IDebugSymbolGroup2* group,
    IDebugSymbols3* symbols,
    std::vector<ScopedPdbSymbolRecord>& params,
    std::vector<ScopedPdbSymbolRecord>& locals)
{
    if (group == nullptr)
    {
        return false;
    }

    ULONG count = 0;

    if (FAILED(group->GetNumberSymbols(&count)) || count == 0)
    {
        return false;
    }

    std::vector<DEBUG_SYMBOL_PARAMETERS> parameters(count);

    if (FAILED(group->GetSymbolParameters(0, count, parameters.data())))
    {
        return false;
    }

    for (ULONG index = 0; index < count; ++index)
    {
        const DEBUG_SYMBOL_PARAMETERS& parameter = parameters[index];

        if ((parameter.Flags & (DEBUG_SYMBOL_IS_ARGUMENT | DEBUG_SYMBOL_IS_LOCAL)) == 0)
        {
            continue;
        }

        std::array<char, 1024> nameBuffer = {};
        ULONG nameSize = 0;

        if (FAILED(group->GetSymbolName(index, nameBuffer.data(), static_cast<ULONG>(nameBuffer.size()), &nameSize)))
        {
            continue;
        }

        ScopedPdbSymbolRecord symbol;
        symbol.Name = nameBuffer.data();
        symbol.ModuleBase = parameter.Module;
        symbol.TypeId = parameter.TypeId;
        symbol.Flags = parameter.Flags;
        TryGetTypeNameFromIds(symbols, symbol.ModuleBase, symbol.TypeId, symbol.TypeName);

        DEBUG_SYMBOL_ENTRY entry = {};

        if (SUCCEEDED(group->GetSymbolEntryInformation(index, &entry)) && entry.Offset != 0)
        {
            symbol.Site = entry.Offset;
        }

        if ((parameter.Flags & DEBUG_SYMBOL_IS_ARGUMENT) != 0)
        {
            params.push_back(symbol);
        }
        else if ((parameter.Flags & DEBUG_SYMBOL_IS_LOCAL) != 0)
        {
            locals.push_back(symbol);
        }
    }

    return !params.empty() || !locals.empty();
}

bool CollectScopedPdbSymbols(
    IDebugSymbols3* symbols,
    IDebugSymbols5* symbols5,
    const uint64_t entryAddress,
    const std::vector<decomp::FunctionRegion>& regions,
    std::vector<ScopedPdbSymbolRecord>& params,
    std::vector<ScopedPdbSymbolRecord>& locals,
    std::string& scopeKind,
    std::vector<std::string>& conflicts)
{
    params.clear();
    locals.clear();
    scopeKind.clear();

    if (symbols == nullptr)
    {
        return false;
    }

    ULONG64 savedInstructionOffset = 0;
    DEBUG_STACK_FRAME savedFrame = {};
    const bool hasSavedScope = SUCCEEDED(symbols->GetScope(&savedInstructionOffset, &savedFrame, nullptr, 0));
    bool switchedScope = false;

    if (hasSavedScope && ContainsAddressInRegions(regions, savedInstructionOffset))
    {
        scopeKind = "current_frame";
    }
    else
    {
        const HRESULT setScopeHr = symbols->SetScope(entryAddress, nullptr, nullptr, 0);

        if (FAILED(setScopeHr))
        {
            conflicts.push_back("pdb scoped symbol collection failed: could not set debugger scope to target function");
            return false;
        }

        switchedScope = true;
        scopeKind = "instruction_scope";
    }

    bool success = false;

    if (symbols5 != nullptr)
    {
        ComPtr<IDebugSymbolGroup2> group2;

        if (SUCCEEDED(symbols5->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_ALL, nullptr, group2.GetAddressOf())))
        {
            success = TryCollectScopeSymbolsFromGroup2(group2.Get(), symbols, params, locals);
        }
    }

    if (!success)
    {
        ComPtr<IDebugSymbolGroup> group;

        if (SUCCEEDED(symbols->GetScopeSymbolGroup(DEBUG_SCOPE_GROUP_ALL, nullptr, group.GetAddressOf())))
        {
            ComPtr<IDebugSymbolGroup2> group2;

            if (SUCCEEDED(group.As(&group2)))
            {
                success = TryCollectScopeSymbolsFromGroup2(group2.Get(), symbols, params, locals);
            }
            else
            {
                success = TryCollectScopeSymbolsFromGroup(group.Get(), symbols, params, locals);
            }
        }
    }

    if (switchedScope)
    {
        if (hasSavedScope)
        {
            symbols->SetScope(0, &savedFrame, nullptr, 0);
        }
        else
        {
            symbols->ResetScope();
        }
    }

    return success;
}

std::vector<TypedBaseCandidate> BuildTypedBaseCandidates(
    const std::vector<ScopedPdbSymbolRecord>& pdbParams,
    const decomp::AnalysisFacts& facts)
{
    std::vector<TypedBaseCandidate> candidates;
    const size_t count = (std::min)(pdbParams.size(), facts.RecoveredArguments.size());

    for (size_t index = 0; index < count; ++index)
    {
        const auto& pdbParam = pdbParams[index];
        const auto& recovered = facts.RecoveredArguments[index];

        if (recovered.Register.empty() || pdbParam.TypeName.empty())
        {
            continue;
        }

        TypedBaseCandidate candidate;
        candidate.Name = !pdbParam.Name.empty() ? pdbParam.Name : recovered.Name;
        candidate.TypeName = pdbParam.TypeName;
        candidate.BaseRegister = recovered.Register;
        candidate.ModuleBase = pdbParam.ModuleBase;
        candidate.TypeId = pdbParam.TypeId;
        candidate.Confidence = decomp::Clamp01((recovered.Confidence * 0.35) + 0.60);
        candidates.push_back(std::move(candidate));
    }

    return candidates;
}

void ApplyPdbParamsToRecoveredArguments(
    const std::vector<ScopedPdbSymbolRecord>& pdbParams,
    decomp::AnalysisFacts& facts)
{
    const size_t count = (std::min)(pdbParams.size(), facts.RecoveredArguments.size());

    for (size_t index = 0; index < count; ++index)
    {
        const ScopedPdbSymbolRecord& pdbParam = pdbParams[index];
        decomp::RecoveredArgument& recovered = facts.RecoveredArguments[index];

        if (!pdbParam.Name.empty() && recovered.Name != pdbParam.Name)
        {
            if (!recovered.Name.empty() && !decomp::StartsWithInsensitive(recovered.Name, "arg"))
            {
                facts.Pdb.Conflicts.push_back(
                    "pdb parameter name '" + pdbParam.Name + "' replaced heuristic name '" + recovered.Name + "'");
            }

            recovered.Name = pdbParam.Name;
        }

        if (!pdbParam.TypeName.empty() && recovered.TypeHint != pdbParam.TypeName)
        {
            if (!recovered.TypeHint.empty() && recovered.TypeHint != "UNKNOWN_TYPE" && recovered.TypeHint != "UNKNOWN_TYPE*")
            {
                facts.Pdb.Conflicts.push_back(
                    "pdb parameter type '" + pdbParam.TypeName + "' replaced heuristic type '" + recovered.TypeHint + "'");
            }

            recovered.TypeHint = pdbParam.TypeName;
        }

        recovered.Confidence = decomp::Clamp01((recovered.Confidence * 0.40) + 0.60);
    }

    if (facts.RecoveredArguments.empty() && !pdbParams.empty() && decomp::StartsWithInsensitive(facts.CallingConvention, "ms_x64"))
    {
        static const std::array<const char*, 4> registers = { "rcx", "rdx", "r8", "r9" };

        for (size_t index = 0; index < pdbParams.size() && index < registers.size(); ++index)
        {
            decomp::RecoveredArgument recovered;
            recovered.Name = pdbParams[index].Name.empty() ? ("arg" + std::to_string(index + 1)) : pdbParams[index].Name;
            recovered.Register = registers[index];
            recovered.TypeHint = pdbParams[index].TypeName;
            recovered.RoleHint = decomp::ContainsInsensitive(pdbParams[index].TypeName, "*") ? "pointer_like" : "scalar";
            recovered.FirstUseSite = facts.EntryAddress;
            recovered.UseCount = 1;
            recovered.Confidence = 0.78;
            facts.RecoveredArguments.push_back(std::move(recovered));
        }
    }
}

void CollectPdbSourceLocations(
    IDebugSymbols3* symbols,
    const decomp::AnalysisFacts& facts,
    decomp::PdbFacts& pdb)
{
    std::set<uint64_t> candidateSites;
    candidateSites.insert(facts.EntryAddress);

    for (const auto& call : facts.Calls)
    {
        candidateSites.insert(call.Site);
    }

    for (const auto& condition : facts.NormalizedConditions)
    {
        candidateSites.insert(condition.Site);
    }

    for (const auto& reference : facts.DataReferences)
    {
        candidateSites.insert(reference.Site);
    }

    size_t added = 0;

    for (const uint64_t site : candidateSites)
    {
        if (added >= 16)
        {
            break;
        }

        decomp::PdbSourceLocation source;

        if (TryGetLineInfoByOffset(symbols, site, source))
        {
            pdb.SourceLocations.push_back(std::move(source));
            ++added;
        }
    }
}

void CollectPdbFieldHints(
    IDebugSymbols3* symbols,
    const decomp::AnalysisFacts& facts,
    const std::vector<TypedBaseCandidate>& candidates,
    std::unordered_map<std::string, EnumeratedFieldInfo>& fieldByRegisterAndOffset,
    decomp::PdbFacts& pdb)
{
    std::set<std::string> seenHints;

    for (const TypedBaseCandidate& candidate : candidates)
    {
        ULONG containerTypeId = 0;
        std::string containerTypeName;

        if (!TryResolveContainerType(symbols, candidate.ModuleBase, candidate.TypeName, containerTypeId, containerTypeName))
        {
            continue;
        }

        const std::vector<EnumeratedFieldInfo> fields = EnumerateTypeFields(symbols, candidate.ModuleBase, containerTypeId);

        for (const decomp::MemoryAccess& access : facts.MemoryAccesses)
        {
            if (NormalizeRegisterAlias(access.BaseRegister) != NormalizeRegisterAlias(candidate.BaseRegister))
            {
                continue;
            }

            int64_t displacement = 0;

            if (!TryParseSignedValue(access.Displacement, displacement) || displacement < 0)
            {
                continue;
            }

            for (const EnumeratedFieldInfo& field : fields)
            {
                if (static_cast<int64_t>(field.Offset) != displacement)
                {
                    continue;
                }

                const std::string key =
                    candidate.BaseRegister + ":" + std::to_string(displacement) + ":" + std::to_string(access.Site);

                if (!seenHints.insert(key).second)
                {
                    continue;
                }

                decomp::PdbFieldHint hint;
                hint.BaseName = candidate.Name;
                hint.BaseType = containerTypeName;
                hint.FieldName = field.Name;
                hint.FieldType = field.TypeName;
                hint.BaseRegister = candidate.BaseRegister;
                hint.Offset = displacement;
                hint.Site = access.Site;
                hint.Confidence = decomp::Clamp01(candidate.Confidence * 0.92);
                pdb.FieldHints.push_back(hint);

                fieldByRegisterAndOffset[candidate.BaseRegister + ":" + std::to_string(displacement)] = field;
            }
        }
    }
}

void CollectPdbEnumHints(
    IDebugSymbols3* symbols,
    const decomp::AnalysisFacts& facts,
    const std::vector<TypedBaseCandidate>& candidates,
    const std::unordered_map<std::string, EnumeratedFieldInfo>& fieldByRegisterAndOffset,
    decomp::PdbFacts& pdb)
{
    std::unordered_map<std::string, TypedBaseCandidate> candidateByRegister;

    for (const TypedBaseCandidate& candidate : candidates)
    {
        candidateByRegister[candidate.BaseRegister] = candidate;
    }

    for (const decomp::DisassembledInstruction& instruction : facts.Instructions)
    {
        if (instruction.Mnemonic != "cmp")
        {
            continue;
        }

        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

        if (operands.size() != 2)
        {
            continue;
        }

        auto tryEmitEnumHint =
            [&](const std::string& typedOperand, const std::string& immediateOperand) -> void
            {
                uint64_t value = 0;

                if (!decomp::TryParseUnsigned(immediateOperand, value))
                {
                    return;
                }

                uint64_t moduleBase = 0;
                ULONG typeId = 0;
                std::string typeName;

                std::string baseRegister;
                int64_t displacement = 0;

                if (TryParseMemoryOperand(typedOperand, baseRegister, displacement))
                {
                    const auto fieldIt = fieldByRegisterAndOffset.find(NormalizeRegisterAlias(baseRegister) + ":" + std::to_string(displacement));

                    if (fieldIt == fieldByRegisterAndOffset.end())
                    {
                        return;
                    }

                    moduleBase = fieldIt->second.ModuleBase;
                    typeId = fieldIt->second.TypeId;
                    typeName = fieldIt->second.TypeName;
                }
                else
                {
                    const std::vector<std::string> registers = ExtractOperandRegisterTokens(typedOperand);

                    if (registers.size() != 1)
                    {
                        return;
                    }

                    const auto candidateIt = candidateByRegister.find(registers.front());

                    if (candidateIt == candidateByRegister.end())
                    {
                        return;
                    }

                    moduleBase = candidateIt->second.ModuleBase;
                    typeId = candidateIt->second.TypeId;
                    typeName = candidateIt->second.TypeName;
                }

                std::array<char, 1024> constantBuffer = {};
                ULONG nameSize = 0;

                if (symbols == nullptr
                    || FAILED(symbols->GetConstantName(moduleBase, typeId, value, constantBuffer.data(), static_cast<ULONG>(constantBuffer.size()), &nameSize)))
                {
                    return;
                }

                decomp::PdbEnumHint hint;
                hint.TypeName = typeName;
                hint.ConstantName = constantBuffer.data();
                hint.Expression = decomp::TrimCopy(typedOperand) + " == " + hint.ConstantName;
                hint.Value = value;
                hint.Site = instruction.Address;
                hint.Confidence = 0.86;
                pdb.EnumHints.push_back(std::move(hint));
            };

        tryEmitEnumHint(operands[0], operands[1]);
        tryEmitEnumHint(operands[1], operands[0]);
    }
}

void CollectPdbFacts(
    IDebugSymbols3* symbols,
    IDebugSymbols5* symbols5,
    const decomp::ModuleInfo& moduleInfo,
    const std::vector<decomp::FunctionRegion>& regions,
    decomp::AnalysisFacts& facts)
{
    facts.Pdb = decomp::PdbFacts();
    facts.Pdb.SymbolFile = ReadModuleNameString(symbols, DEBUG_MODNAME_SYMBOL_FILE, DEBUG_ANY_ID, moduleInfo.Base);

    SymbolLookupResult functionSymbol;

    if (TryLookupSymbolByOffset(symbols, facts.EntryAddress, functionSymbol))
    {
        facts.Pdb.FunctionName = SimplifySymbolDisplay(functionSymbol.Name);
    }
    else
    {
        facts.Pdb.FunctionName = facts.QueryText;
    }

    if (TryGetTypeNameForOffset(symbols, facts.EntryAddress, facts.Pdb.Prototype))
    {
        facts.Pdb.ReturnType = ExtractReturnTypeFromPrototype(facts.Pdb.Prototype, facts.Pdb.FunctionName);
        facts.Pdb.PrototypeParameters = ParsePrototypeParameters(facts.Pdb.Prototype);
    }

    std::vector<ScopedPdbSymbolRecord> pdbParams;
    std::vector<ScopedPdbSymbolRecord> pdbLocals;
    CollectScopedPdbSymbols(symbols, symbols5, facts.EntryAddress, regions, pdbParams, pdbLocals, facts.Pdb.ScopeKind, facts.Pdb.Conflicts);

    if (facts.Pdb.ScopeKind.empty())
    {
        facts.Pdb.ScopeKind = "none";
    }

    for (const ScopedPdbSymbolRecord& param : pdbParams)
    {
        decomp::PdbScopedSymbol symbol;
        symbol.Name = param.Name;
        symbol.Type = param.TypeName;
        symbol.Storage = "argument";
        symbol.Location = facts.Pdb.ScopeKind;
        symbol.Site = param.Site;
        symbol.Confidence = 0.82;
        facts.Pdb.Params.push_back(std::move(symbol));
    }

    for (const ScopedPdbSymbolRecord& local : pdbLocals)
    {
        decomp::PdbScopedSymbol symbol;
        symbol.Name = local.Name;
        symbol.Type = local.TypeName;
        symbol.Storage = "local";
        symbol.Location = facts.Pdb.ScopeKind;
        symbol.Site = local.Site;
        symbol.Confidence = 0.74;
        facts.Pdb.Locals.push_back(std::move(symbol));
    }

    ApplyPdbParamsToRecoveredArguments(pdbParams, facts);
    decomp::RefreshDerivedAnalysisFacts(facts);
    CollectPdbSourceLocations(symbols, facts, facts.Pdb);

    std::unordered_map<std::string, EnumeratedFieldInfo> fieldByRegisterAndOffset;
    const std::vector<TypedBaseCandidate> typedBaseCandidates = BuildTypedBaseCandidates(pdbParams, facts);
    CollectPdbFieldHints(symbols, facts, typedBaseCandidates, fieldByRegisterAndOffset, facts.Pdb);
    CollectPdbEnumHints(symbols, facts, typedBaseCandidates, fieldByRegisterAndOffset, facts.Pdb);

    for (const decomp::PdbScopedSymbol& param : facts.Pdb.Params)
    {
        decomp::TypeRecoveryHint hint;
        hint.Site = param.Site;
        hint.Expression = param.Name;
        hint.Type = param.Type;
        hint.Source = "pdb_param";
        hint.Kind = "declared_parameter";
        hint.Evidence = param.Location;
        hint.PointerLike = param.Type.find('*') != std::string::npos;
        hint.Confidence = param.Confidence;
        facts.TypeHints.push_back(std::move(hint));
    }

    for (const decomp::PdbScopedSymbol& local : facts.Pdb.Locals)
    {
        decomp::TypeRecoveryHint hint;
        hint.Site = local.Site;
        hint.Expression = local.Name;
        hint.Type = local.Type;
        hint.Source = "pdb_local";
        hint.Kind = "declared_local";
        hint.Evidence = local.Location;
        hint.PointerLike = local.Type.find('*') != std::string::npos;
        hint.Confidence = local.Confidence;
        facts.TypeHints.push_back(std::move(hint));
    }

    for (const decomp::PdbFieldHint& field : facts.Pdb.FieldHints)
    {
        decomp::TypeRecoveryHint hint;
        hint.Site = field.Site;
        hint.Expression = field.BaseName + "->" + field.FieldName;
        hint.Type = field.FieldType;
        hint.Source = "pdb_field";
        hint.Kind = "field_offset";
        hint.Evidence = field.BaseType + decomp::HexS64(field.Offset);
        hint.PointerLike = field.FieldType.find('*') != std::string::npos;
        hint.Confidence = field.Confidence;
        facts.TypeHints.push_back(std::move(hint));
    }

    for (const decomp::PdbEnumHint& enumHint : facts.Pdb.EnumHints)
    {
        decomp::TypeRecoveryHint hint;
        hint.Site = enumHint.Site;
        hint.Expression = enumHint.Expression;
        hint.Type = enumHint.TypeName;
        hint.Source = "pdb_enum";
        hint.Kind = "enum_constant";
        hint.Evidence = enumHint.ConstantName + "=" + decomp::HexU64(enumHint.Value);
        hint.EnumLike = true;
        hint.Confidence = enumHint.Confidence;
        facts.TypeHints.push_back(std::move(hint));
    }

    if (!facts.Pdb.SymbolFile.empty() || !facts.Pdb.FunctionName.empty())
    {
        facts.Pdb.Availability = "symbols";
        facts.Pdb.Confidence = 0.45;
    }

    if (!facts.Pdb.Prototype.empty() || !facts.Pdb.SourceLocations.empty() || !facts.Pdb.FieldHints.empty() || !facts.Pdb.EnumHints.empty())
    {
        facts.Pdb.Availability = "typed";
        facts.Pdb.Confidence = 0.72;
    }

    if (!facts.Pdb.Params.empty() || !facts.Pdb.Locals.empty())
    {
        facts.Pdb.Availability = "scoped";
        facts.Pdb.Confidence = 0.88;
    }

    if (facts.Pdb.Availability != "none")
    {
        facts.Facts.push_back("pdb facts available: " + facts.Pdb.Availability);
    }

    if (!facts.Pdb.Params.empty())
    {
        facts.Facts.push_back("pdb scoped params: " + std::to_string(facts.Pdb.Params.size()));
    }

    if (!facts.Pdb.Locals.empty())
    {
        facts.Facts.push_back("pdb scoped locals: " + std::to_string(facts.Pdb.Locals.size()));
    }

    if (!facts.Pdb.FieldHints.empty())
    {
        facts.Facts.push_back("pdb field hints: " + std::to_string(facts.Pdb.FieldHints.size()));
    }

    if (!facts.Pdb.EnumHints.empty())
    {
        facts.Facts.push_back("pdb enum hints: " + std::to_string(facts.Pdb.EnumHints.size()));
    }

    if (!facts.TypeHints.empty())
    {
        facts.Facts.push_back("combined type hints: " + std::to_string(facts.TypeHints.size()));
    }
}

bool IsTailCallContext(const DecodedInstructionContext& context, const decomp::AnalysisFacts& facts)
{
    if (!context.IsUnconditionalBranch
        || context.IsIndirect
        || !context.HasBranchTarget
        || context.BranchTarget == context.EndAddress)
    {
        return false;
    }

    for (const decomp::DisassembledInstruction& instruction : facts.Instructions)
    {
        if (instruction.Address == context.BranchTarget)
        {
            return false;
        }
    }

    return true;
}

void EnrichAnalysisFactsWithDebugMetadata(
    IDebugSymbols3* symbols,
    IDebugDataSpaces4* dataSpaces,
    const decomp::ModuleInfo& moduleInfo,
    const std::vector<DecodedInstructionContext>& decodedContexts,
    decomp::AnalysisFacts& facts)
{
    facts.DataReferences.clear();
    facts.CallTargets.clear();

    for (const DecodedInstructionContext& context : decodedContexts)
    {
        SymbolLookupResult directSymbol;
        SymbolLookupResult pointedSymbol;
        decomp::ModuleInfo targetModule;
        uint64_t pointerValue = 0;
        std::string stringPreview;

        if (context.HasRipRelativeMemory)
        {
            decomp::DataReference reference;
            reference.Site = context.Address;
            reference.TargetAddress = context.RipRelativeTarget;
            reference.RipRelative = true;

            const bool hasDirectSymbol = TryLookupSymbolByOffset(symbols, context.RipRelativeTarget, directSymbol);
            const bool hasPointerValue = TryReadPointerValue(dataSpaces, context.RipRelativeTarget, pointerValue);
            const bool hasPointedSymbol = hasPointerValue && TryLookupSymbolByOffset(symbols, pointerValue, pointedSymbol);
            const bool hasAscii = TryReadAsciiString(dataSpaces, context.RipRelativeTarget, stringPreview);
            const bool hasUtf16 = !hasAscii && TryReadUtf16String(dataSpaces, context.RipRelativeTarget, stringPreview);

            if (hasDirectSymbol && directSymbol.Exact)
            {
                CollectModuleInfo(symbols, context.RipRelativeTarget, targetModule);
            }
            else if (hasPointedSymbol)
            {
                CollectModuleInfo(symbols, pointerValue, targetModule);
            }

            if ((hasDirectSymbol && decomp::ContainsInsensitive(directSymbol.Name, "__imp_")) || hasPointedSymbol)
            {
                reference.Kind = "import_thunk";
                reference.Symbol = SimplifySymbolDisplay(hasPointedSymbol ? pointedSymbol.Name : directSymbol.Name);
                reference.Display = reference.Symbol;
                reference.ModuleName = !targetModule.ModuleName.empty() ? targetModule.ModuleName : moduleInfo.ModuleName;
                reference.Dereferenced = hasPointedSymbol;
            }
            else if (hasAscii || hasUtf16)
            {
                reference.Kind = hasAscii ? "string_ascii" : "string_utf16";
                reference.Display = stringPreview;
                reference.Preview = stringPreview;
                reference.ModuleName = moduleInfo.ModuleName;
            }
            else if (hasDirectSymbol)
            {
                reference.Kind = "global_symbol";
                reference.Symbol = SimplifySymbolDisplay(directSymbol.Name);
                reference.Display = reference.Symbol;
                reference.ModuleName = !targetModule.ModuleName.empty() ? targetModule.ModuleName : moduleInfo.ModuleName;
            }
            else
            {
                reference.Kind = "global_data";
                reference.Display = decomp::HexU64(context.RipRelativeTarget);
                reference.ModuleName = moduleInfo.ModuleName;
            }

            facts.DataReferences.push_back(std::move(reference));
        }

        const bool isTailCall = IsTailCallContext(context, facts);

        if (!context.IsCall && !isTailCall)
        {
            continue;
        }

        decomp::CallTargetInfo call;
        call.Site = context.Address;
        call.Indirect = context.IsIndirect;
        call.TailCall = isTailCall;
        const decomp::MemoryAccess* callAccess = FindMemoryAccessAtSite(facts, context.Address);

        uint64_t targetAddress = 0;

        if (context.HasBranchTarget)
        {
            targetAddress = context.BranchTarget;
        }
        else if (context.HasRipRelativeMemory && TryReadPointerValue(dataSpaces, context.RipRelativeTarget, targetAddress))
        {
            call.TargetKind = "import_iat";
        }

        call.TargetAddress = targetAddress;

        if (context.IsIndirect && callAccess != nullptr)
        {
            int64_t displacement = 0;
            const bool hasParsedDisplacement = callAccess->Displacement.empty()
                || TryParseSignedValue(callAccess->Displacement, displacement);

            call.TargetExpression = BuildMemoryExpression(*callAccess);

            if (call.TargetKind.empty())
            {
                call.TargetKind = "indirect_memory";
            }

            if (callAccess->WidthBits == 64
                && !callAccess->StackFrameRelative
                && !callAccess->BaseRegister.empty()
                && callAccess->BaseRegister != "rip"
                && callAccess->BaseRegister != "rsp"
                && callAccess->BaseRegister != "rbp"
                && hasParsedDisplacement
                && displacement >= 0)
            {
                call.VirtualCall = true;
                call.VtableOffset = static_cast<uint32_t>(displacement);
                call.TargetKind = "virtual_call_candidate";
            }
        }
        else if (context.IsIndirect && !context.Operands.empty())
        {
            call.TargetExpression = decomp::JoinStrings(context.Operands, ", ");
        }

        SymbolLookupResult symbol;
        decomp::ModuleInfo calleeModule;
        std::string typeName;

        if (targetAddress != 0)
        {
            TryLookupSymbolByOffset(symbols, targetAddress, symbol);
            CollectModuleInfo(symbols, targetAddress, calleeModule);
            if (!TryGetTypeNameForOffset(symbols, targetAddress, typeName) && !symbol.Name.empty())
            {
                TryGetTypeNameForSymbol(symbols, symbol.Name, typeName);
            }
        }

        const std::string displayName =
            !symbol.Name.empty() ? SimplifySymbolDisplay(symbol.Name)
            : context.HasRipRelativeMemory ? decomp::HexU64(context.RipRelativeTarget)
            : context.Operands.empty() ? "<unknown>"
            : decomp::JoinStrings(context.Operands, ", ");

        if (call.TargetKind.empty())
        {
            if (targetAddress != 0 && !calleeModule.ModuleName.empty())
            {
                const std::string scope = (calleeModule.ModuleName == moduleInfo.ModuleName) ? "internal" : "external";
                call.TargetKind = isTailCall
                    ? ("tail_call_" + scope + (context.IsIndirect ? "_indirect" : "_direct"))
                    : (scope + (context.IsIndirect ? "_indirect" : "_direct"));
            }
            else
            {
                call.TargetKind = isTailCall
                    ? (context.IsIndirect ? "tail_call_indirect" : "tail_call_direct")
                    : (context.IsIndirect ? "indirect" : "direct");
            }
        }

        call.DisplayName = displayName;
        call.ModuleName = !calleeModule.ModuleName.empty() ? calleeModule.ModuleName : moduleInfo.ModuleName;
        call.Prototype = !typeName.empty() ? typeName : ("UNKNOWN_TYPE " + displayName + "(...)");
        call.ReturnType = ExtractReturnTypeFromPrototype(typeName, displayName);
        call.Parameters = ParsePrototypeParameters(call.Prototype);
        call.SideEffects = isTailCall ? "tail-calls target and does not return to this function" : InferSideEffectsFromName(displayName);
        call.MemoryEffects = InferMemoryEffectsFromName(displayName);
        call.Ownership =
            (decomp::ContainsInsensitive(displayName, "Alloc") || decomp::ContainsInsensitive(displayName, "malloc") || decomp::ContainsInsensitive(displayName, "operator new")) ? "may_return_owned_resource"
            : (decomp::ContainsInsensitive(displayName, "Free") || decomp::ContainsInsensitive(displayName, "delete") || decomp::ContainsInsensitive(displayName, "Close")) ? "may_release_resource"
            : "unknown";
        call.Confidence = decomp::Clamp01(
            0.50
            + (targetAddress != 0 ? 0.10 : 0.0)
            + (!symbol.Name.empty() ? 0.15 : 0.0)
            + (!typeName.empty() ? 0.15 : 0.0)
            + (context.HasRipRelativeMemory ? 0.05 : 0.0)
            + (isTailCall ? 0.05 : 0.0)
            + (call.VirtualCall ? 0.06 : 0.0));
        ApplyKnownApiSemantics(call);
        facts.CallTargets.push_back(std::move(call));
    }

    if (!facts.DataReferences.empty())
    {
        facts.Facts.push_back("rip-relative references classified: " + std::to_string(facts.DataReferences.size()));
    }

    if (!facts.CallTargets.empty())
    {
        facts.Facts.push_back("call target summaries: " + std::to_string(facts.CallTargets.size()));
    }

    for (const decomp::CallTargetInfo& target : facts.CallTargets)
    {
        auto existing = std::find_if(
            facts.CalleeSummaries.begin(),
            facts.CalleeSummaries.end(),
            [&target](const decomp::CalleeSummary& summary)
            {
                return summary.Site == target.Site;
            });

        decomp::CalleeSummary summary;
        summary.Site = target.Site;
        summary.Callee = target.DisplayName;
        summary.ReturnType = !target.ReturnType.empty() ? target.ReturnType : "UNKNOWN_TYPE";
        summary.ParameterModel = !target.Prototype.empty() ? target.Prototype : "UNKNOWN_TYPE " + target.DisplayName + "(...)";
        summary.SideEffects = target.SideEffects.empty() ? "unknown" : target.SideEffects;
        summary.MemoryEffects = !target.MemoryEffects.empty()
            ? target.MemoryEffects
            : target.TailCall ? "delegates to tail-call target" : InferMemoryEffectsFromName(target.DisplayName);
        if (summary.MemoryEffects == "unknown")
        {
            summary.MemoryEffects = target.SideEffects;
        }
        summary.Ownership = !target.Ownership.empty() ? target.Ownership
            : (decomp::ContainsInsensitive(target.DisplayName, "Alloc") || decomp::ContainsInsensitive(target.DisplayName, "malloc") || decomp::ContainsInsensitive(target.DisplayName, "operator new")) ? "may_return_owned_resource"
            : (decomp::ContainsInsensitive(target.DisplayName, "Free") || decomp::ContainsInsensitive(target.DisplayName, "delete") || decomp::ContainsInsensitive(target.DisplayName, "Close")) ? "may_release_resource"
            : "unknown";
        summary.Source = target.TailCall ? "tail_call_target" : (target.Prototype.empty() ? "symbol" : "symbol_type");
        summary.Parameters = target.Parameters;
        summary.TailCall = target.TailCall;
        summary.Confidence = decomp::Clamp01(target.Confidence + (!target.Prototype.empty() ? 0.08 : 0.0) + (target.TailCall ? 0.03 : 0.0));
        ApplyKnownApiSemantics(summary);

        if (existing != facts.CalleeSummaries.end())
        {
            *existing = std::move(summary);
        }
        else
        {
            facts.CalleeSummaries.push_back(std::move(summary));
        }
    }

    for (const decomp::CallTargetInfo& target : facts.CallTargets)
    {
        std::string name;
        std::string summary;
        std::string replacement;

        if (decomp::ContainsInsensitive(target.DisplayName, "memcpy") || decomp::ContainsInsensitive(target.DisplayName, "memmove"))
        {
            name = "memory_copy";
            summary = "symbol-resolved memory copy helper";
            replacement = "copy_bytes(dst, src, size)";
        }
        else if (decomp::ContainsInsensitive(target.DisplayName, "memset") || decomp::ContainsInsensitive(target.DisplayName, "RtlZeroMemory"))
        {
            name = "memory_fill";
            summary = "symbol-resolved memory fill helper";
            replacement = "fill_bytes(dst, value, size)";
        }
        else if (decomp::ContainsInsensitive(target.DisplayName, "__security_check_cookie"))
        {
            name = "security_cookie";
            summary = "symbol-resolved compiler security cookie check";
            replacement = "verify_stack_cookie()";
        }
        else if (decomp::ContainsInsensitive(target.DisplayName, "__chkstk") || decomp::ContainsInsensitive(target.DisplayName, "_alloca_probe"))
        {
            name = "stack_probe";
            summary = "symbol-resolved compiler stack probe";
            replacement = "probe_stack_allocation(size)";
        }

        if (name.empty())
        {
            continue;
        }

        const auto duplicate = std::find_if(
            facts.Idioms.begin(),
            facts.Idioms.end(),
            [&target, &name](const decomp::IdiomPattern& idiom)
            {
                return idiom.Site == target.Site && idiom.Name == name;
            });

        if (duplicate != facts.Idioms.end())
        {
            continue;
        }

        decomp::IdiomPattern idiom;
        idiom.Site = target.Site;
        idiom.Kind = "library_call";
        idiom.Name = name;
        idiom.Summary = summary;
        idiom.Replacement = replacement;
        idiom.Evidence = target.DisplayName;
        idiom.Confidence = target.Confidence > 0.0 ? decomp::Clamp01(target.Confidence + 0.08) : 0.78;
        facts.Idioms.push_back(std::move(idiom));
    }

    RecoverSwitchTargetsFromDebugData(dataSpaces, moduleInfo, facts.Regions, decodedContexts, facts);

    size_t recoveredSwitchTargets = 0;

    for (const decomp::SwitchInfo& switchInfo : facts.Switches)
    {
        recoveredSwitchTargets += switchInfo.CaseTargets.size();
    }

    if (recoveredSwitchTargets != 0)
    {
        facts.Facts.push_back("switch case targets recovered: " + std::to_string(recoveredSwitchTargets));
    }
}



decomp::AnalyzeResponse BuildAnalyzerOnlyResponse(const decomp::AnalyzeRequest& request)
{
    decomp::AnalyzeResponse response;
    response.Status = "ok";
    response.Provider = "none";
    response.Summary = "LLM disabled. Showing deterministic analyzer facts only.";
    response.Confidence = request.Facts.PreLlmConfidence;
    response.Uncertainties = request.Facts.UncertainPoints;

    std::string functionName = request.Facts.QueryText.empty() ? "analyzed_function" : request.Facts.QueryText;

    if (!request.Facts.RecoveredArguments.empty())
    {
        for (const auto& argument : request.Facts.RecoveredArguments)
        {
            decomp::TypedNameConfidence item;
            item.Name = argument.Name;
            item.Type = argument.TypeHint.empty() ? "UNKNOWN_TYPE" : argument.TypeHint;
            item.Confidence = argument.Confidence;
            response.Params.push_back(item);
        }
    }
    else if (!request.Facts.Pdb.Params.empty())
    {
        for (const auto& argument : request.Facts.Pdb.Params)
        {
            decomp::TypedNameConfidence item;
            item.Name = argument.Name;
            item.Type = argument.Type.empty() ? "UNKNOWN_TYPE" : argument.Type;
            item.Confidence = argument.Confidence;
            response.Params.push_back(item);
        }
    }

    if (!request.Facts.RecoveredLocals.empty())
    {
        for (const auto& local : request.Facts.RecoveredLocals)
        {
            decomp::TypedNameConfidence item;
            item.Name = local.Name;
            item.Type = local.TypeHint.empty() ? "UNKNOWN_TYPE" : local.TypeHint;
            item.Confidence = local.Confidence;
            response.Locals.push_back(item);
        }
    }
    else if (!request.Facts.Pdb.Locals.empty())
    {
        for (const auto& local : request.Facts.Pdb.Locals)
        {
            decomp::TypedNameConfidence item;
            item.Name = local.Name;
            item.Type = local.Type.empty() ? "UNKNOWN_TYPE" : local.Type;
            item.Confidence = local.Confidence;
            response.Locals.push_back(item);
        }
    }

    std::string signature = "void";

    if (!response.Params.empty())
    {
        for (size_t index = 0; index < response.Params.size(); ++index)
        {
            if (index == 0)
            {
                signature.clear();
            }
            else
            {
                signature += ", ";
            }

            signature += response.Params[index].Type + " " + response.Params[index].Name;
        }
    }

    response.PseudoC =
        "UNKNOWN_TYPE "
        + functionName
        + "("
        + signature
        + ")\n{\n    /* LLM disabled. Review analyzer facts. */\n    return UNKNOWN_VALUE;\n}\n";
    return response;
}

std::string FormatSummaryForDisplay(const std::string& summary)
{
    std::string formatted;
    formatted.reserve(summary.size() + 16);

    for (size_t index = 0; index < summary.size();)
    {
        const char ch = summary[index];
        formatted.push_back(ch);

        if (ch == '.' || ch == '!' || ch == '?')
        {
            size_t next = index + 1;

            while (next < summary.size() && (summary[next] == ' ' || summary[next] == '\t'))
            {
                ++next;
            }

            const bool decimalLike =
                index > 0
                && next < summary.size()
                && std::isdigit(static_cast<unsigned char>(summary[index - 1])) != 0
                && std::isdigit(static_cast<unsigned char>(summary[next])) != 0;

            if (!decimalLike
                && next < summary.size()
                && summary[next] != '\r'
                && summary[next] != '\n'
                && summary[next] != '.')
            {
                formatted.push_back('\n');
            }

            index = next;
            continue;
        }

        ++index;
    }

    return formatted;
}

std::vector<std::string> g_userNoReturnOverrides;
std::vector<std::string> g_userTypeOverrides;
std::vector<std::string> g_userFieldOverrides;
std::vector<std::string> g_userRenameOverrides;
bool g_baseNoReturnOverrideCaptured = false;
std::string g_baseNoReturnOverrideEnvironment;

struct KernelBuildFacts
{
    bool Available = false;
    bool HasSystemVersion = false;
    bool HasWin32Version = false;
    bool HasKdVersion = false;
    std::string DebugClass;
    std::string Qualifier;
    uint32_t PlatformId = 0;
    uint32_t Win32Major = 0;
    uint32_t Win32Minor = 0;
    uint32_t KdMajor = 0;
    uint32_t KdMinor = 0;
    std::string ServicePack;
    uint32_t ServicePackNumber = 0;
    std::string BuildString;
    std::string BuildLab;
    std::string Fingerprint;
};

struct CachedAnalyzeArtifact
{
    std::string RequestJson;
    std::string ResponseJson;
    std::string DataModelJson;
    std::string DebugPromptDump;
    std::string Target;
    std::string Module;
    std::string Provider;
    std::string RequestId;
    std::string Timestamp;
    std::string ArtifactPath;
    KernelBuildFacts KernelBuild;
    uint64_t EntryAddress = 0;
    uint64_t EntryRva = 0;
    bool HasEntryRva = false;
    double Confidence = 0.0;
    size_t VerifierIssueCount = 0;
};

constexpr size_t kAnalyzeHistoryLimit = 8;
std::deque<CachedAnalyzeArtifact> g_analyzeHistory;
std::string g_lastRequestJson;
std::string g_lastResponseJson;
std::string g_lastDataModelJson;
std::string g_lastDebugPromptDump;

void ApplyNoReturnOverrideEnvironment(const decomp::DecompOptions& options)
{
    if (!g_baseNoReturnOverrideCaptured)
    {
        const char* existingValue = std::getenv("DECOMP_NORETURN_OVERRIDES");
        g_baseNoReturnOverrideEnvironment = existingValue == nullptr ? std::string() : std::string(existingValue);
        g_baseNoReturnOverrideCaptured = true;
    }

    if (options.ClearUserOverrides)
    {
        g_userNoReturnOverrides.clear();
        g_userTypeOverrides.clear();
        g_userFieldOverrides.clear();
        g_userRenameOverrides.clear();
    }

    for (const auto& overrideValue : options.NoReturnOverrides)
    {
        AppendUniqueString(g_userNoReturnOverrides, overrideValue);
    }

    std::vector<std::string> merged;

    if (!g_baseNoReturnOverrideEnvironment.empty())
    {
        std::string current;

        for (const char ch : g_baseNoReturnOverrideEnvironment)
        {
            if (ch == ',' || ch == ';')
            {
                AppendUniqueString(merged, current);
                current.clear();
                continue;
            }

            current.push_back(ch);
        }

        AppendUniqueString(merged, current);
    }

    for (const auto& overrideValue : g_userNoReturnOverrides)
    {
        AppendUniqueString(merged, overrideValue);
    }

    SetEnvironmentVariableA("DECOMP_NORETURN_OVERRIDES", decomp::JoinStrings(merged, ";").c_str());
}

void AddPersistentUserCorrections(const decomp::DecompOptions& options)
{
    for (const auto& value : options.TypeOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(value, '=');

        if (parts.size() == 2 && !parts[0].empty() && !parts[1].empty())
        {
            AppendUniqueString(g_userTypeOverrides, value);
        }
    }

    for (const auto& value : options.FieldOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(value, '=');

        if (parts.size() == 2 && !parts[0].empty() && !parts[1].empty())
        {
            AppendUniqueString(g_userFieldOverrides, value);
        }
    }

    for (const auto& value : options.RenameOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(value, '=');

        if (parts.size() == 2 && !parts[0].empty() && !parts[1].empty())
        {
            AppendUniqueString(g_userRenameOverrides, value);
        }
    }
}

void ReportMalformedUserCorrections(const decomp::DecompOptions& options, decomp::AnalysisFacts& facts)
{
    for (const auto& value : options.TypeOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(value, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            facts.UncertainPoints.push_back("ignored malformed /type override: " + value);
        }
    }

    for (const auto& value : options.FieldOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(value, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            facts.UncertainPoints.push_back("ignored malformed /field override: " + value);
        }
    }

    for (const auto& value : options.RenameOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(value, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            facts.UncertainPoints.push_back("ignored malformed /rename override: " + value);
        }
    }
}

void ApplyUserCorrections(const decomp::DecompOptions& options, decomp::AnalysisFacts& facts)
{
    ReportMalformedUserCorrections(options, facts);
    AddPersistentUserCorrections(options);

    for (const auto& typeOverride : g_userTypeOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(typeOverride, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            facts.UncertainPoints.push_back("ignored malformed /type override: " + typeOverride);
            continue;
        }

        decomp::TypeRecoveryHint hint;
        hint.Expression = parts[0];
        hint.Type = parts[1];
        hint.Source = "user_override";
        hint.Kind = "type_override";
        hint.Evidence = "/type:" + typeOverride;
        hint.PointerLike = decomp::ContainsInsensitive(parts[1], "*");
        hint.ArrayLike = decomp::ContainsInsensitive(parts[1], "[");
        hint.Confidence = 0.95;
        facts.TypeHints.push_back(std::move(hint));
        facts.Facts.push_back("user type override: " + parts[0] + " => " + parts[1]);
    }

    for (const auto& fieldOverride : g_userFieldOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(fieldOverride, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            facts.UncertainPoints.push_back("ignored malformed /field override: " + fieldOverride);
            continue;
        }

        decomp::TypeRecoveryHint hint;
        hint.Expression = parts[0];
        hint.Type = parts[1];
        hint.Source = "user_override";
        hint.Kind = "field_override";
        hint.Evidence = "/field:" + fieldOverride;
        hint.PointerLike = decomp::ContainsInsensitive(parts[1], "*");
        hint.Confidence = 0.95;
        facts.TypeHints.push_back(std::move(hint));
        facts.Facts.push_back("user field override: " + parts[0] + " => " + parts[1]);
    }

    for (const auto& renameOverride : g_userRenameOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(renameOverride, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            facts.UncertainPoints.push_back("ignored malformed /rename override: " + renameOverride);
            continue;
        }

        decomp::TypeRecoveryHint hint;
        hint.Expression = parts[0];
        hint.Type = parts[1];
        hint.Source = "user_override";
        hint.Kind = "rename_override";
        hint.Evidence = "/rename:" + renameOverride;
        hint.Confidence = 0.95;
        facts.TypeHints.push_back(std::move(hint));
        facts.Facts.push_back("user rename override: " + parts[0] + " => " + parts[1]);
    }
}

void ApplyResponseRenames(const decomp::DecompOptions& options, decomp::AnalyzeResponse& response)
{
    AddPersistentUserCorrections(options);

    for (const auto& renameOverride : g_userRenameOverrides)
    {
        const std::vector<std::string> parts = SplitCorrectionPair(renameOverride, '=');

        if (parts.size() != 2 || parts[0].empty() || parts[1].empty())
        {
            continue;
        }

        ReplaceIdentifier(response.PseudoC, parts[0], parts[1]);

        for (auto& param : response.Params)
        {
            if (param.Name == parts[0])
            {
                param.Name = parts[1];
            }
        }

        for (auto& local : response.Locals)
        {
            if (local.Name == parts[0])
            {
                local.Name = parts[1];
            }
        }
    }
}

std::string BuildDataModelSnapshotJson(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response)
{
    std::string json;
    json += "{\n";
    json += "  \"schema\": \"windbg-decompile-ext.data_model.v1\",\n";
    json += "  \"target\": \"" + decomp::EscapeJsonString(request.Facts.QueryText) + "\",\n";
    json += "  \"entry\": \"" + decomp::HexU64(request.Facts.EntryAddress) + "\",\n";
    json += "  \"module\": \"" + decomp::EscapeJsonString(request.Facts.Module.ModuleName) + "\",\n";
    json += "  \"blocks\": " + std::to_string(request.Facts.Blocks.size()) + ",\n";
    json += "  \"instructions\": " + std::to_string(request.Facts.Instructions.size()) + ",\n";
    json += "  \"type_hints\": " + std::to_string(request.Facts.TypeHints.size()) + ",\n";
    json += "  \"idioms\": " + std::to_string(request.Facts.Idioms.size()) + ",\n";
    json += "  \"callee_summaries\": " + std::to_string(request.Facts.CalleeSummaries.size()) + ",\n";
    json += "  \"block_value_states\": " + std::to_string(request.Facts.BlockValueStates.size()) + ",\n";
    json += "  \"evidence_graph_nodes\": " + std::to_string(request.Facts.EvidenceGraph.Nodes.size()) + ",\n";
    json += "  \"evidence_graph_edges\": " + std::to_string(request.Facts.EvidenceGraph.Edges.size()) + ",\n";
    json += "  \"observed_arguments\": " + std::to_string(request.Facts.ObservedBehavior.ArgumentSamples.size()) + ",\n";
    json += "  \"memory_hotspots\": " + std::to_string(request.Facts.ObservedBehavior.MemoryHotspots.size()) + ",\n";
    json += "  \"ttd_queries\": " + std::to_string(request.Facts.ObservedBehavior.TtdQueries.size()) + ",\n";
    json += "  \"uncertainties\": " + std::to_string(response.Uncertainties.size()) + ",\n";
    json += "  \"request_json\": ";
    json += decomp::SerializeAnalyzeRequest(request, true);
    json += ",\n  \"response_json\": ";
    json += decomp::SerializeAnalyzeResponse(response, true);
    json += "\n}\n";
    return json;
}

std::string FormatWin32Error(DWORD error)
{
    return "win32 error " + std::to_string(error);
}

std::string ReadEnvironmentVariableValue(const char* name)
{
    const DWORD size = GetEnvironmentVariableA(name, nullptr, 0);

    if (size == 0)
    {
        return std::string();
    }

    std::string value(static_cast<size_t>(size), '\0');
    GetEnvironmentVariableA(name, value.data(), size);

    if (!value.empty() && value.back() == '\0')
    {
        value.pop_back();
    }

    return value;
}

bool IsPathSeparator(char ch)
{
    return ch == '\\' || ch == '/';
}

std::string TrimTrailingPathSeparators(std::string path)
{
    while (path.size() > 3 && IsPathSeparator(path.back()))
    {
        path.pop_back();
    }

    return path;
}

std::string JoinPath(const std::string& left, const std::string& right)
{
    if (left.empty())
    {
        return right;
    }

    if (right.empty())
    {
        return left;
    }

    if (IsPathSeparator(left.back()))
    {
        return left + right;
    }

    return left + "\\" + right;
}

std::string ExpandArtifactPath(const std::string& rawPath)
{
    std::string expanded = decomp::TrimCopy(rawPath);

    if (expanded.empty())
    {
        return expanded;
    }

    if (expanded == "~" || decomp::StartsWithInsensitive(expanded, "~/") || decomp::StartsWithInsensitive(expanded, "~\\"))
    {
        const std::string home = ReadEnvironmentVariableValue("USERPROFILE");

        if (!home.empty())
        {
            expanded = expanded.size() == 1 ? home : home + expanded.substr(1);
        }
    }

    const DWORD required = ExpandEnvironmentStringsA(expanded.c_str(), nullptr, 0);

    if (required == 0)
    {
        return expanded;
    }

    std::string buffer(static_cast<size_t>(required), '\0');

    if (ExpandEnvironmentStringsA(expanded.c_str(), buffer.data(), required) == 0)
    {
        return expanded;
    }

    if (!buffer.empty() && buffer.back() == '\0')
    {
        buffer.pop_back();
    }

    return buffer;
}

std::string GetParentPath(const std::string& path)
{
    const size_t slash = path.find_last_of("\\/");

    if (slash == std::string::npos)
    {
        return std::string();
    }

    if (slash == 2 && path.size() >= 3 && path[1] == ':')
    {
        return path.substr(0, 3);
    }

    return path.substr(0, slash);
}

size_t FindDirectoryCreationStart(const std::string& path)
{
    if (path.size() >= 3 && path[1] == ':' && IsPathSeparator(path[2]))
    {
        return 3;
    }

    if (path.size() >= 2 && IsPathSeparator(path[0]) && IsPathSeparator(path[1]))
    {
        const size_t serverEnd = path.find_first_of("\\/", 2);

        if (serverEnd == std::string::npos)
        {
            return path.size();
        }

        const size_t shareEnd = path.find_first_of("\\/", serverEnd + 1);

        if (shareEnd == std::string::npos)
        {
            return path.size();
        }

        return shareEnd + 1;
    }

    return 0;
}

bool EnsureDirectoryTree(const std::string& rawPath, std::string& error)
{
    std::string path = TrimTrailingPathSeparators(rawPath);

    if (path.empty())
    {
        return true;
    }

    std::replace(path.begin(), path.end(), '/', '\\');

    const DWORD attributes = GetFileAttributesA(path.c_str());

    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            return true;
        }

        error = "path exists but is not a directory: " + path;
        return false;
    }

    const size_t start = FindDirectoryCreationStart(path);

    for (size_t index = start; index <= path.size(); ++index)
    {
        if (index != path.size() && !IsPathSeparator(path[index]))
        {
            continue;
        }

        const std::string part = path.substr(0, index);

        if (part.empty())
        {
            continue;
        }

        const DWORD partAttributes = GetFileAttributesA(part.c_str());

        if (partAttributes != INVALID_FILE_ATTRIBUTES)
        {
            if ((partAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            {
                error = "path exists but is not a directory: " + part;
                return false;
            }

            continue;
        }

        if (CreateDirectoryA(part.c_str(), nullptr) == FALSE)
        {
            const DWORD createError = GetLastError();

            if (createError != ERROR_ALREADY_EXISTS)
            {
                error = "failed to create directory " + part + ": " + FormatWin32Error(createError);
                return false;
            }
        }
    }

    return true;
}

bool WriteTextFileAtomic(const std::string& path, const std::string& text, std::string& error)
{
    const std::string parent = GetParentPath(path);

    if (!parent.empty() && !EnsureDirectoryTree(parent, error))
    {
        return false;
    }

    const std::string tempPath = path + ".tmp." + decomp::MakeRequestId();

    {
        std::ofstream stream(tempPath, std::ios::binary | std::ios::trunc);

        if (!stream)
        {
            error = "failed to open temp artifact for write: " + tempPath;
            return false;
        }

        stream.write(text.data(), static_cast<std::streamsize>(text.size()));
        stream.close();

        if (!stream)
        {
            DeleteFileA(tempPath.c_str());
            error = "failed to write temp artifact: " + tempPath;
            return false;
        }
    }

    if (MoveFileExA(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE)
    {
        const DWORD moveError = GetLastError();
        DeleteFileA(tempPath.c_str());
        error = "failed to replace artifact " + path + ": " + FormatWin32Error(moveError);
        return false;
    }

    return true;
}

bool ReadTextFile(const std::string& path, std::string& text, std::string& error)
{
    std::ifstream stream(path, std::ios::binary);

    if (!stream)
    {
        error = "failed to open artifact: " + path;
        return false;
    }

    std::ostringstream buffer;
    buffer << stream.rdbuf();
    text = buffer.str();
    return true;
}

std::string SanitizeFileNameComponent(const std::string& value)
{
    std::string sanitized;
    sanitized.reserve(value.size());

    for (const char ch : value)
    {
        const unsigned char byte = static_cast<unsigned char>(ch);
        const bool invalid = byte < 0x20
            || ch == '<'
            || ch == '>'
            || ch == ':'
            || ch == '"'
            || ch == '/'
            || ch == '\\'
            || ch == '|'
            || ch == '?'
            || ch == '*';

        sanitized.push_back(invalid ? '_' : ch);
    }

    sanitized = decomp::TrimCopy(sanitized);

    if (sanitized.empty())
    {
        sanitized = "decomp";
    }

    if (sanitized.size() > 96)
    {
        sanitized.resize(96);
    }

    return sanitized;
}

std::string GetCurrentExtensionModulePath()
{
    HMODULE module = nullptr;

    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&GetCurrentExtensionModulePath),
            &module) == FALSE)
    {
        return std::string();
    }

    std::vector<char> modulePath(MAX_PATH);

    while (modulePath.size() <= 32768)
    {
        const DWORD length = GetModuleFileNameA(module, modulePath.data(), static_cast<DWORD>(modulePath.size()));

        if (length == 0)
        {
            return std::string();
        }

        if (static_cast<size_t>(length) < modulePath.size() - 1)
        {
            return std::string(modulePath.data(), static_cast<size_t>(length));
        }

        modulePath.resize(modulePath.size() * 2);
    }

    return std::string();
}

std::string BuildDefaultArtifactDirectory()
{
    const std::string modulePath = GetCurrentExtensionModulePath();

    if (!modulePath.empty())
    {
        const std::string directory = GetParentPath(modulePath);

        if (!directory.empty())
        {
            return JoinPath(directory, "artifact");
        }
    }

    return "artifact";
}

std::string BuildArtifactBuildKey(const KernelBuildFacts& facts)
{
    std::vector<std::string> parts;

    if (facts.HasWin32Version)
    {
        parts.push_back("win32_" + std::to_string(facts.Win32Major) + "_" + std::to_string(facts.Win32Minor));
    }

    if (facts.HasKdVersion)
    {
        parts.push_back("kd_" + std::to_string(facts.KdMajor) + "_" + std::to_string(facts.KdMinor));
    }

    if (!facts.BuildString.empty())
    {
        parts.push_back("build_" + facts.BuildString);
    }
    else if (!facts.BuildLab.empty())
    {
        parts.push_back("buildlab_" + facts.BuildLab);
    }
    else if (!facts.Fingerprint.empty())
    {
        parts.push_back(facts.Fingerprint);
    }
    else
    {
        parts.push_back("unknown_build");
    }

    return SanitizeFileNameComponent(decomp::JoinStrings(parts, "_"));
}

std::string BuildDefaultArtifactPath(const CachedAnalyzeArtifact& artifact)
{
    const std::string buildKey = BuildArtifactBuildKey(artifact.KernelBuild);
    const std::string module = SanitizeFileNameComponent(artifact.Module.empty() ? "unknown_module" : artifact.Module);
    const uint64_t stableOffset = artifact.HasEntryRva ? artifact.EntryRva : artifact.EntryAddress;

    return JoinPath(
        JoinPath(BuildDefaultArtifactDirectory(), buildKey),
        module + "_" + decomp::HexU64(stableOffset) + ".decomp.json");
}

bool TryReadNullTerminatedAsciiString(
    IDebugDataSpaces4* dataSpaces,
    uint64_t address,
    ULONG size,
    std::string& text)
{
    std::vector<uint8_t> bytes;

    if (!ReadVirtualPrefix(dataSpaces, address, size, bytes))
    {
        return false;
    }

    std::string candidate;

    for (const uint8_t byte : bytes)
    {
        if (byte == 0)
        {
            break;
        }

        if (byte < 0x20 || byte > 0x7E)
        {
            return false;
        }

        candidate.push_back(static_cast<char>(byte));
    }

    if (candidate.empty())
    {
        return false;
    }

    text = candidate;
    return true;
}

bool TryReadNtBuildLab(IDebugDataSpaces4* dataSpaces, std::string& buildLab)
{
    if (dataSpaces == nullptr)
    {
        return false;
    }

    ULONG64 address = 0;
    ULONG dataSize = 0;

    if (FAILED(dataSpaces->ReadDebuggerData(DEBUG_DATA_NtBuildLabAddr, &address, sizeof(address), &dataSize))
        || address == 0)
    {
        return false;
    }

    return TryReadNullTerminatedAsciiString(dataSpaces, address, 256, buildLab);
}

std::string BuildKernelBuildFingerprint(const KernelBuildFacts& facts)
{
    std::vector<std::string> parts;

    if (facts.HasWin32Version)
    {
        parts.push_back("win32=" + std::to_string(facts.Win32Major) + "." + std::to_string(facts.Win32Minor));
    }

    if (facts.HasKdVersion)
    {
        parts.push_back("kd=" + std::to_string(facts.KdMajor) + "." + std::to_string(facts.KdMinor));
    }

    if (!facts.BuildString.empty())
    {
        parts.push_back("build_string=" + facts.BuildString);
    }

    if (!facts.BuildLab.empty())
    {
        parts.push_back("build_lab=" + facts.BuildLab);
    }

    return decomp::JoinStrings(parts, ";");
}

KernelBuildFacts CollectKernelBuildFacts(
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugDataSpaces4* dataSpaces)
{
    KernelBuildFacts facts;
    const decomp::SessionPolicyFacts session = BuildSessionPolicyFacts(control);
    facts.DebugClass = session.DebugClass;
    facts.Qualifier = session.Qualifier;

    if (control != nullptr)
    {
        ULONG platformId = 0;
        ULONG kdMajor = 0;
        ULONG kdMinor = 0;
        ULONG servicePackUsed = 0;
        ULONG servicePackNumber = 0;
        ULONG buildStringUsed = 0;
        std::array<char, 128> servicePack = {};
        std::array<char, 256> buildString = {};

        if (SUCCEEDED(control->GetSystemVersion(
                &platformId,
                &kdMajor,
                &kdMinor,
                servicePack.data(),
                static_cast<ULONG>(servicePack.size()),
                &servicePackUsed,
                &servicePackNumber,
                buildString.data(),
                static_cast<ULONG>(buildString.size()),
                &buildStringUsed)))
        {
            facts.HasSystemVersion = true;
            facts.HasKdVersion = true;
            facts.PlatformId = platformId;
            facts.KdMajor = kdMajor;
            facts.KdMinor = kdMinor;
            facts.ServicePack = servicePack.data();
            facts.ServicePackNumber = servicePackNumber;
            facts.BuildString = buildString.data();
        }
    }

    if (control4 != nullptr)
    {
        ULONG platformId = 0;
        ULONG win32Major = 0;
        ULONG win32Minor = 0;
        ULONG kdMajor = 0;
        ULONG kdMinor = 0;

        if (SUCCEEDED(control4->GetSystemVersionValues(&platformId, &win32Major, &win32Minor, &kdMajor, &kdMinor)))
        {
            facts.HasWin32Version = true;
            facts.HasKdVersion = true;
            facts.PlatformId = platformId;
            facts.Win32Major = win32Major;
            facts.Win32Minor = win32Minor;
            facts.KdMajor = kdMajor;
            facts.KdMinor = kdMinor;
        }
    }

    TryReadNtBuildLab(dataSpaces, facts.BuildLab);
    facts.Fingerprint = BuildKernelBuildFingerprint(facts);
    facts.Available = !facts.Fingerprint.empty();
    return facts;
}

decomp::JsonValue KernelBuildFactsToJson(const KernelBuildFacts& facts)
{
    decomp::JsonValue object = decomp::JsonValue::MakeObject();
    object.Set("available", decomp::JsonValue::MakeBoolean(facts.Available));
    object.Set("debug_class", decomp::JsonValue::MakeString(facts.DebugClass));
    object.Set("qualifier", decomp::JsonValue::MakeString(facts.Qualifier));
    object.Set("has_system_version", decomp::JsonValue::MakeBoolean(facts.HasSystemVersion));
    object.Set("has_win32_version", decomp::JsonValue::MakeBoolean(facts.HasWin32Version));
    object.Set("has_kd_version", decomp::JsonValue::MakeBoolean(facts.HasKdVersion));
    object.Set("platform_id", decomp::JsonValue::MakeNumber(static_cast<double>(facts.PlatformId)));
    object.Set("win32_major", decomp::JsonValue::MakeNumber(static_cast<double>(facts.Win32Major)));
    object.Set("win32_minor", decomp::JsonValue::MakeNumber(static_cast<double>(facts.Win32Minor)));
    object.Set("kd_major", decomp::JsonValue::MakeNumber(static_cast<double>(facts.KdMajor)));
    object.Set("kd_minor", decomp::JsonValue::MakeNumber(static_cast<double>(facts.KdMinor)));
    object.Set("service_pack", decomp::JsonValue::MakeString(facts.ServicePack));
    object.Set("service_pack_number", decomp::JsonValue::MakeNumber(static_cast<double>(facts.ServicePackNumber)));
    object.Set("build_string", decomp::JsonValue::MakeString(facts.BuildString));
    object.Set("build_lab", decomp::JsonValue::MakeString(facts.BuildLab));
    object.Set("fingerprint", decomp::JsonValue::MakeString(facts.Fingerprint));
    return object;
}

bool TryGetJsonStringValue(const decomp::JsonValue& object, const std::string& key, std::string& value)
{
    const decomp::JsonValue* member = object.Find(key);

    if (member == nullptr || !member->IsString())
    {
        return false;
    }

    value = member->GetString();
    return true;
}

bool TryGetJsonBoolValue(const decomp::JsonValue& object, const std::string& key, bool& value)
{
    const decomp::JsonValue* member = object.Find(key);

    if (member == nullptr || !member->IsBoolean())
    {
        return false;
    }

    value = member->GetBoolean();
    return true;
}

bool TryGetJsonU32Value(const decomp::JsonValue& object, const std::string& key, uint32_t& value)
{
    const decomp::JsonValue* member = object.Find(key);

    if (member == nullptr
        || !member->IsNumber()
        || member->GetNumber() < 0.0
        || member->GetNumber() > 4294967295.0)
    {
        return false;
    }

    value = static_cast<uint32_t>(member->GetNumber());
    return true;
}

bool ParseKernelBuildFacts(const decomp::JsonValue& value, KernelBuildFacts& facts)
{
    if (!value.IsObject())
    {
        return false;
    }

    TryGetJsonBoolValue(value, "available", facts.Available);
    TryGetJsonStringValue(value, "debug_class", facts.DebugClass);
    TryGetJsonStringValue(value, "qualifier", facts.Qualifier);
    TryGetJsonBoolValue(value, "has_system_version", facts.HasSystemVersion);
    TryGetJsonBoolValue(value, "has_win32_version", facts.HasWin32Version);
    TryGetJsonBoolValue(value, "has_kd_version", facts.HasKdVersion);
    TryGetJsonU32Value(value, "platform_id", facts.PlatformId);
    TryGetJsonU32Value(value, "win32_major", facts.Win32Major);
    TryGetJsonU32Value(value, "win32_minor", facts.Win32Minor);
    TryGetJsonU32Value(value, "kd_major", facts.KdMajor);
    TryGetJsonU32Value(value, "kd_minor", facts.KdMinor);
    TryGetJsonStringValue(value, "service_pack", facts.ServicePack);
    TryGetJsonU32Value(value, "service_pack_number", facts.ServicePackNumber);
    TryGetJsonStringValue(value, "build_string", facts.BuildString);
    TryGetJsonStringValue(value, "build_lab", facts.BuildLab);
    TryGetJsonStringValue(value, "fingerprint", facts.Fingerprint);

    if (facts.Fingerprint.empty())
    {
        facts.Fingerprint = BuildKernelBuildFingerprint(facts);
    }

    facts.Available = facts.Available || !facts.Fingerprint.empty();
    return true;
}

bool ExtractJsonMemberText(
    const decomp::JsonValue& object,
    const std::string& primaryKey,
    const std::string& legacyKey,
    std::string& text,
    std::string& error)
{
    const decomp::JsonValue* member = object.Find(primaryKey);

    if (member == nullptr && !legacyKey.empty())
    {
        member = object.Find(legacyKey);
    }

    if (member == nullptr)
    {
        error = "artifact is missing " + primaryKey;
        return false;
    }

    if (member->IsString())
    {
        text = member->GetString();
        return true;
    }

    text = decomp::SerializeJson(*member, true);
    return true;
}

decomp::JsonValue ParseJsonOrString(const std::string& text)
{
    const decomp::JsonParseResult parsed = decomp::ParseJson(text);

    if (parsed.Success)
    {
        return parsed.Value;
    }

    return decomp::JsonValue::MakeString(text);
}

std::string BuildPersistentArtifactJson(const CachedAnalyzeArtifact& artifact)
{
    decomp::JsonValue object = decomp::JsonValue::MakeObject();
    object.Set("schema", decomp::JsonValue::MakeString("windbg-decompile-ext.decomp_artifact.v1"));
    object.Set("kind", decomp::JsonValue::MakeString("analyze_result"));
    object.Set("saved_at", decomp::JsonValue::MakeString(artifact.Timestamp));
    object.Set("target", decomp::JsonValue::MakeString(artifact.Target));
    object.Set("module", decomp::JsonValue::MakeString(artifact.Module));
    object.Set("entry", decomp::JsonValue::MakeString(decomp::HexU64(artifact.EntryAddress)));
    object.Set("rva", decomp::JsonValue::MakeString(decomp::HexU64(artifact.EntryRva)));
    object.Set("has_rva", decomp::JsonValue::MakeBoolean(artifact.HasEntryRva));
    object.Set("provider", decomp::JsonValue::MakeString(artifact.Provider));
    object.Set("request_id", decomp::JsonValue::MakeString(artifact.RequestId));
    object.Set("confidence", decomp::JsonValue::MakeNumber(artifact.Confidence));
    object.Set("verifier_issue_count", decomp::JsonValue::MakeNumber(static_cast<double>(artifact.VerifierIssueCount)));
    object.Set("kernel_build", KernelBuildFactsToJson(artifact.KernelBuild));
    object.Set("request", ParseJsonOrString(artifact.RequestJson));
    object.Set("response", ParseJsonOrString(artifact.ResponseJson));
    object.Set("data_model", ParseJsonOrString(artifact.DataModelJson));
    object.Set("debug_prompt", decomp::JsonValue::MakeString(artifact.DebugPromptDump));
    return decomp::SerializeJson(object, true) + "\n";
}

bool SaveCachedAnalyzeArtifact(
    const CachedAnalyzeArtifact& artifact,
    const std::string& rawPath,
    std::string& actualPath,
    std::string& error)
{
    actualPath = rawPath.empty() ? BuildDefaultArtifactPath(artifact) : ExpandArtifactPath(rawPath);

    if (actualPath.empty())
    {
        error = "artifact path is empty";
        return false;
    }

    const std::string json = BuildPersistentArtifactJson(artifact);
    return WriteTextFileAtomic(actualPath, json, error);
}

bool LoadCachedAnalyzeArtifact(
    const std::string& rawPath,
    CachedAnalyzeArtifact& artifact,
    std::string& error)
{
    const std::string path = ExpandArtifactPath(rawPath);
    std::string text;

    if (!ReadTextFile(path, text, error))
    {
        return false;
    }

    const decomp::JsonParseResult parsed = decomp::ParseJson(text);

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        error = parsed.Error.empty() ? "artifact must be a JSON object" : parsed.Error;
        return false;
    }

    std::string schema;
    TryGetJsonStringValue(parsed.Value, "schema", schema);

    if (schema != "windbg-decompile-ext.decomp_artifact.v1")
    {
        error = "unsupported artifact schema: " + (schema.empty() ? std::string("<missing>") : schema);
        return false;
    }

    if (!ExtractJsonMemberText(parsed.Value, "request", "request_json", artifact.RequestJson, error)
        || !ExtractJsonMemberText(parsed.Value, "response", "response_json", artifact.ResponseJson, error))
    {
        return false;
    }

    const decomp::JsonValue* dataModel = parsed.Value.Find("data_model");

    if (dataModel == nullptr)
    {
        dataModel = parsed.Value.Find("data_model_json");
    }

    if (dataModel != nullptr)
    {
        artifact.DataModelJson = dataModel->IsString() ? dataModel->GetString() : decomp::SerializeJson(*dataModel, true);
    }

    TryGetJsonStringValue(parsed.Value, "debug_prompt", artifact.DebugPromptDump);

    if (artifact.DebugPromptDump.empty())
    {
        TryGetJsonStringValue(parsed.Value, "debug_prompt_dump", artifact.DebugPromptDump);
    }

    const decomp::JsonValue* kernelBuild = parsed.Value.Find("kernel_build");

    if (kernelBuild != nullptr)
    {
        ParseKernelBuildFacts(*kernelBuild, artifact.KernelBuild);
    }

    decomp::AnalyzeRequest request;
    decomp::AnalyzeResponse response;

    if (!decomp::ParseAnalyzeRequest(artifact.RequestJson, request, error))
    {
        error = "failed to parse artifact request: " + error;
        return false;
    }

    if (!decomp::ParseAnalyzeResponse(artifact.ResponseJson, response, error))
    {
        error = "failed to parse artifact response: " + error;
        return false;
    }

    if (artifact.DataModelJson.empty())
    {
        artifact.DataModelJson = BuildDataModelSnapshotJson(request, response);
    }

    if (artifact.DebugPromptDump.empty())
    {
        artifact.DebugPromptDump = decomp::BuildDebugPromptDump(request);
    }

    TryGetJsonStringValue(parsed.Value, "saved_at", artifact.Timestamp);
    TryGetJsonStringValue(parsed.Value, "target", artifact.Target);
    TryGetJsonStringValue(parsed.Value, "module", artifact.Module);
    TryGetJsonStringValue(parsed.Value, "provider", artifact.Provider);
    TryGetJsonStringValue(parsed.Value, "request_id", artifact.RequestId);
    TryGetJsonBoolValue(parsed.Value, "has_rva", artifact.HasEntryRva);

    artifact.ArtifactPath = path;
    artifact.Target = artifact.Target.empty() ? request.Facts.QueryText : artifact.Target;
    artifact.Module = artifact.Module.empty() ? request.Facts.Module.ModuleName : artifact.Module;
    artifact.Provider = artifact.Provider.empty() ? response.Provider : artifact.Provider;
    artifact.RequestId = artifact.RequestId.empty() ? request.RequestId : artifact.RequestId;
    artifact.EntryAddress = request.Facts.EntryAddress;
    artifact.EntryRva = request.Facts.Rva;
    artifact.HasEntryRva = artifact.HasEntryRva
        || (request.Facts.Module.Base != 0 && request.Facts.EntryAddress >= request.Facts.Module.Base);
    artifact.Confidence = response.Verifier.AdjustedConfidence;
    artifact.VerifierIssueCount = response.Verifier.Issues.size();
    return true;
}

std::string BuildKernelBuildDisplay(const KernelBuildFacts& facts)
{
    if (!facts.Fingerprint.empty())
    {
        return facts.Fingerprint;
    }

    return "unavailable";
}

bool EqualInsensitiveString(const std::string& left, const std::string& right)
{
    return decomp::ToLowerAscii(left) == decomp::ToLowerAscii(right);
}

bool KernelBuildsAreCompatible(const KernelBuildFacts& saved, const KernelBuildFacts& current)
{
    bool hasCommonIdentity = false;

    if (!saved.BuildLab.empty() && !current.BuildLab.empty())
    {
        if (!EqualInsensitiveString(saved.BuildLab, current.BuildLab))
        {
            return false;
        }

        hasCommonIdentity = true;
    }

    if (!saved.BuildString.empty() && !current.BuildString.empty())
    {
        if (!EqualInsensitiveString(saved.BuildString, current.BuildString))
        {
            return false;
        }

        hasCommonIdentity = true;
    }

    if (saved.HasKdVersion && current.HasKdVersion)
    {
        if (saved.KdMajor != current.KdMajor || saved.KdMinor != current.KdMinor)
        {
            return false;
        }

        hasCommonIdentity = true;
    }

    if (saved.HasWin32Version && current.HasWin32Version)
    {
        if (saved.Win32Major != current.Win32Major || saved.Win32Minor != current.Win32Minor)
        {
            return false;
        }

        hasCommonIdentity = true;
    }

    return hasCommonIdentity;
}

bool ValidateLoadedArtifactKernelBuild(
    const CachedAnalyzeArtifact& artifact,
    const KernelBuildFacts& current,
    std::string& warning,
    std::string& error)
{
    if (artifact.KernelBuild.Fingerprint.empty())
    {
        error = "saved artifact has no kernel_build fingerprint";
        return false;
    }

    if (current.Fingerprint.empty())
    {
        error = "current session kernel_build fingerprint is unavailable; saved="
            + BuildKernelBuildDisplay(artifact.KernelBuild);
        return false;
    }

    if (EqualInsensitiveString(artifact.KernelBuild.Fingerprint, current.Fingerprint))
    {
        return true;
    }

    if (KernelBuildsAreCompatible(artifact.KernelBuild, current))
    {
        warning = "kernel_build matched by common build values, but optional fingerprint fields differ";
        return true;
    }

    error = "kernel_build mismatch: saved="
        + BuildKernelBuildDisplay(artifact.KernelBuild)
        + " current="
        + BuildKernelBuildDisplay(current);
    return false;
}

std::string BuildCacheTimestamp()
{
    const std::time_t now = std::time(nullptr);
    std::tm localTime = {};
    std::array<char, 32> buffer = {};

    if (localtime_s(&localTime, &now) != 0)
    {
        return "unknown";
    }

    std::snprintf(
        buffer.data(),
        buffer.size(),
        "%04d-%02d-%02d %02d:%02d:%02d",
        localTime.tm_year + 1900,
        localTime.tm_mon + 1,
        localTime.tm_mday,
        localTime.tm_hour,
        localTime.tm_min,
        localTime.tm_sec);
    return buffer.data();
}

void RememberCachedAnalyzeArtifact(CachedAnalyzeArtifact artifact)
{
    g_lastRequestJson = artifact.RequestJson;
    g_lastResponseJson = artifact.ResponseJson;
    g_lastDataModelJson = artifact.DataModelJson;
    g_lastDebugPromptDump = artifact.DebugPromptDump;

    g_analyzeHistory.push_front(std::move(artifact));

    while (g_analyzeHistory.size() > kAnalyzeHistoryLimit)
    {
        g_analyzeHistory.pop_back();
    }
}

void StoreCachedAnalyzeResult(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const KernelBuildFacts& kernelBuild)
{
    CachedAnalyzeArtifact artifact;
    artifact.RequestJson = decomp::SerializeAnalyzeRequest(request, true);
    artifact.ResponseJson = decomp::SerializeAnalyzeResponse(response, true);
    artifact.DataModelJson = BuildDataModelSnapshotJson(request, response);
    artifact.DebugPromptDump = decomp::BuildDebugPromptDump(request);
    artifact.Target = request.Facts.QueryText;
    artifact.Module = request.Facts.Module.ModuleName;
    artifact.Provider = response.Provider;
    artifact.RequestId = request.RequestId;
    artifact.Timestamp = BuildCacheTimestamp();
    artifact.EntryAddress = request.Facts.EntryAddress;
    artifact.EntryRva = request.Facts.Rva;
    artifact.HasEntryRva = request.Facts.Module.Base != 0 && request.Facts.EntryAddress >= request.Facts.Module.Base;
    artifact.Confidence = response.Verifier.AdjustedConfidence;
    artifact.VerifierIssueCount = response.Verifier.Issues.size();
    artifact.KernelBuild = kernelBuild;

    RememberCachedAnalyzeArtifact(std::move(artifact));
}

const CachedAnalyzeArtifact* GetCachedAnalyzeArtifact(uint32_t index)
{
    if (index == 0 || index > g_analyzeHistory.size())
    {
        return nullptr;
    }

    return &g_analyzeHistory[static_cast<size_t>(index - 1)];
}

void PrintAnalyzeHistory(IDebugControl* control, IDebugControl4* control4)
{
    if (g_analyzeHistory.empty())
    {
        OutputLine(control, control4, "history: no cached !decomp results\n");
        return;
    }

    OutputLine(control, control4, "history:\n");
    OutputLine(control, control4, "index  timestamp            entry       confidence  issues  provider  target  request_id\n");

    for (size_t index = 0; index < g_analyzeHistory.size(); ++index)
    {
        const CachedAnalyzeArtifact& artifact = g_analyzeHistory[index];
        OutputLine(
            control,
            control4,
            "%5llu  %-19s  %-10s  %.2f        %5llu  %s  %s  %s\n",
            static_cast<unsigned long long>(index + 1),
            artifact.Timestamp.c_str(),
            decomp::HexU64(artifact.EntryAddress).c_str(),
            artifact.Confidence,
            static_cast<unsigned long long>(artifact.VerifierIssueCount),
            artifact.Provider.c_str(),
            artifact.Target.c_str(),
            artifact.RequestId.c_str());
    }
}

void PrintUsage(IDebugControl* control, IDebugControl4* control4)
{
    OutputLine(control, control4, "usage: !decomp [/verbose] [/doctor] [/history] [/view:brief|explain|json|facts|prompt|data|window|analyzer|plan] [/last[:N]:explain|facts|json|data|prompt] [/limit:deep|huge|N] [/timeout:N] <addr|module!symbol>\n");
    OutputLine(control, control4, "view : !decomp /view:window opens cached analyzed functions when no target is supplied; /view:window /history does the same explicitly\n");
    OutputLine(control, control4, "fix  : /fix:noreturn:name /fix:type:expr=TYPE /fix:field:expr=TYPE /fix:rename:old=new /fix:clear\n");
    OutputLine(control, control4, "file : successful LLM results are saved automatically beside decomp.dll under artifact\\ and replayed automatically for the same target and kernel_build\n");
    OutputLine(control, control4, "compat: legacy switches such as /brief, /json, /facts-only, /debug-prompt, /data-model, /last-json, /deep, and /noreturn: still work\n");
    OutputLine(control, control4, "cfg  : decomp.llm.json beside decomp.dll\n");
    OutputLine(control, control4, "env  : DECOMP_LLM_*, OPENAI_API_KEY may override config values\n");
}

std::string YesNo(bool value)
{
    return value ? "yes" : "no";
}

std::string SanitizeEndpointForDisplay(const std::string& endpoint)
{
    std::string sanitized = endpoint;
    const size_t scheme = sanitized.find("://");
    const size_t authorityStart = scheme == std::string::npos ? 0 : scheme + 3;
    const size_t at = sanitized.find('@', authorityStart);
    const size_t slash = sanitized.find('/', authorityStart);

    if (at != std::string::npos && (slash == std::string::npos || at < slash))
    {
        sanitized = sanitized.substr(0, authorityStart) + "<credentials-redacted>" + sanitized.substr(at);
    }

    const size_t query = sanitized.find('?');

    if (query != std::string::npos)
    {
        sanitized = sanitized.substr(0, query) + "?<redacted>";
    }

    return sanitized;
}

std::string ReadEnvironmentVariableForDoctor(const char* name)
{
    const DWORD size = GetEnvironmentVariableA(name, nullptr, 0);

    if (size == 0)
    {
        return std::string();
    }

    std::string value(static_cast<size_t>(size), '\0');
    GetEnvironmentVariableA(name, value.data(), size);

    if (!value.empty() && value.back() == '\0')
    {
        value.pop_back();
    }

    return value;
}

std::string ProcessorTypeToString(ULONG processor)
{
    switch (processor)
    {
    case IMAGE_FILE_MACHINE_AMD64:
        return "x64";
    case IMAGE_FILE_MACHINE_I386:
        return "x86";
    case IMAGE_FILE_MACHINE_ARM64:
        return "arm64";
    default:
        return "unknown(" + std::to_string(processor) + ")";
    }
}

void PrintDoctorOutput(const DebugApi& api, const decomp::DecompOptions& options)
{
    std::string error;
    decomp::LlmClientConfig config;
    const std::string configPath = decomp::BuildDefaultLlmConfigPath();
    const bool configPresent = decomp::PathExistsAsFile(configPath);
    const bool configLoaded = decomp::LoadLlmClientConfig(config, error, false);
    const bool chatGptProvider = configLoaded && decomp::IsChatGptProviderConfig(config);
    const bool dmlAware = AreOutputCallbacksDmlAware(api.Advanced2.Get());
    const decomp::SessionPolicyFacts session = BuildSessionPolicyFacts(api.Control.Get());
    ULONG processor = 0;
    const bool processorKnown = api.Control.Get() != nullptr
        && SUCCEEDED(api.Control->GetEffectiveProcessorType(&processor));

    OutputLine(api.Control.Get(), api.Control4.Get(), "doctor:\n");
    OutputLine(api.Control.Get(), api.Control4.Get(), "config_path : %s\n", configPath.c_str());
    OutputLine(api.Control.Get(), api.Control4.Get(), "config_file : %s\n", configPresent ? "present" : "missing (DECOMP_DOCTOR_CONFIG_MISSING)");

    if (!configLoaded)
    {
        OutputLine(api.Control.Get(), api.Control4.Get(), "config_load : error (DECOMP_DOCTOR_CONFIG_INVALID) %s\n", error.c_str());
    }
    else
    {
        OutputLine(api.Control.Get(), api.Control4.Get(), "config_load : ok\n");
        OutputLine(api.Control.Get(), api.Control4.Get(), "provider    : %s\n", config.Provider.c_str());
        OutputLine(api.Control.Get(), api.Control4.Get(), "model       : %s\n", config.Model.c_str());
        const std::string endpointDisplay = config.Endpoint.empty() ? std::string("<mock>") : SanitizeEndpointForDisplay(config.Endpoint);
        OutputLine(api.Control.Get(), api.Control4.Get(), "endpoint    : %s\n", endpointDisplay.c_str());
        OutputLine(api.Control.Get(), api.Control4.Get(), "timeout_ms  : %u\n", config.TimeoutMs);
        OutputLine(api.Control.Get(), api.Control4.Get(), "tokens      : max=%u chunk=%u merge=%u\n", config.MaxCompletionTokens, config.ChunkCompletionTokens, config.MergeCompletionTokens);
        OutputLine(
            api.Control.Get(),
            api.Control4.Get(),
            "chunking    : force=%s trigger_instructions=%u trigger_blocks=%u block_limit=%u count_limit=%u\n",
            YesNo(config.ForceChunked).c_str(),
            config.ChunkTriggerInstructions,
            config.ChunkTriggerBlocks,
            config.ChunkBlockLimit,
            config.ChunkCountLimit);

        if (chatGptProvider)
        {
            const std::string authPath = config.ChatGptAuthFile.empty()
                ? decomp::BuildDefaultChatGptAuthFilePathForConfig()
                : config.ChatGptAuthFile;
            const bool envToken = !ReadEnvironmentVariableForDoctor("DECOMP_LLM_CHATGPT_ACCESS_TOKEN").empty()
                || !ReadEnvironmentVariableForDoctor("DECOMP_LLM_CODEX_ACCESS_TOKEN").empty()
                || !ReadEnvironmentVariableForDoctor("KERNFORGE_CODEX_ACCESS_TOKEN").empty();

            OutputLine(api.Control.Get(), api.Control4.Get(), "chatgpt_auth_file : %s\n", authPath.empty() ? "<unavailable>" : authPath.c_str());
            OutputLine(api.Control.Get(), api.Control4.Get(), "chatgpt_auth_seen : access_token=%s env_token=%s auth_file=%s\n", YesNo(!config.ApiKey.empty()).c_str(), YesNo(envToken).c_str(), YesNo(decomp::PathExistsAsFile(authPath)).c_str());
        }
        else
        {
            const bool apiKeyEnv = !ReadEnvironmentVariableForDoctor("DECOMP_LLM_API_KEY").empty()
                || !ReadEnvironmentVariableForDoctor("OPENAI_API_KEY").empty();
            OutputLine(api.Control.Get(), api.Control4.Get(), "api_key_seen : configured=%s env=%s\n", YesNo(!config.ApiKey.empty()).c_str(), YesNo(apiKeyEnv).c_str());
        }
    }

    OutputLine(api.Control.Get(), api.Control4.Get(), "dml         : %s\n", dmlAware ? "available" : "plain-text fallback");
    OutputLine(api.Control.Get(), api.Control4.Get(), "session     : class=%s qualifier=%s execution=%s strategy=%s\n", session.DebugClass.c_str(), session.Qualifier.c_str(), session.ExecutionKind.c_str(), session.AnalysisStrategy.c_str());

    if (processorKnown)
    {
        OutputLine(api.Control.Get(), api.Control4.Get(), "processor   : %s\n", ProcessorTypeToString(processor).c_str());

        if (processor != IMAGE_FILE_MACHINE_AMD64)
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "warning     : DECOMP_DOCTOR_ARCH_UNSUPPORTED expected x64 target analysis\n");
        }
    }
    else
    {
        OutputLine(api.Control.Get(), api.Control4.Get(), "processor   : unknown (DECOMP_DOCTOR_PROCESSOR_UNKNOWN)\n");
    }

    OutputLine(api.Control.Get(), api.Control4.Get(), "pdb         : target-specific; run !decomp /view:plan <target> to inspect symbol enrichment\n");

    if (options.DoctorNetwork)
    {
        OutputLine(api.Control.Get(), api.Control4.Get(), "network     : skipped (DECOMP_DOCTOR_NET_SKIPPED) provider ping is not executed by /doctor\n");
    }
}

void PrintPlanOutput(
    const decomp::AnalyzeRequest& request,
    const decomp::LlmClientConfig& llmConfig,
    const decomp::DecompOptions& options,
    IDebugControl* control,
    IDebugControl4* control4)
{
    const decomp::LlmChunkPlanSummary chunkPlan = decomp::SummarizeLlmChunkPlan(request, llmConfig);
    const std::string promptDump = decomp::BuildDebugPromptDump(request);
    std::vector<std::string> recommendations;

    if (request.Facts.Instructions.empty())
    {
        recommendations.push_back("DECOMP_PLAN_NO_INSTRUCTIONS: target resolved but no instructions were recovered");
    }

    if (request.Facts.Instructions.size() >= options.MaxInstructions)
    {
        recommendations.push_back("DECOMP_PLAN_LIMIT_REACHED: rerun with /limit:deep, /limit:huge, or /limit:N if the function was truncated");
    }

    if (request.Facts.Pdb.Availability == "none")
    {
        recommendations.push_back("DECOMP_PLAN_PDB_NONE: load private symbols/PDBs for better names, types, fields, and source lines");
    }

    if (chunkPlan.UseChunked && llmConfig.TimeoutMs < 60000)
    {
        recommendations.push_back("DECOMP_PLAN_TIMEOUT_LOW: use /timeout:120000 or raise timeout_ms for chunked cloud analysis");
    }

    if (chunkPlan.UseChunked && chunkPlan.EstimatedChunks >= llmConfig.ChunkCountLimit)
    {
        recommendations.push_back("DECOMP_PLAN_CHUNK_LIMIT: raise chunk_count_limit before lowering /limit if quality matters");
    }

    if (llmConfig.Endpoint.empty())
    {
        recommendations.push_back("DECOMP_PLAN_MOCK_PROVIDER: configure endpoint/provider before expecting LLM pseudo-code");
    }

    OutputLine(control, control4, "plan:\n");
    OutputLine(control, control4, "target      : %s\n", request.Facts.QueryText.c_str());
    OutputLine(control, control4, "entry       : %s\n", decomp::HexU64(request.Facts.EntryAddress).c_str());
    OutputLine(control, control4, "query       : %s\n", decomp::HexU64(request.Facts.QueryAddress).c_str());
    OutputLine(control, control4, "module      : %s\n", request.Facts.Module.ModuleName.c_str());
    OutputLine(control, control4, "regions     : %llu\n", static_cast<unsigned long long>(request.Facts.Regions.size()));
    OutputLine(control, control4, "instructions: %llu / limit %u\n", static_cast<unsigned long long>(request.Facts.Instructions.size()), options.MaxInstructions);
    OutputLine(control, control4, "blocks      : %llu\n", static_cast<unsigned long long>(request.Facts.Blocks.size()));
    OutputLine(control, control4, "calls       : direct=%llu indirect=%llu targets=%llu\n", static_cast<unsigned long long>(request.Facts.Calls.size()), static_cast<unsigned long long>(request.Facts.IndirectCalls.size()), static_cast<unsigned long long>(request.Facts.CallTargets.size()));
    OutputLine(control, control4, "pdb         : availability=%s scope=%s params=%llu locals=%llu fields=%llu enums=%llu\n", request.Facts.Pdb.Availability.c_str(), request.Facts.Pdb.ScopeKind.c_str(), static_cast<unsigned long long>(request.Facts.Pdb.Params.size()), static_cast<unsigned long long>(request.Facts.Pdb.Locals.size()), static_cast<unsigned long long>(request.Facts.Pdb.FieldHints.size()), static_cast<unsigned long long>(request.Facts.Pdb.EnumHints.size()));
    OutputLine(control, control4, "session     : %s/%s class=%s qualifier=%s\n", request.Facts.SessionPolicy.ExecutionKind.c_str(), request.Facts.SessionPolicy.AnalysisStrategy.c_str(), request.Facts.SessionPolicy.DebugClass.c_str(), request.Facts.SessionPolicy.Qualifier.c_str());
    const std::string endpointDisplay = llmConfig.Endpoint.empty() ? std::string("<mock>") : SanitizeEndpointForDisplay(llmConfig.Endpoint);
    OutputLine(control, control4, "llm         : provider=%s model=%s endpoint=%s timeout_ms=%u\n", llmConfig.Provider.c_str(), llmConfig.Model.c_str(), endpointDisplay.c_str(), llmConfig.TimeoutMs);
    OutputLine(control, control4, "chunking    : use=%s estimated_chunks=%llu reason=%s block_limit=%u count_limit=%u\n", YesNo(chunkPlan.UseChunked).c_str(), static_cast<unsigned long long>(chunkPlan.EstimatedChunks), chunkPlan.Reason.c_str(), llmConfig.ChunkBlockLimit, llmConfig.ChunkCountLimit);
    OutputLine(control, control4, "prompt      : dump_chars=%llu facts=%llu evidence_nodes=%llu evidence_edges=%llu\n", static_cast<unsigned long long>(promptDump.size()), static_cast<unsigned long long>(request.Facts.Facts.size()), static_cast<unsigned long long>(request.Facts.EvidenceGraph.Nodes.size()), static_cast<unsigned long long>(request.Facts.EvidenceGraph.Edges.size()));

    OutputLine(control, control4, "\nrecommendations:\n");

    if (recommendations.empty())
    {
        OutputLine(control, control4, "- none\n");
        return;
    }

    for (const std::string& recommendation : recommendations)
    {
        OutputLine(control, control4, "- %s\n", recommendation.c_str());
    }
}

void PrintFactsOnly(
    const decomp::AnalyzeRequest& request,
    ResponseOutputSink& sink)
{
    SinkOutputLine(sink, "%s\n", decomp::SerializeAnalyzeRequest(request, true).c_str());
}

void PrintDataModelOutput(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    ResponseOutputSink& sink)
{
    SinkOutputLine(sink, "%s\n", BuildDataModelSnapshotJson(request, response).c_str());
}

std::string BuildBlockNavigationCommand(const decomp::AnalysisFacts& facts, const std::string& blockId)
{
    const decomp::BasicBlock* block = FindBlockById(facts, blockId);

    if (block == nullptr)
    {
        return std::string();
    }

    return BuildDisassembleCommand(block->StartAddress, block->EndAddress);
}

void OutputBlockLinkList(
    ResponseOutputSink& sink,
    const decomp::AnalysisFacts& facts,
    const std::string& label,
    const std::vector<std::string>& blockIds)
{
    if (blockIds.empty())
    {
        return;
    }

    SinkOutputLine(sink, "  %s:\n", label.c_str());

    for (const auto& blockId : blockIds)
    {
        const decomp::BasicBlock* block = FindBlockById(facts, blockId);

        if (block == nullptr)
        {
            SinkOutputLine(sink, "    - %s\n", blockId.c_str());
            continue;
        }

        OutputLinkLine(
            sink,
            "    - " + blockId + " " + decomp::HexU64(block->StartAddress) + "-" + decomp::HexU64(block->EndAddress),
            BuildDisassembleCommand(block->StartAddress, block->EndAddress));
    }
}

std::string BuildIssueNavigationCommand(const decomp::AnalyzeRequest& request, const std::string& issue)
{
    const decomp::AnalysisFacts& facts = request.Facts;
    const std::string lower = decomp::ToLowerAscii(issue);

    if (decomp::ContainsInsensitive(lower, "loop"))
    {
        for (const auto& region : facts.ControlFlow)
        {
            if (region.Kind == "natural_loop")
            {
                const std::string command = BuildBlockNavigationCommand(facts, region.HeaderBlock);

                if (!command.empty())
                {
                    return command;
                }
            }
        }
    }

    if (decomp::ContainsInsensitive(lower, "switch") && !facts.Switches.empty())
    {
        return BuildDisassembleAddressCommand(facts.Switches.front().Site);
    }

    if (decomp::ContainsInsensitive(lower, "branch") || decomp::ContainsInsensitive(lower, "control-flow"))
    {
        for (const auto& instruction : facts.Instructions)
        {
            if (instruction.IsConditionalBranch)
            {
                return BuildDisassembleAddressCommand(instruction.Address);
            }
        }

        for (const auto& region : facts.ControlFlow)
        {
            const std::string command = BuildBlockNavigationCommand(facts, region.HeaderBlock);

            if (!command.empty())
            {
                return command;
            }
        }
    }

    if (decomp::ContainsInsensitive(lower, "no-return") || decomp::ContainsInsensitive(lower, "non-returning"))
    {
        for (const auto& call : facts.Calls)
        {
            if (!call.Returns)
            {
                return BuildDisassembleAddressCommand(call.Site);
            }
        }

        for (const auto& call : facts.CallTargets)
        {
            if (decomp::ContainsInsensitive(call.SideEffects, "no-return") || decomp::ContainsInsensitive(call.ReturnType, "noreturn"))
            {
                return BuildDisassembleAddressCommand(call.Site);
            }
        }
    }

    if (decomp::ContainsInsensitive(lower, "return"))
    {
        for (const auto& instruction : facts.Instructions)
        {
            if (instruction.IsReturn)
            {
                return BuildDisassembleAddressCommand(instruction.Address);
            }
        }
    }

    if (decomp::ContainsInsensitive(lower, "parameter") || decomp::ContainsInsensitive(lower, "identifier"))
    {
        return BuildDisassembleAddressCommand(facts.EntryAddress);
    }

    if (decomp::ContainsInsensitive(lower, "instruction") && !facts.Instructions.empty())
    {
        return BuildDisassembleAddressCommand(facts.Instructions.front().Address);
    }

    if (decomp::ContainsInsensitive(lower, "function range")
        || decomp::ContainsInsensitive(lower, "evidence")
        || decomp::ContainsInsensitive(lower, "schema")
        || decomp::ContainsInsensitive(lower, "confidence"))
    {
        return BuildDisassembleAddressCommand(facts.EntryAddress);
    }

    return std::string();
}

void PrintLinkedIssueList(
    const char* title,
    const std::vector<std::string>& issues,
    const decomp::AnalyzeRequest& request,
    ResponseOutputSink& sink)
{
    if (issues.empty())
    {
        return;
    }

    SinkOutputLine(sink, "\n%s:\n", title);

    for (const auto& issue : issues)
    {
        const std::string command = BuildIssueNavigationCommand(request, issue);

        if (command.empty())
        {
            SinkOutputLine(sink, "- %s\n", issue.c_str());
            continue;
        }

        OutputLinkLine(sink, "- " + issue, command);
    }
}

void PrintLinkedIssueLine(
    const std::string& label,
    const std::string& issue,
    const decomp::AnalyzeRequest& request,
    ResponseOutputSink& sink)
{
    const std::string text = label + issue;
    const std::string command = BuildIssueNavigationCommand(request, issue);

    if (command.empty())
    {
        SinkOutputLine(sink, "%s\n", text.c_str());
        return;
    }

    OutputLinkLine(sink, text, command);
}

void PrintSuggestedFixes(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    ResponseOutputSink& sink)
{
    const std::vector<decomp::SuggestedFix> fixes = decomp::BuildSuggestedFixes(request, response);

    if (fixes.empty())
    {
        return;
    }

    SinkOutputLine(sink, "\nsuggested fixes:\n");

    for (const decomp::SuggestedFix& fix : fixes)
    {
        std::string label = "- " + fix.SwitchText + " [" + fix.Kind + "] " + fix.Reason;

        if (!fix.Evidence.empty())
        {
            label += " (" + fix.Evidence + ")";
        }

        if (fix.Site != 0)
        {
            label += " site=" + decomp::HexU64(fix.Site);
        }

        if (fix.SwitchText.find("=TYPE") != std::string::npos)
        {
            SinkOutputLine(sink, "%s\n", label.c_str());
            continue;
        }

        const std::string command = "!decomp " + fix.SwitchText + " " + QuoteCommandArgument(request.Facts.QueryText);
        OutputLinkLine(sink, label, command);
    }
}

std::string BuildLastReplayCommand(const std::string& mode, uint32_t cacheIndex)
{
    if (cacheIndex <= 1)
    {
        return "!decomp /last:" + mode;
    }

    return "!decomp /last:" + std::to_string(cacheIndex) + ":" + mode;
}

void PrintActionLinks(
    const decomp::AnalyzeRequest& request,
    ResponseOutputSink& sink,
    const decomp::DecompOptions& options)
{
    if (!sink.SupportsLinks())
    {
        return;
    }

    sink.WriteText("actions     : ");
    OutputLinkInline(sink, "explain", BuildLastReplayCommand("explain", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "json", BuildLastReplayCommand("json", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "facts", BuildLastReplayCommand("facts", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "prompt", BuildLastReplayCommand("prompt", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "data-model", BuildLastReplayCommand("data", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "history", "!decomp /history");
    sink.WriteText("\n");

    sink.WriteText("nav         : ");
    OutputLinkInline(sink, "entry", BuildDisassembleAddressCommand(request.Facts.EntryAddress));
    sink.WriteText(" ");
    OutputLinkInline(sink, "bp-entry", "bp " + decomp::HexU64(request.Facts.EntryAddress));
    sink.WriteText(" ");
    OutputLinkInline(sink, "last-json", BuildLastReplayCommand("json", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "last-dx", BuildLastReplayCommand("data", options.LastCacheIndex));
    sink.WriteText(" ");
    OutputLinkInline(sink, "last-prompt", BuildLastReplayCommand("prompt", options.LastCacheIndex));
    sink.WriteText("\n");
}

void OutputBlockAnchoredLine(
    ResponseOutputSink& sink,
    const decomp::AnalysisFacts& facts,
    const std::string& blockId,
    const std::string& label)
{
    const std::string command = BuildBlockNavigationCommand(facts, blockId);

    if (command.empty())
    {
        SinkOutputLine(sink, "%s\n", label.c_str());
        return;
    }

    OutputLinkLine(sink, label, command);
}

void PrintObfuscationExplainOutput(
    const decomp::AnalyzeRequest& request,
    ResponseOutputSink& sink)
{
    const decomp::ObfuscationFacts& obfuscation = request.Facts.Obfuscation;
    const decomp::SemanticControlFlowOverlay& semanticControlFlow = request.Facts.SemanticControlFlow;

    if (obfuscation.Dispatchers.empty()
        && obfuscation.OpaquePredicates.empty()
        && obfuscation.SubstitutionIdioms.empty()
        && semanticControlFlow.Edges.empty())
    {
        return;
    }

    constexpr size_t kExplainDispatcherLimit = 8;
    constexpr size_t kExplainEdgeLimit = 16;
    constexpr size_t kExplainPredicateLimit = 12;
    constexpr size_t kExplainSubstitutionLimit = 12;
    SinkOutputLine(sink, "\nobfuscation:\n");

    for (size_t index = 0; index < obfuscation.Dispatchers.size() && index < kExplainDispatcherLimit; ++index)
    {
        const decomp::ObfuscationDispatcher& dispatcher = obfuscation.Dispatchers[index];
        const std::string label = "- dispatcher "
            + dispatcher.Kind
            + " header="
            + dispatcher.HeaderBlock
            + " state="
            + dispatcher.StateVariable
            + " confidence="
            + std::to_string(dispatcher.Confidence);
        OutputBlockAnchoredLine(sink, request.Facts, dispatcher.HeaderBlock, label);

        if (!dispatcher.Evidence.empty())
        {
            SinkOutputLine(sink, "  evidence: %s\n", dispatcher.Evidence.c_str());
        }

        for (size_t edgeIndex = 0; edgeIndex < dispatcher.RecoveredEdges.size() && edgeIndex < kExplainEdgeLimit; ++edgeIndex)
        {
            const decomp::RecoveredControlFlowEdge& edge = dispatcher.RecoveredEdges[edgeIndex];
            std::string edgeLabel = "  - recovered edge "
                + edge.SourceBlock
                + " -> "
                + edge.TargetBlock;

            if (!edge.StateValue.empty())
            {
                edgeLabel += " state=" + edge.StateValue;
            }

            if (!edge.Condition.empty())
            {
                edgeLabel += " condition=" + edge.Condition;
            }

            edgeLabel += " confidence=" + std::to_string(edge.Confidence);
            OutputBlockAnchoredLine(sink, request.Facts, edge.SourceBlock, edgeLabel);
        }

        if (dispatcher.RecoveredEdges.size() > kExplainEdgeLimit)
        {
            SinkOutputLine(sink, "  - recovered edges truncated: %llu omitted\n", static_cast<unsigned long long>(dispatcher.RecoveredEdges.size() - kExplainEdgeLimit));
        }
    }

    for (size_t index = 0; index < obfuscation.OpaquePredicates.size() && index < kExplainPredicateLimit; ++index)
    {
        const decomp::OpaquePredicateFact& predicate = obfuscation.OpaquePredicates[index];
        const std::string label = "- opaque predicate block="
            + predicate.BlockId
            + " predicate="
            + predicate.Predicate
            + " result="
            + predicate.ConstantResult
            + " live="
            + predicate.LiveTargetBlock
            + " dead="
            + predicate.DeadTargetBlock
            + " confidence="
            + std::to_string(predicate.Confidence);

        if (predicate.Site != 0)
        {
            OutputLinkLine(sink, label, BuildDisassembleAddressCommand(predicate.Site));
        }
        else
        {
            OutputBlockAnchoredLine(sink, request.Facts, predicate.BlockId, label);
        }
    }

    for (size_t index = 0; index < obfuscation.SubstitutionIdioms.size() && index < kExplainSubstitutionLimit; ++index)
    {
        const decomp::SubstitutionIdiomFact& idiom = obfuscation.SubstitutionIdioms[index];
        const std::string label = "- substitution "
            + idiom.Pattern
            + " block="
            + idiom.BlockId
            + " "
            + idiom.OriginalExpression
            + " => "
            + idiom.SimplifiedExpression
            + " confidence="
            + std::to_string(idiom.Confidence);

        if (idiom.Site != 0)
        {
            OutputLinkLine(sink, label, BuildDisassembleAddressCommand(idiom.Site));
        }
        else
        {
            OutputBlockAnchoredLine(sink, request.Facts, idiom.BlockId, label);
        }
    }

    if (!semanticControlFlow.Edges.empty())
    {
        size_t liveEdges = 0;
        size_t deadEdges = 0;

        for (const decomp::SemanticControlFlowEdge& edge : semanticControlFlow.Edges)
        {
            if (edge.Dead)
            {
                ++deadEdges;
            }
            else
            {
                ++liveEdges;
            }
        }

        SinkOutputLine(
            sink,
            "- semantic CFG overlay: live_edges=%llu dead_edges=%llu confidence=%.2f\n",
            static_cast<unsigned long long>(liveEdges),
            static_cast<unsigned long long>(deadEdges),
            semanticControlFlow.Confidence);
    }
}

void PrintExplainOutput(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    ResponseOutputSink& sink)
{
    SinkOutputLine(sink, "\nevidence:\n");

    for (const auto& evidence : response.Evidence)
    {
        SinkOutputLine(sink, "- %s\n", evidence.Claim.c_str());

        for (const auto& blockId : evidence.Blocks)
        {
            const decomp::BasicBlock* block = FindBlockById(request.Facts, blockId);

            if (block == nullptr)
            {
                SinkOutputLine(sink, "  - %s\n", blockId.c_str());
                continue;
            }

            OutputLinkLine(
                sink,
                "  - " + blockId + " " + decomp::HexU64(block->StartAddress) + "-" + decomp::HexU64(block->EndAddress),
                BuildDisassembleCommand(block->StartAddress, block->EndAddress));
        }
    }

    PrintObfuscationExplainOutput(request, sink);

    if (!request.Facts.ControlFlow.empty())
    {
        SinkOutputLine(sink, "\ncontrol_flow:\n");

        for (const auto& region : request.Facts.ControlFlow)
        {
            const std::string headerCommand = BuildBlockNavigationCommand(request.Facts, region.HeaderBlock);
            const std::string label = "- " + region.Kind
                + " header=" + region.HeaderBlock
                + " condition=" + region.Condition
                + " confidence=" + std::to_string(region.Confidence);

            if (headerCommand.empty())
            {
                SinkOutputLine(sink, "%s\n", label.c_str());
            }
            else
            {
                OutputLinkLine(sink, label, headerCommand);
            }

            if (!region.Evidence.empty())
            {
                SinkOutputLine(sink, "  evidence: %s\n", region.Evidence.c_str());
            }

            OutputBlockLinkList(sink, request.Facts, "body", region.BodyBlocks);
            OutputBlockLinkList(sink, request.Facts, "latch", region.LatchBlocks);
            OutputBlockLinkList(sink, request.Facts, "exit", region.ExitBlocks);
        }
    }

    if (!request.Facts.TypeHints.empty())
    {
        SinkOutputLine(sink, "\ntype_hints:\n");

        for (const auto& hint : request.Facts.TypeHints)
        {
            const std::string label = "- " + hint.Expression + " => " + hint.Type
                + " [" + hint.Source + " " + std::to_string(hint.Confidence) + "]";

            if (hint.Site != 0)
            {
                OutputLinkLine(sink, label, BuildDisassembleAddressCommand(hint.Site));
            }
            else
            {
                SinkOutputLine(sink, "%s\n", label.c_str());
            }
        }
    }

    if (!request.Facts.CallTargets.empty())
    {
        SinkOutputLine(sink, "\ncall_targets:\n");

        for (const auto& call : request.Facts.CallTargets)
        {
            const std::string label = "- " + decomp::HexU64(call.Site) + " " + call.DisplayName + " " + call.TargetKind;
            const std::string command = call.TargetAddress != 0 ? BuildDisassembleCommand(call.TargetAddress, call.TargetAddress + 0x30) : ("u " + decomp::HexU64(call.Site));
            OutputLinkLine(sink, label, command);
        }
    }

    if (!request.Facts.ObservedBehavior.ArgumentSamples.empty()
        || !request.Facts.ObservedBehavior.MemoryHotspots.empty()
        || !request.Facts.ObservedBehavior.TtdQueries.empty())
    {
        SinkOutputLine(sink, "\nobserved_behavior:\n");
        SinkOutputLine(
            sink,
            "- ip=%s in_function=%s sp=%s confidence=%.2f\n",
            decomp::HexU64(request.Facts.ObservedBehavior.InstructionPointer).c_str(),
            request.Facts.ObservedBehavior.CurrentInstructionInFunction ? "true" : "false",
            decomp::HexU64(request.Facts.ObservedBehavior.StackPointer).c_str(),
            request.Facts.ObservedBehavior.Confidence);

        for (const auto& argument : request.Facts.ObservedBehavior.ArgumentSamples)
        {
            SinkOutputLine(
                sink,
                "- %s/%s = %s %s [%.2f]\n",
                argument.Name.c_str(),
                argument.Register.c_str(),
                decomp::HexU64(argument.Value).c_str(),
                argument.Symbol.c_str(),
                argument.Confidence);
        }

        for (const auto& hotspot : request.Facts.ObservedBehavior.MemoryHotspots)
        {
            SinkOutputLine(
                sink,
                "- hotspot %s read=%u write=%u [%.2f]\n",
                hotspot.Expression.c_str(),
                hotspot.ReadCount,
                hotspot.WriteCount,
                hotspot.Confidence);

            for (const auto& site : hotspot.Sites)
            {
                OutputLinkLine(
                    sink,
                    "  - site " + decomp::HexU64(site),
                    BuildDisassembleAddressCommand(site));
            }
        }

        for (const auto& query : request.Facts.ObservedBehavior.TtdQueries)
        {
            OutputLinkLine(sink, "- " + query, query);
        }
    }
}

void RenderResponse(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& displayConfig,
    ResponseOutputSink& sink,
    const decomp::DecompOptions& options)
{
    if (options.JsonOutput)
    {
        SinkOutputLine(sink, "%s\n", decomp::SerializeAnalyzeRequest(request, true).c_str());
        SinkOutputLine(sink, "%s\n", decomp::SerializeAnalyzeResponse(response, true).c_str());
        return;
    }

    if (options.FactsOnlyOutput)
    {
        PrintFactsOnly(request, sink);
        return;
    }

    if (options.DataModelOutput)
    {
        PrintDataModelOutput(request, response, sink);
        return;
    }

    SinkOutputLine(sink, "target      : %s\n", request.Facts.QueryText.c_str());
    if (sink.SupportsLinks())
    {
        sink.WriteText("entry       : ");
        OutputLinkInline(sink, decomp::HexU64(request.Facts.EntryAddress), BuildDisassembleCommand(request.Facts.EntryAddress, request.Facts.EntryAddress + 0x40));
        sink.WriteText("\n");
    }
    else
    {
        SinkOutputLine(sink, "entry       : %s\n", decomp::HexU64(request.Facts.EntryAddress).c_str());
    }
    SinkOutputLine(sink, "query       : %s\n", decomp::HexU64(request.Facts.QueryAddress).c_str());
    SinkOutputLine(sink, "module      : %s\n", request.Facts.Module.ModuleName.c_str());
    SinkOutputLine(sink, "regions     : %llu\n", static_cast<unsigned long long>(request.Facts.Regions.size()));
    SinkOutputLine(sink, "session     : %s/%s\n", request.Facts.SessionPolicy.ExecutionKind.c_str(), request.Facts.SessionPolicy.AnalysisStrategy.c_str());
    SinkOutputLine(sink, "analyzer    : %.2f\n", request.Facts.PreLlmConfidence);
    SinkOutputLine(sink, "llm         : %.2f\n", response.Confidence);
    SinkOutputLine(sink, "verified    : %.2f\n", response.Verifier.AdjustedConfidence);
    SinkOutputLine(sink, "provider    : %s\n\n", response.Provider.c_str());
    PrintActionLinks(request, sink, options);

    if (!response.Summary.empty())
    {
        const std::string formattedSummary = FormatSummaryForDisplay(response.Summary);
        SinkOutputLine(sink, "summary:\n%s\n\n", formattedSummary.c_str());
    }

    if (options.BriefOutput)
    {
        if (!response.Uncertainties.empty())
        {
            PrintLinkedIssueLine("top_uncertainty: ", response.Uncertainties.front(), request, sink);
        }

        if (!response.Verifier.Warnings.empty())
        {
            PrintLinkedIssueLine("top_warning    : ", response.Verifier.Warnings.front(), request, sink);
        }

        return;
    }

    if (!response.PseudoC.empty())
    {
        SinkOutputLine(sink, "pseudo_c:\n");
        PrintPseudoCodeHighlighted(response, displayConfig, sink);
        SinkOutputLine(sink, "\n");
    }
    if (!response.Uncertainties.empty())
    {
        PrintLinkedIssueList("uncertainties", response.Uncertainties, request, sink);
    }

    if (!response.Verifier.Warnings.empty())
    {
        if (!response.Verifier.Issues.empty())
        {
            std::vector<std::string> issueLines;
            issueLines.reserve(response.Verifier.Issues.size());

            for (const auto& issue : response.Verifier.Issues)
            {
                std::string line = "[" + issue.Severity + "/" + issue.Code + "] " + issue.Message;

                if (!issue.Evidence.empty())
                {
                    line += " (" + issue.Evidence + ")";
                }

                issueLines.push_back(std::move(line));
            }

            PrintLinkedIssueList("verifier issues", issueLines, request, sink);
        }
        else
        {
            PrintLinkedIssueList("verifier warnings", response.Verifier.Warnings, request, sink);
        }
    }

    PrintSuggestedFixes(request, response, sink);

    if (options.ExplainOutput)
    {
        PrintExplainOutput(request, response, sink);
    }
}

enum class ViewerRtfColor : int
{
    Text = 1,
    Muted = 2,
    Blue = 3,
    Green = 4,
    Purple = 5,
    Red = 6,
    Orange = 7,
    Background = 8,
    Border = 9,
    Surface = 10
};

constexpr COLORREF kNativeViewerBackgroundColor = RGB(13, 17, 23);
constexpr COLORREF kNativeViewerSurfaceColor = RGB(22, 27, 34);
constexpr COLORREF kNativeViewerSelectedColor = RGB(31, 111, 235);
constexpr COLORREF kNativeViewerTextColor = RGB(201, 209, 217);
constexpr COLORREF kNativeViewerMutedTextColor = RGB(139, 148, 158);
constexpr int kNativeViewerOuterMargin = 12;
constexpr int kNativeViewerControlGap = 10;
constexpr int kNativeViewerPanelHeaderHeight = 42;
constexpr int kNativeViewerFunctionItemHeight = 52;

int ViewerRtfColorIndex(ViewerRtfColor color)
{
    return static_cast<int>(color);
}

void AppendRtfColor(std::string& rtf, ViewerRtfColor color)
{
    rtf += "\\cf";
    rtf += std::to_string(ViewerRtfColorIndex(color));
    rtf += " ";
}

void AppendRtfEscapedWide(std::string& rtf, const std::wstring& text)
{
    for (const wchar_t ch : text)
    {
        if (ch == L'\\')
        {
            rtf += "\\\\";
        }
        else if (ch == L'{')
        {
            rtf += "\\{";
        }
        else if (ch == L'}')
        {
            rtf += "\\}";
        }
        else if (ch == L'\t')
        {
            rtf += "\\tab ";
        }
        else if (ch == L'\r')
        {
            continue;
        }
        else if (ch == L'\n')
        {
            rtf += "\\line ";
        }
        else if (ch >= 0x20 && ch <= 0x7e)
        {
            rtf.push_back(static_cast<char>(ch));
        }
        else
        {
            const int signedValue = ch <= 0x7fff ? static_cast<int>(ch) : static_cast<int>(ch) - 0x10000;
            rtf += "\\u";
            rtf += std::to_string(signedValue);
            rtf += "?";
        }
    }
}

void AppendRtfEscapedUtf8(std::string& rtf, const std::string& text)
{
    const std::wstring wide = Utf8ToWide(text);

    if (!wide.empty() || text.empty())
    {
        AppendRtfEscapedWide(rtf, wide);
        return;
    }

    for (const unsigned char ch : text)
    {
        if (ch == '\\')
        {
            rtf += "\\\\";
        }
        else if (ch == '{')
        {
            rtf += "\\{";
        }
        else if (ch == '}')
        {
            rtf += "\\}";
        }
        else if (ch >= 0x20 && ch <= 0x7e)
        {
            rtf.push_back(static_cast<char>(ch));
        }
        else
        {
            rtf += "?";
        }
    }
}

std::vector<std::string> SplitViewerTextLines(const std::string& text)
{
    std::vector<std::string> lines;
    std::string current;

    for (const char ch : text)
    {
        if (ch == '\r')
        {
            continue;
        }

        if (ch == '\n')
        {
            lines.push_back(current);
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty())
    {
        lines.push_back(current);
    }

    return lines;
}

bool IsViewerSectionHeading(const std::string& line)
{
    const std::string heading = decomp::ToLowerAscii(decomp::TrimCopy(line));
    static const std::set<std::string> kHeadings =
    {
        "summary:",
        "pseudo_c:",
        "uncertainties:",
        "verifier issues:",
        "verifier warnings:",
        "suggested fixes:",
        "evidence:",
        "control_flow:",
        "type_hints:",
        "call_targets:",
        "observed_behavior:"
    };

    return kHeadings.find(heading) != kHeadings.end();
}

bool TrySplitViewerMetadataLine(const std::string& line, std::string& key, std::string& value)
{
    bool success = false;

    do
    {
        if (line.empty() || line.front() == ' ' || line.front() == '-')
        {
            break;
        }

        const size_t colon = line.find(':');

        if (colon == std::string::npos || colon == 0 || colon > 18 || colon + 1 >= line.size())
        {
            break;
        }

        key = decomp::TrimCopy(line.substr(0, colon));
        value = decomp::TrimCopy(line.substr(colon + 1));

        if (key.empty() || value.empty())
        {
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

void AppendRtfCommandAwareText(std::string& rtf, const std::string& text)
{
    const std::string marker = " [cmd: ";
    size_t cursor = 0;

    while (cursor < text.size())
    {
        const size_t commandStart = text.find(marker, cursor);

        if (commandStart == std::string::npos)
        {
            AppendRtfEscapedUtf8(rtf, text.substr(cursor));
            break;
        }

        AppendRtfEscapedUtf8(rtf, text.substr(cursor, commandStart - cursor));

        const size_t commandTextStart = commandStart + marker.size();
        const size_t commandEnd = text.find(']', commandTextStart);

        if (commandEnd == std::string::npos)
        {
            AppendRtfEscapedUtf8(rtf, text.substr(commandStart));
            break;
        }

        rtf += "\\cf3\\f1\\fs16 ";
        AppendRtfEscapedUtf8(rtf, "  ");
        AppendRtfEscapedUtf8(rtf, text.substr(commandTextStart, commandEnd - commandTextStart));
        rtf += "\\f0\\fs19\\cf1 ";
        cursor = commandEnd + 1;
    }
}

bool IsCodeIdentifierStart(char ch)
{
    return std::isalpha(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

bool IsCodeIdentifierChar(char ch)
{
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

bool IsCodeKeyword(const std::string& token)
{
    static const std::set<std::string> kKeywords =
    {
        "auto",
        "bool",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "false",
        "float",
        "for",
        "goto",
        "if",
        "int",
        "long",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "true",
        "typedef",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "uint8_t",
        "uintptr_t",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while"
    };

    return kKeywords.find(token) != kKeywords.end();
}

size_t GetUtf8SequenceLength(const std::string& text, size_t index)
{
    size_t length = 1;

    do
    {
        if (index >= text.size())
        {
            break;
        }

        const unsigned char lead = static_cast<unsigned char>(text[index]);

        if (lead < 0x80)
        {
            break;
        }

        if (lead >= 0xc2 && lead <= 0xdf)
        {
            length = 2;
        }
        else if (lead >= 0xe0 && lead <= 0xef)
        {
            length = 3;
        }
        else if (lead >= 0xf0 && lead <= 0xf4)
        {
            length = 4;
        }

        if (index + length > text.size())
        {
            length = text.size() - index;
            break;
        }

        for (size_t offset = 1; offset < length; ++offset)
        {
            const unsigned char ch = static_cast<unsigned char>(text[index + offset]);

            if (ch < 0x80 || ch > 0xbf)
            {
                length = offset;
                break;
            }
        }
    }
    while (false);

    return length;
}

void AppendRtfCodeToken(std::string& rtf, const std::string& token, ViewerRtfColor color, bool bold)
{
    AppendRtfColor(rtf, color);

    if (bold)
    {
        rtf += "\\b ";
    }

    AppendRtfEscapedUtf8(rtf, token);

    if (bold)
    {
        rtf += "\\b0 ";
    }

    AppendRtfColor(rtf, ViewerRtfColor::Text);
}

void AppendRtfHighlightedCodeLine(std::string& rtf, const std::string& line)
{
    size_t index = 0;

    while (index < line.size())
    {
        if (index + 1 < line.size() && line[index] == '/' && line[index + 1] == '/')
        {
            AppendRtfCodeToken(rtf, line.substr(index), ViewerRtfColor::Green, false);
            return;
        }

        if (line[index] == '"' || line[index] == '\'')
        {
            const char quote = line[index];
            size_t end = index + 1;
            bool escaped = false;

            while (end < line.size())
            {
                const char ch = line[end];

                if (!escaped && ch == quote)
                {
                    ++end;
                    break;
                }

                escaped = !escaped && ch == '\\';

                if (ch != '\\')
                {
                    escaped = false;
                }

                ++end;
            }

            AppendRtfCodeToken(rtf, line.substr(index, end - index), ViewerRtfColor::Red, false);
            index = end;
            continue;
        }

        if (std::isdigit(static_cast<unsigned char>(line[index])) != 0)
        {
            size_t end = index + 1;

            while (end < line.size())
            {
                const char ch = line[end];

                if (std::isalnum(static_cast<unsigned char>(ch)) == 0 && ch != 'x' && ch != 'X' && ch != '`' && ch != '.')
                {
                    break;
                }

                ++end;
            }

            AppendRtfCodeToken(rtf, line.substr(index, end - index), ViewerRtfColor::Orange, false);
            index = end;
            continue;
        }

        if (IsCodeIdentifierStart(line[index]))
        {
            size_t end = index + 1;

            while (end < line.size() && IsCodeIdentifierChar(line[end]))
            {
                ++end;
            }

            const std::string token = line.substr(index, end - index);
            size_t next = end;

            while (next < line.size() && std::isspace(static_cast<unsigned char>(line[next])) != 0)
            {
                ++next;
            }

            if (IsCodeKeyword(token))
            {
                AppendRtfCodeToken(rtf, token, ViewerRtfColor::Purple, true);
            }
            else if (next < line.size() && line[next] == '(')
            {
                AppendRtfCodeToken(rtf, token, ViewerRtfColor::Blue, false);
            }
            else
            {
                AppendRtfEscapedUtf8(rtf, token);
            }

            index = end;
            continue;
        }

        if ((static_cast<unsigned char>(line[index]) & 0x80) != 0)
        {
            const size_t length = GetUtf8SequenceLength(line, index);
            AppendRtfEscapedUtf8(rtf, line.substr(index, length));
            index += length;
            continue;
        }

        AppendRtfEscapedUtf8(rtf, std::string(1, line[index]));
        ++index;
    }
}

void AppendRtfTitle(std::string& rtf, const decomp::AnalyzeRequest& request)
{
    rtf += "\\pard\\plain\\f0\\fs34\\b\\cf1\\sa20 ";
    AppendRtfEscapedUtf8(rtf, "!decomp ");
    AppendRtfEscapedUtf8(rtf, request.Facts.QueryText);
    rtf += "\\b0\\par\n";

    rtf += "\\pard\\plain\\f0\\fs18\\cf2\\sa180 ";

    if (!request.Facts.Module.ModuleName.empty())
    {
        AppendRtfEscapedUtf8(rtf, request.Facts.Module.ModuleName);
    }
    else
    {
        AppendRtfEscapedUtf8(rtf, "native decompile viewer");
    }

    rtf += "\\par\\par\n";
}

void AppendRtfSectionHeading(std::string& rtf, const std::string& line)
{
    std::string label = decomp::TrimCopy(line);

    if (!label.empty() && label.back() == ':')
    {
        label.pop_back();
    }

    rtf += "\\pard\\plain\\f0\\fs23\\b\\cf3\\sb180\\sa60 ";
    AppendRtfEscapedUtf8(rtf, label);
    rtf += "\\b0\\par\n";
}

void AppendRtfMetadataLine(std::string& rtf, const std::string& key, const std::string& value)
{
    rtf += "\\pard\\plain\\f0\\fs19\\cf1\\li1680\\fi-1440\\tx1680\\sa24 ";
    rtf += "\\cf2\\b ";
    AppendRtfEscapedUtf8(rtf, key);
    rtf += "\\b0\\tab\\cf1 ";
    AppendRtfCommandAwareText(rtf, value);
    rtf += "\\par\n";
}

void AppendRtfBulletLine(std::string& rtf, const std::string& line)
{
    const size_t firstText = line.find_first_not_of(' ');
    const size_t leadingSpaces = firstText == std::string::npos ? 0 : firstText;
    const int leftIndent = 240 + static_cast<int>((leadingSpaces / 2) * 240);

    rtf += "\\pard\\plain\\f0\\fs19\\cf1\\li";
    rtf += std::to_string(leftIndent);
    rtf += "\\fi-180\\sa20 ";
    AppendRtfCommandAwareText(rtf, decomp::TrimCopy(line));
    rtf += "\\par\n";
}

void AppendRtfPlainLine(std::string& rtf, const std::string& line)
{
    rtf += "\\pard\\plain\\f0\\fs19\\cf1\\sa20 ";
    AppendRtfCommandAwareText(rtf, line);
    rtf += "\\par\n";
}

void AppendRtfCodeLine(std::string& rtf, const std::string& line)
{
    rtf += "\\pard\\plain\\f1\\fs18\\cf1\\cb10\\li300\\ri300\\sa0 ";

    if (line.empty())
    {
        rtf += " ";
    }
    else
    {
        AppendRtfHighlightedCodeLine(rtf, line);
    }

    rtf += "\\par\n";
}

std::string BuildPrettyViewerRtf(const decomp::AnalyzeRequest& request, const std::string& text)
{
    std::string rtf;
    rtf.reserve(text.size() * 2U + 4096U);
    rtf += "{\\rtf1\\ansi\\deff0\\uc1\n";
    rtf += "{\\fonttbl{\\f0\\fnil\\fcharset0 Segoe UI;}{\\f1\\fmodern\\fcharset0 Consolas;}}\n";
    rtf += "{\\colortbl ;";
    rtf += "\\red201\\green209\\blue217;";
    rtf += "\\red139\\green148\\blue158;";
    rtf += "\\red88\\green166\\blue255;";
    rtf += "\\red63\\green185\\blue80;";
    rtf += "\\red210\\green168\\blue255;";
    rtf += "\\red255\\green123\\blue114;";
    rtf += "\\red255\\green166\\blue87;";
    rtf += "\\red13\\green17\\blue23;";
    rtf += "\\red48\\green54\\blue61;";
    rtf += "\\red22\\green27\\blue34;";
    rtf += "}\n";
    rtf += "\\viewkind4\\fs19\\cf1\\cb8\n";

    AppendRtfTitle(rtf, request);

    bool inPseudoCode = false;
    const std::vector<std::string> lines = SplitViewerTextLines(text);

    for (const std::string& line : lines)
    {
        const std::string trimmed = decomp::TrimCopy(line);
        const std::string lower = decomp::ToLowerAscii(trimmed);

        if (lower == "pseudo_c:")
        {
            AppendRtfSectionHeading(rtf, line);
            inPseudoCode = true;
            continue;
        }

        if (inPseudoCode && !line.empty() && line.front() != ' ' && IsViewerSectionHeading(line))
        {
            inPseudoCode = false;
        }

        if (inPseudoCode)
        {
            AppendRtfCodeLine(rtf, line);
            continue;
        }

        if (trimmed.empty())
        {
            rtf += "\\pard\\plain\\f0\\fs10\\par\n";
            continue;
        }

        if (IsViewerSectionHeading(line))
        {
            AppendRtfSectionHeading(rtf, line);
            continue;
        }

        std::string key;
        std::string value;

        if (TrySplitViewerMetadataLine(line, key, value))
        {
            AppendRtfMetadataLine(rtf, key, value);
            continue;
        }

        if (!trimmed.empty() && trimmed.front() == '-')
        {
            AppendRtfBulletLine(rtf, line);
            continue;
        }

        AppendRtfPlainLine(rtf, line);
    }

    rtf += "}";
    return rtf;
}

struct NativeViewerRtfStream
{
    const char* Data = nullptr;
    size_t Size = 0;
    size_t Offset = 0;
};

struct NativeViewerHistoryEntry
{
    std::wstring Label;
    std::wstring SecondaryLabel;
    std::wstring WindowTitle;
    std::wstring Text;
    std::string RtfText;
};

DWORD CALLBACK NativeViewerEditStreamCallback(DWORD_PTR cookie, LPBYTE buffer, LONG byteCount, LONG* copied)
{
    NativeViewerRtfStream* stream = reinterpret_cast<NativeViewerRtfStream*>(cookie);

    if (stream == nullptr || buffer == nullptr || copied == nullptr || byteCount <= 0)
    {
        if (copied != nullptr)
        {
            *copied = 0;
        }

        return 0;
    }

    const size_t remaining = stream->Offset < stream->Size ? stream->Size - stream->Offset : 0;
    const size_t bytesToCopy = std::min(remaining, static_cast<size_t>(byteCount));

    if (bytesToCopy > 0)
    {
        std::memcpy(buffer, stream->Data + stream->Offset, bytesToCopy);
        stream->Offset += bytesToCopy;
    }

    *copied = static_cast<LONG>(bytesToCopy);
    return 0;
}

struct NativeViewerWindowState
{
    std::wstring Title;
    std::wstring Text;
    std::string RtfText;
    HWND Window = nullptr;
    HWND Edit = nullptr;
    HWND HistoryHeader = nullptr;
    HWND HistoryList = nullptr;
    HFONT EditFont = nullptr;
    HFONT HistoryFont = nullptr;
    HBRUSH BackgroundBrush = nullptr;
    HBRUSH SurfaceBrush = nullptr;
    HBRUSH SelectedBrush = nullptr;
    HICON Icon = nullptr;
    HICON SmallIcon = nullptr;
    WNDPROC OriginalEditProc = nullptr;
    HMODULE RichEditModule = nullptr;
    std::vector<NativeViewerHistoryEntry> HistoryEntries;
    size_t ActiveHistoryIndex = 0;
    bool SupportsEditMessages = false;
    bool SupportsRichText = false;
};

void RedrawNativeViewerEdit(HWND edit)
{
    if (edit == nullptr || !IsWindow(edit))
    {
        return;
    }

    RedrawWindow(
        edit,
        nullptr,
        nullptr,
        RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_FRAME);
}

bool IsNativeViewerScrollKey(WPARAM key)
{
    return key == VK_UP
        || key == VK_DOWN
        || key == VK_PRIOR
        || key == VK_NEXT
        || key == VK_HOME
        || key == VK_END
        || key == VK_LEFT
        || key == VK_RIGHT;
}

LRESULT CALLBACK NativeViewerEditWindowProc(HWND edit, UINT message, WPARAM wparam, LPARAM lparam)
{
    NativeViewerWindowState* state = reinterpret_cast<NativeViewerWindowState*>(GetWindowLongPtrW(edit, GWLP_USERDATA));
    WNDPROC original = state != nullptr ? state->OriginalEditProc : nullptr;

    if (original == nullptr)
    {
        return DefWindowProcW(edit, message, wparam, lparam);
    }

    const LRESULT result = CallWindowProcW(original, edit, message, wparam, lparam);
    bool redraw = false;

    switch (message)
    {
    case WM_VSCROLL:
    case WM_HSCROLL:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
        redraw = true;
        break;
    case WM_KEYDOWN:
        redraw = IsNativeViewerScrollKey(wparam);
        break;
    default:
        break;
    }

    if (redraw)
    {
        RedrawNativeViewerEdit(edit);
    }

    return result;
}

void InstallNativeViewerEditSubclass(NativeViewerWindowState& state)
{
    if (state.Edit == nullptr || !state.SupportsEditMessages)
    {
        return;
    }

    SetLastError(ERROR_SUCCESS);
    SetWindowLongPtrW(state.Edit, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&state));

    if (GetLastError() != ERROR_SUCCESS)
    {
        return;
    }

    SetLastError(ERROR_SUCCESS);
    state.OriginalEditProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
        state.Edit,
        GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(NativeViewerEditWindowProc)));

    if (state.OriginalEditProc == nullptr && GetLastError() != ERROR_SUCCESS)
    {
        SetWindowLongPtrW(state.Edit, GWLP_USERDATA, 0);
    }
}

bool StreamNativeViewerRichText(NativeViewerWindowState& state)
{
    bool success = false;

    do
    {
        if (!state.SupportsRichText || state.Edit == nullptr || state.RtfText.empty())
        {
            break;
        }

        NativeViewerRtfStream stream;
        stream.Data = state.RtfText.data();
        stream.Size = state.RtfText.size();

        EDITSTREAM editStream = {};
        editStream.dwCookie = reinterpret_cast<DWORD_PTR>(&stream);
        editStream.pfnCallback = NativeViewerEditStreamCallback;

        SendMessageW(state.Edit, EM_SETREADONLY, FALSE, 0);
        SetWindowTextW(state.Edit, L"");
        const LRESULT result = SendMessageW(state.Edit, EM_STREAMIN, SF_RTF, reinterpret_cast<LPARAM>(&editStream));
        SendMessageW(state.Edit, EM_SETREADONLY, TRUE, 0);

        if (result == 0 || editStream.dwError != 0 || stream.Offset != stream.Size)
        {
            break;
        }

        success = true;
        RedrawNativeViewerEdit(state.Edit);
    }
    while (false);

    return success;
}

bool SetNativeViewerEntry(NativeViewerWindowState& state, size_t index)
{
    bool success = false;

    do
    {
        if (index >= state.HistoryEntries.size())
        {
            break;
        }

        state.ActiveHistoryIndex = index;
        state.Text = state.HistoryEntries[index].Text;
        state.RtfText = state.HistoryEntries[index].RtfText;

        if (state.Window != nullptr && !state.HistoryEntries[index].WindowTitle.empty())
        {
            SetWindowTextW(state.Window, state.HistoryEntries[index].WindowTitle.c_str());
        }

        if (state.HistoryList != nullptr)
        {
            SendMessageW(state.HistoryList, LB_SETCURSEL, static_cast<WPARAM>(index), 0);
        }

        if (state.Edit == nullptr)
        {
            success = true;
            break;
        }

        bool usedRichText = false;

        if (state.SupportsRichText)
        {
            SendMessageW(state.Edit, EM_SETBKGNDCOLOR, 0, kNativeViewerBackgroundColor);
            usedRichText = StreamNativeViewerRichText(state);
        }

        if (!usedRichText)
        {
            SetWindowTextW(state.Edit, state.Text.c_str());
        }

        if (state.SupportsEditMessages)
        {
            SendMessageW(state.Edit, EM_SETSEL, 0, 0);
        }

        RedrawNativeViewerEdit(state.Edit);
        success = true;
    }
    while (false);

    return success;
}

int GetNativeViewerHistoryListWidth(int clientWidth)
{
    int width = 0;

    do
    {
        if (clientWidth < 760)
        {
            break;
        }

        width = clientWidth / 5;

        if (width < 280)
        {
            width = 280;
        }
        else if (width > 380)
        {
            width = 380;
        }
    }
    while (false);

    return width;
}

void LayoutNativeViewerControls(NativeViewerWindowState& state, int clientWidth, int clientHeight)
{
    const int listWidth = GetNativeViewerHistoryListWidth(clientWidth);
    const int contentHeight = (std::max)(0, clientHeight - (kNativeViewerOuterMargin * 2));

    if (state.HistoryHeader != nullptr)
    {
        ShowWindow(state.HistoryHeader, listWidth > 0 ? SW_SHOW : SW_HIDE);
        MoveWindow(
            state.HistoryHeader,
            kNativeViewerOuterMargin,
            kNativeViewerOuterMargin,
            listWidth,
            kNativeViewerPanelHeaderHeight,
            TRUE);
    }

    if (state.HistoryList != nullptr)
    {
        ShowWindow(state.HistoryList, listWidth > 0 ? SW_SHOW : SW_HIDE);
        MoveWindow(
            state.HistoryList,
            kNativeViewerOuterMargin,
            kNativeViewerOuterMargin + kNativeViewerPanelHeaderHeight,
            listWidth,
            (std::max)(0, contentHeight - kNativeViewerPanelHeaderHeight),
            TRUE);
    }

    if (state.Edit != nullptr)
    {
        int editX = kNativeViewerOuterMargin;

        if (listWidth > 0)
        {
            editX += listWidth + kNativeViewerControlGap;
        }

        const int editWidth = (std::max)(0, clientWidth - editX - kNativeViewerOuterMargin);

        MoveWindow(
            state.Edit,
            editX,
            kNativeViewerOuterMargin,
            editWidth,
            contentHeight,
            TRUE);
    }
}

struct NativeViewerLaunchSync
{
    HANDLE ReadyEvent = nullptr;
    bool Success = false;
    bool Abandoned = false;
    HWND WindowHandle = nullptr;
    HWND OwnerHandle = nullptr;
    std::string Error;
    std::mutex Mutex;

    ~NativeViewerLaunchSync()
    {
        if (ReadyEvent != nullptr)
        {
            CloseHandle(ReadyEvent);
            ReadyEvent = nullptr;
        }
    }
};

struct NativeViewerThreadContext
{
    NativeViewerWindowState* State = nullptr;
    std::shared_ptr<NativeViewerLaunchSync> Sync;
    HWND Owner = nullptr;
    HMODULE Module = nullptr;
};

constexpr wchar_t kNativeViewerWindowClass[] = L"WindbgDecompNativeViewerWindow";
constexpr DWORD kNativeViewerLaunchTimeoutMs = 15000;
constexpr UINT_PTR kNativeViewerHistoryListId = 2;

uint32_t MakeNativeViewerIconPixel(COLORREF color)
{
    return 0xff000000U
        | (static_cast<uint32_t>(GetRValue(color)) << 16)
        | (static_cast<uint32_t>(GetGValue(color)) << 8)
        | static_cast<uint32_t>(GetBValue(color));
}

int ScaleNativeViewerIconCoord(int value, int size)
{
    return (std::max)(1, (value * size) / 32);
}

void FillNativeViewerIconRect(
    uint32_t* pixels,
    int size,
    int left,
    int top,
    int right,
    int bottom,
    COLORREF color)
{
    const int clampedLeft = (std::max)(0, (std::min)(size, left));
    const int clampedTop = (std::max)(0, (std::min)(size, top));
    const int clampedRight = (std::max)(0, (std::min)(size, right));
    const int clampedBottom = (std::max)(0, (std::min)(size, bottom));
    const uint32_t pixel = MakeNativeViewerIconPixel(color);

    for (int y = clampedTop; y < clampedBottom; ++y)
    {
        for (int x = clampedLeft; x < clampedRight; ++x)
        {
            pixels[(y * size) + x] = pixel;
        }
    }
}

HICON CreateNativeViewerIcon(int size)
{
    HICON icon = nullptr;
    HBITMAP colorBitmap = nullptr;
    HBITMAP maskBitmap = nullptr;

    do
    {
        if (size <= 0)
        {
            break;
        }

        BITMAPINFO bitmapInfo = {};
        bitmapInfo.bmiHeader.biSize = sizeof(bitmapInfo.bmiHeader);
        bitmapInfo.bmiHeader.biWidth = size;
        bitmapInfo.bmiHeader.biHeight = -size;
        bitmapInfo.bmiHeader.biPlanes = 1;
        bitmapInfo.bmiHeader.biBitCount = 32;
        bitmapInfo.bmiHeader.biCompression = BI_RGB;

        void* bits = nullptr;
        HDC screen = GetDC(nullptr);

        if (screen == nullptr)
        {
            break;
        }

        colorBitmap = CreateDIBSection(screen, &bitmapInfo, DIB_RGB_COLORS, &bits, nullptr, 0);
        ReleaseDC(nullptr, screen);

        if (colorBitmap == nullptr || bits == nullptr)
        {
            break;
        }

        uint32_t* pixels = static_cast<uint32_t*>(bits);
        const uint32_t background = MakeNativeViewerIconPixel(kNativeViewerBackgroundColor);

        for (int index = 0; index < size * size; ++index)
        {
            pixels[index] = background;
        }

        FillNativeViewerIconRect(pixels, size, 0, 0, size, ScaleNativeViewerIconCoord(2, size), RGB(88, 166, 255));
        FillNativeViewerIconRect(pixels, size, 0, size - ScaleNativeViewerIconCoord(2, size), size, size, RGB(88, 166, 255));
        FillNativeViewerIconRect(pixels, size, 0, 0, ScaleNativeViewerIconCoord(2, size), size, RGB(88, 166, 255));
        FillNativeViewerIconRect(pixels, size, size - ScaleNativeViewerIconCoord(2, size), 0, size, size, RGB(88, 166, 255));
        FillNativeViewerIconRect(pixels, size, ScaleNativeViewerIconCoord(4, size), ScaleNativeViewerIconCoord(4, size), ScaleNativeViewerIconCoord(7, size), size - ScaleNativeViewerIconCoord(4, size), RGB(31, 111, 235));

        const COLORREF glyph = RGB(201, 209, 217);
        FillNativeViewerIconRect(pixels, size, ScaleNativeViewerIconCoord(10, size), ScaleNativeViewerIconCoord(8, size), ScaleNativeViewerIconCoord(13, size), ScaleNativeViewerIconCoord(24, size), glyph);
        FillNativeViewerIconRect(pixels, size, ScaleNativeViewerIconCoord(13, size), ScaleNativeViewerIconCoord(8, size), ScaleNativeViewerIconCoord(22, size), ScaleNativeViewerIconCoord(11, size), glyph);
        FillNativeViewerIconRect(pixels, size, ScaleNativeViewerIconCoord(13, size), ScaleNativeViewerIconCoord(21, size), ScaleNativeViewerIconCoord(22, size), ScaleNativeViewerIconCoord(24, size), glyph);
        FillNativeViewerIconRect(pixels, size, ScaleNativeViewerIconCoord(21, size), ScaleNativeViewerIconCoord(11, size), ScaleNativeViewerIconCoord(24, size), ScaleNativeViewerIconCoord(21, size), glyph);

        const int maskStride = ((size + 15) / 16) * 2;
        std::vector<uint8_t> maskBits(static_cast<size_t>(maskStride * size), 0);
        maskBitmap = CreateBitmap(size, size, 1, 1, maskBits.data());

        if (maskBitmap == nullptr)
        {
            break;
        }

        ICONINFO iconInfo = {};
        iconInfo.fIcon = TRUE;
        iconInfo.hbmColor = colorBitmap;
        iconInfo.hbmMask = maskBitmap;
        icon = CreateIconIndirect(&iconInfo);
    }
    while (false);

    if (colorBitmap != nullptr)
    {
        DeleteObject(colorBitmap);
    }

    if (maskBitmap != nullptr)
    {
        DeleteObject(maskBitmap);
    }

    return icon;
}

void InstallNativeViewerWindowIcons(NativeViewerWindowState& state)
{
    if (state.Window == nullptr)
    {
        return;
    }

    state.Icon = CreateNativeViewerIcon(32);
    state.SmallIcon = CreateNativeViewerIcon(16);

    if (state.Icon != nullptr)
    {
        SendMessageW(state.Window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(state.Icon));
    }

    if (state.SmallIcon != nullptr)
    {
        SendMessageW(state.Window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(state.SmallIcon));
    }
}

void ApplyNativeViewerDarkFrame(HWND window)
{
    using DwmSetWindowAttributeFn = HRESULT(WINAPI*)(HWND, DWORD, LPCVOID, DWORD);

    HMODULE dwm = LoadLibraryW(L"dwmapi.dll");

    do
    {
        if (dwm == nullptr)
        {
            break;
        }

        DwmSetWindowAttributeFn setWindowAttribute = reinterpret_cast<DwmSetWindowAttributeFn>(
            GetProcAddress(dwm, "DwmSetWindowAttribute"));

        if (setWindowAttribute == nullptr)
        {
            break;
        }

        const BOOL enabled = TRUE;
        HRESULT result = setWindowAttribute(window, 20, &enabled, sizeof(enabled));

        if (FAILED(result))
        {
            setWindowAttribute(window, 19, &enabled, sizeof(enabled));
        }
    }
    while (false);

    if (dwm != nullptr)
    {
        FreeLibrary(dwm);
    }
}

void TryAttachNativeViewerInputThread(
    DWORD currentThread,
    DWORD targetThread,
    std::vector<DWORD>& attachedThreads)
{
    if (targetThread == 0 || targetThread == currentThread)
    {
        return;
    }

    if (std::find(attachedThreads.begin(), attachedThreads.end(), targetThread) != attachedThreads.end())
    {
        return;
    }

    if (AttachThreadInput(currentThread, targetThread, TRUE))
    {
        attachedThreads.push_back(targetThread);
    }
}

void DetachNativeViewerInputThreads(DWORD currentThread, const std::vector<DWORD>& attachedThreads)
{
    for (DWORD targetThread : attachedThreads)
    {
        AttachThreadInput(currentThread, targetThread, FALSE);
    }
}

void ShowNativeViewerWindowInFront(HWND window)
{
    if (window == nullptr)
    {
        return;
    }

    const DWORD currentThread = GetCurrentThreadId();
    std::vector<DWORD> attachedThreads;
    HWND owner = GetWindow(window, GW_OWNER);
    HWND foreground = GetForegroundWindow();
    DWORD ownerThread = owner != nullptr ? GetWindowThreadProcessId(owner, nullptr) : 0;
    DWORD foregroundThread = foreground != nullptr ? GetWindowThreadProcessId(foreground, nullptr) : 0;

    TryAttachNativeViewerInputThread(currentThread, ownerThread, attachedThreads);
    TryAttachNativeViewerInputThread(currentThread, foregroundThread, attachedThreads);

    ShowWindow(window, SW_SHOWNORMAL);
    SetWindowPos(
        window,
        HWND_TOPMOST,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetWindowPos(
        window,
        HWND_NOTOPMOST,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    BringWindowToTop(window);
    SetForegroundWindow(window);
    SetActiveWindow(window);
    SetFocus(window);
    UpdateWindow(window);
    DetachNativeViewerInputThreads(currentThread, attachedThreads);
}

LRESULT CALLBACK NativeViewerWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    NativeViewerWindowState* state = reinterpret_cast<NativeViewerWindowState*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    switch (message)
    {
    case WM_CREATE:
    {
        const CREATESTRUCTW* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
        state = reinterpret_cast<NativeViewerWindowState*>(create->lpCreateParams);
        state->Window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        state->BackgroundBrush = CreateSolidBrush(kNativeViewerBackgroundColor);
        state->SurfaceBrush = CreateSolidBrush(kNativeViewerSurfaceColor);
        state->SelectedBrush = CreateSolidBrush(kNativeViewerSelectedColor);
        InstallNativeViewerWindowIcons(*state);

        if (state->HistoryEntries.empty())
        {
            NativeViewerHistoryEntry entry;
            entry.Label = L"current";
            entry.SecondaryLabel = L"Current result";
            entry.WindowTitle = L"Decompile Viewer";
            entry.Text = state->Text;
            entry.RtfText = state->RtfText;
            state->HistoryEntries.push_back(std::move(entry));
        }

        std::wstring header = L"Analyzed functions";

        if (!state->HistoryEntries.empty())
        {
            header += L"  ";
            header += std::to_wstring(static_cast<unsigned long long>(state->HistoryEntries.size()));
        }

        state->HistoryHeader = CreateWindowExW(
            0,
            L"STATIC",
            header.c_str(),
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | SS_LEFT | SS_CENTERIMAGE,
            0,
            0,
            0,
            0,
            window,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(3)),
            GetModuleHandleW(nullptr),
            nullptr);

        state->HistoryList = CreateWindowExW(
            0,
            L"LISTBOX",
            L"",
            WS_CHILD
                | WS_VISIBLE
                | WS_CLIPSIBLINGS
                | WS_VSCROLL
                | LBS_NOTIFY
                | LBS_NOINTEGRALHEIGHT
                | LBS_OWNERDRAWFIXED
                | LBS_HASSTRINGS,
            0,
            0,
            0,
            0,
            window,
            reinterpret_cast<HMENU>(kNativeViewerHistoryListId),
            GetModuleHandleW(nullptr),
            nullptr);

        if (state->HistoryList != nullptr)
        {
            for (const NativeViewerHistoryEntry& entry : state->HistoryEntries)
            {
                SendMessageW(state->HistoryList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(entry.Label.c_str()));
            }

            SendMessageW(state->HistoryList, LB_SETITEMHEIGHT, 0, kNativeViewerFunctionItemHeight);
        }

        state->RichEditModule = LoadLibraryW(L"Msftedit.dll");
        const wchar_t* editClass = state->RichEditModule != nullptr ? L"RICHEDIT50W" : L"EDIT";
        const bool requestedRichEdit = state->RichEditModule != nullptr;
        const DWORD editStyle = WS_CHILD
            | WS_VISIBLE
            | WS_CLIPSIBLINGS
            | WS_VSCROLL
            | WS_HSCROLL
            | ES_MULTILINE
            | ES_READONLY
            | ES_AUTOVSCROLL
            | ES_AUTOHSCROLL;

        state->Edit = CreateWindowExW(
            0,
            editClass,
            L"",
            editStyle,
            0,
            0,
            0,
            0,
            window,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1)),
            GetModuleHandleW(nullptr),
            nullptr);
        state->SupportsEditMessages = state->Edit != nullptr;
        state->SupportsRichText = requestedRichEdit && state->Edit != nullptr;

        if (state->Edit == nullptr && state->RichEditModule != nullptr)
        {
            FreeLibrary(state->RichEditModule);
            state->RichEditModule = nullptr;
            state->Edit = CreateWindowExW(
                0,
                L"EDIT",
                L"",
                editStyle,
                0,
                0,
                0,
                0,
                window,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1)),
                GetModuleHandleW(nullptr),
                nullptr);
            state->SupportsEditMessages = state->Edit != nullptr;
            state->SupportsRichText = false;
        }

        if (state->Edit == nullptr)
        {
            state->Edit = CreateWindowExW(
                0,
                L"STATIC",
                state->Text.c_str(),
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | SS_LEFT,
                0,
                0,
                0,
                0,
                window,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1)),
                GetModuleHandleW(nullptr),
                nullptr);
            state->SupportsEditMessages = false;
            state->SupportsRichText = false;
        }

        if (state->Edit != nullptr)
        {
            InstallNativeViewerEditSubclass(*state);

            if (state->SupportsEditMessages)
            {
                SendMessageW(state->Edit, EM_SETLIMITTEXT, static_cast<WPARAM>(0x7FFFFFFE), 0);
                SendMessageW(
                    state->Edit,
                    EM_SETMARGINS,
                    EC_LEFTMARGIN | EC_RIGHTMARGIN,
                    MAKELPARAM(16, 16));
            }

            if (state->SupportsRichText)
            {
                SendMessageW(state->Edit, EM_SETBKGNDCOLOR, 0, kNativeViewerBackgroundColor);
                SendMessageW(state->Edit, EM_SETEDITSTYLE, SES_EXTENDBACKCOLOR, SES_EXTENDBACKCOLOR);
            }

            state->EditFont = CreateFontW(
                -15,
                0,
                0,
                0,
                FW_NORMAL,
                FALSE,
                FALSE,
                FALSE,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                FIXED_PITCH | FF_MODERN,
                L"Consolas");
            state->HistoryFont = CreateFontW(
                -14,
                0,
                0,
                0,
                FW_NORMAL,
                FALSE,
                FALSE,
                FALSE,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                VARIABLE_PITCH | FF_SWISS,
                L"Segoe UI");

            if (state->EditFont != nullptr)
            {
                SendMessageW(state->Edit, WM_SETFONT, reinterpret_cast<WPARAM>(state->EditFont), TRUE);
            }

            if (state->HistoryFont != nullptr && state->HistoryList != nullptr)
            {
                SendMessageW(state->HistoryList, WM_SETFONT, reinterpret_cast<WPARAM>(state->HistoryFont), TRUE);
            }

            if (state->HistoryFont != nullptr && state->HistoryHeader != nullptr)
            {
                SendMessageW(state->HistoryHeader, WM_SETFONT, reinterpret_cast<WPARAM>(state->HistoryFont), TRUE);
            }

            SetNativeViewerEntry(*state, state->ActiveHistoryIndex);

            RECT clientRect = {};
            GetClientRect(window, &clientRect);
            LayoutNativeViewerControls(*state, clientRect.right - clientRect.left, clientRect.bottom - clientRect.top);
        }

        return 0;
    }
    case WM_ERASEBKGND:
    {
        HDC deviceContext = reinterpret_cast<HDC>(wparam);
        RECT clientRect = {};
        GetClientRect(window, &clientRect);

        HBRUSH brush = state != nullptr && state->BackgroundBrush != nullptr
            ? state->BackgroundBrush
            : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));

        FillRect(deviceContext, &clientRect, brush);
        return 1;
    }
    case WM_CTLCOLORLISTBOX:
    {
        HDC deviceContext = reinterpret_cast<HDC>(wparam);
        SetTextColor(deviceContext, kNativeViewerTextColor);
        SetBkColor(deviceContext, kNativeViewerSurfaceColor);

        if (state != nullptr && state->SurfaceBrush != nullptr)
        {
            return reinterpret_cast<LRESULT>(state->SurfaceBrush);
        }

        return reinterpret_cast<LRESULT>(GetStockObject(BLACK_BRUSH));
    }
    case WM_MEASUREITEM:
    {
        MEASUREITEMSTRUCT* measure = reinterpret_cast<MEASUREITEMSTRUCT*>(lparam);

        if (measure != nullptr && measure->CtlID == kNativeViewerHistoryListId)
        {
            measure->itemHeight = kNativeViewerFunctionItemHeight;
            return TRUE;
        }

        break;
    }
    case WM_DRAWITEM:
    {
        const DRAWITEMSTRUCT* draw = reinterpret_cast<const DRAWITEMSTRUCT*>(lparam);

        if (state != nullptr
            && draw != nullptr
            && draw->CtlID == kNativeViewerHistoryListId
            && draw->itemID != static_cast<UINT>(-1)
            && draw->itemID < state->HistoryEntries.size())
        {
            const bool selected = (draw->itemState & ODS_SELECTED) != 0;
            HBRUSH brush = selected && state->SelectedBrush != nullptr
                ? state->SelectedBrush
                : state->SurfaceBrush;

            if (brush == nullptr)
            {
                brush = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
            }

            FillRect(draw->hDC, &draw->rcItem, brush);
            SetBkMode(draw->hDC, TRANSPARENT);
            SetTextColor(draw->hDC, selected ? RGB(255, 255, 255) : kNativeViewerTextColor);

            RECT primary = draw->rcItem;
            primary.left += 12;
            primary.right -= 10;
            primary.top += 7;
            primary.bottom = primary.top + 20;
            DrawTextW(
                draw->hDC,
                state->HistoryEntries[draw->itemID].Label.c_str(),
                -1,
                &primary,
                DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

            SetTextColor(draw->hDC, selected ? RGB(220, 235, 255) : kNativeViewerMutedTextColor);

            RECT secondary = draw->rcItem;
            secondary.left += 12;
            secondary.right -= 10;
            secondary.top += 28;
            secondary.bottom -= 4;
            DrawTextW(
                draw->hDC,
                state->HistoryEntries[draw->itemID].SecondaryLabel.c_str(),
                -1,
                &secondary,
                DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

            return TRUE;
        }

        break;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    {
        HDC deviceContext = reinterpret_cast<HDC>(wparam);
        HWND control = reinterpret_cast<HWND>(lparam);
        const bool isHistoryList = state != nullptr && control == state->HistoryList;
        SetTextColor(deviceContext, kNativeViewerTextColor);
        SetBkColor(deviceContext, isHistoryList ? kNativeViewerSurfaceColor : kNativeViewerBackgroundColor);

        if (state != nullptr)
        {
            HBRUSH brush = isHistoryList ? state->SurfaceBrush : state->BackgroundBrush;

            if (brush != nullptr)
            {
                return reinterpret_cast<LRESULT>(brush);
            }
        }

        return reinterpret_cast<LRESULT>(GetStockObject(BLACK_BRUSH));
    }
    case WM_SIZE:
    {
        if (state != nullptr)
        {
            LayoutNativeViewerControls(*state, LOWORD(lparam), HIWORD(lparam));
        }

        return 0;
    }
    case WM_COMMAND:
    {
        if (state != nullptr
            && LOWORD(wparam) == kNativeViewerHistoryListId
            && HIWORD(wparam) == LBN_SELCHANGE
            && state->HistoryList != nullptr)
        {
            const LRESULT selected = SendMessageW(state->HistoryList, LB_GETCURSEL, 0, 0);

            if (selected >= 0)
            {
                SetNativeViewerEntry(*state, static_cast<size_t>(selected));
            }

            return 0;
        }

        break;
    }
    case WM_SETFOCUS:
    {
        if (state != nullptr && state->Edit != nullptr)
        {
            SetFocus(state->Edit);
        }

        return 0;
    }
    case WM_CLOSE:
    {
        DestroyWindow(window);
        return 0;
    }
    case WM_DESTROY:
    {
        PostQuitMessage(0);
        return 0;
    }
    case WM_NCDESTROY:
    {
        if (state != nullptr)
        {
            if (state->Edit != nullptr && IsWindow(state->Edit))
            {
                if (state->OriginalEditProc != nullptr)
                {
                    SetWindowLongPtrW(state->Edit, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(state->OriginalEditProc));
                }

                SetWindowLongPtrW(state->Edit, GWLP_USERDATA, 0);
            }

            state->OriginalEditProc = nullptr;

            if (state->EditFont != nullptr)
            {
                DeleteObject(state->EditFont);
                state->EditFont = nullptr;
            }

            if (state->HistoryFont != nullptr)
            {
                DeleteObject(state->HistoryFont);
                state->HistoryFont = nullptr;
            }

            if (state->BackgroundBrush != nullptr)
            {
                DeleteObject(state->BackgroundBrush);
                state->BackgroundBrush = nullptr;
            }

            if (state->SurfaceBrush != nullptr)
            {
                DeleteObject(state->SurfaceBrush);
                state->SurfaceBrush = nullptr;
            }

            if (state->SelectedBrush != nullptr)
            {
                DeleteObject(state->SelectedBrush);
                state->SelectedBrush = nullptr;
            }

            if (state->Icon != nullptr)
            {
                DestroyIcon(state->Icon);
                state->Icon = nullptr;
            }

            if (state->SmallIcon != nullptr)
            {
                DestroyIcon(state->SmallIcon);
                state->SmallIcon = nullptr;
            }

            if (state->RichEditModule != nullptr)
            {
                FreeLibrary(state->RichEditModule);
                state->RichEditModule = nullptr;
            }

            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            delete state;
        }

        return 0;
    }
    default:
        break;
    }

    return DefWindowProcW(window, message, wparam, lparam);
}

bool PinNativeViewerModule(HMODULE& module, std::string& error)
{
    bool success = false;
    module = nullptr;

    do
    {
        if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(&NativeViewerWindowProc),
            &module))
        {
            error = "failed to pin native viewer module: " + FormatWin32Error(GetLastError());
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool RegisterNativeViewerWindowClass(HMODULE module, std::string& error)
{
    bool success = false;

    do
    {
        HMODULE instance = module;

        if (instance == nullptr)
        {
            instance = GetModuleHandleW(nullptr);
        }

        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.style = CS_HREDRAW | CS_VREDRAW;
        windowClass.lpfnWndProc = NativeViewerWindowProc;
        windowClass.hInstance = instance;
        windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hIconSm = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        windowClass.lpszClassName = kNativeViewerWindowClass;

        if (RegisterClassExW(&windowClass) == 0)
        {
            const DWORD registerError = GetLastError();

            if (registerError != ERROR_CLASS_ALREADY_EXISTS)
            {
                error = "failed to register native viewer window class: " + FormatWin32Error(registerError);
                break;
            }
        }

        success = true;
    }
    while (false);

    return success;
}

struct DebuggerOwnerWindowSearch
{
    HWND First = nullptr;
    HWND Preferred = nullptr;
};

BOOL CALLBACK FindDebuggerOwnerWindowProc(HWND window, LPARAM parameter)
{
    DebuggerOwnerWindowSearch* search = reinterpret_cast<DebuggerOwnerWindowSearch*>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);

    if (processId != GetCurrentProcessId())
    {
        return TRUE;
    }

    if (!IsWindowVisible(window) || GetWindow(window, GW_OWNER) != nullptr)
    {
        return TRUE;
    }

    std::array<wchar_t, 128> className = {};
    GetClassNameW(window, className.data(), static_cast<int>(className.size()));

    if (std::wstring(className.data()) == kNativeViewerWindowClass)
    {
        return TRUE;
    }

    std::array<wchar_t, 256> title = {};
    GetWindowTextW(window, title.data(), static_cast<int>(title.size()));

    if (title[0] == L'\0')
    {
        return TRUE;
    }

    if (search->First == nullptr)
    {
        search->First = window;
    }

    const std::wstring titleText = title.data();

    if (titleText.find(L"WinDbg") != std::wstring::npos
        || titleText.find(L"Windows Debugger") != std::wstring::npos
        || titleText.find(L"Debugger") != std::wstring::npos)
    {
        search->Preferred = window;
        return FALSE;
    }

    return TRUE;
}

HWND FindDebuggerOwnerWindow()
{
    DebuggerOwnerWindowSearch search;
    EnumWindows(FindDebuggerOwnerWindowProc, reinterpret_cast<LPARAM>(&search));
    return search.Preferred != nullptr ? search.Preferred : search.First;
}

void SignalNativeViewerLaunch(
    const std::shared_ptr<NativeViewerLaunchSync>& sync,
    bool success,
    HWND window,
    HWND owner,
    const std::string& error)
{
    if (!sync)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(sync->Mutex);
        sync->Success = success;
        sync->WindowHandle = window;
        sync->OwnerHandle = owner;
        sync->Error = error;

        if (sync->ReadyEvent != nullptr)
        {
            SetEvent(sync->ReadyEvent);
        }
    }
}

bool TrySignalNativeViewerLaunchSuccess(
    const std::shared_ptr<NativeViewerLaunchSync>& sync,
    HWND window,
    HWND owner)
{
    bool success = false;

    do
    {
        if (!sync)
        {
            break;
        }

        std::lock_guard<std::mutex> lock(sync->Mutex);

        if (sync->Abandoned)
        {
            break;
        }

        sync->Success = true;
        sync->WindowHandle = window;
        sync->OwnerHandle = owner;
        sync->Error.clear();

        if (sync->ReadyEvent != nullptr)
        {
            SetEvent(sync->ReadyEvent);
        }

        success = true;
    }
    while (false);

    return success;
}

void NativeViewerThreadMain(NativeViewerThreadContext* rawContext)
{
    HMODULE module = rawContext != nullptr ? rawContext->Module : nullptr;

    {
        std::unique_ptr<NativeViewerThreadContext> context(rawContext);
        std::unique_ptr<NativeViewerWindowState> state(context != nullptr ? context->State : nullptr);
        std::string error;
        HWND window = nullptr;
        bool enteredMessageLoop = false;

        do
        {
            if (context == nullptr || context->Sync == nullptr || state == nullptr)
            {
                error = "native viewer thread context is invalid";
                break;
            }

            if (!RegisterNativeViewerWindowClass(module, error))
            {
                break;
            }

            const DWORD exStyle = WS_EX_WINDOWEDGE | (context->Owner != nullptr ? 0 : WS_EX_APPWINDOW);
            window = CreateWindowExW(
                exStyle,
                kNativeViewerWindowClass,
                state->Title.c_str(),
                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                980,
                720,
                context->Owner,
                nullptr,
                module != nullptr ? module : GetModuleHandleW(nullptr),
                state.get());

            if (window == nullptr)
            {
                error = "failed to create native viewer window: " + FormatWin32Error(GetLastError());
                break;
            }

            ApplyNativeViewerDarkFrame(window);
            state.release();

            if (!TrySignalNativeViewerLaunchSuccess(context->Sync, window, context->Owner))
            {
                DestroyWindow(window);
                window = nullptr;
                error = "native viewer launch was abandoned";
                break;
            }

            ShowNativeViewerWindowInFront(window);

            MSG message = {};
            enteredMessageLoop = true;

            while (GetMessageW(&message, nullptr, 0, 0) > 0)
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        while (false);

        if (!enteredMessageLoop)
        {
            if (window != nullptr)
            {
                DestroyWindow(window);
                window = nullptr;
            }

            SignalNativeViewerLaunch(
                context != nullptr ? context->Sync : nullptr,
                false,
                nullptr,
                context != nullptr ? context->Owner : nullptr,
                error.empty() ? std::string("failed to open native viewer") : error);
        }
    }

    if (module != nullptr)
    {
        UnregisterClassW(kNativeViewerWindowClass, module);
        FreeLibraryAndExitThread(module, 0);
    }
}

std::string BuildNativeViewerDisplayTarget(const std::string& module, const std::string& target)
{
    if (target.empty())
    {
        return module.empty() ? std::string("<unknown>") : module;
    }

    if (target.find('!') != std::string::npos || module.empty())
    {
        return target;
    }

    return module + "!" + target;
}

std::string BuildNativeViewerWindowTitle(const std::string& displayTarget)
{
    return "Decompile Viewer - " + displayTarget;
}

std::string BuildNativeViewerRequestIdentity(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response)
{
    if (!request.RequestId.empty())
    {
        return "request:" + request.RequestId;
    }

    const uint64_t stableOffset = request.Facts.Module.Base != 0 && request.Facts.EntryAddress >= request.Facts.Module.Base
        ? request.Facts.EntryAddress - request.Facts.Module.Base
        : request.Facts.EntryAddress;

    return decomp::ToLowerAscii(request.Facts.Module.ModuleName)
        + "|"
        + decomp::HexU64(stableOffset)
        + "|"
        + decomp::ToLowerAscii(request.Facts.QueryText)
        + "|"
        + decomp::ToLowerAscii(response.Provider);
}

std::string BuildNativeViewerArtifactIdentity(const CachedAnalyzeArtifact& artifact)
{
    if (!artifact.RequestId.empty())
    {
        return "request:" + artifact.RequestId;
    }

    const uint64_t stableOffset = artifact.HasEntryRva ? artifact.EntryRva : artifact.EntryAddress;

    return decomp::ToLowerAscii(artifact.Module)
        + "|"
        + decomp::HexU64(stableOffset)
        + "|"
        + decomp::ToLowerAscii(artifact.Target)
        + "|"
        + decomp::ToLowerAscii(artifact.Provider);
}

std::string BuildNativeViewerEntrySecondaryLabel(
    const CachedAnalyzeArtifact& artifact,
    bool current)
{
    std::vector<std::string> parts;

    if (current)
    {
        parts.push_back("current");
    }
    else if (!artifact.Timestamp.empty())
    {
        parts.push_back(artifact.Timestamp);
    }

    if (artifact.EntryAddress != 0)
    {
        parts.push_back(decomp::HexU64(artifact.EntryAddress));
    }

    if (artifact.Confidence > 0.0)
    {
        std::array<char, 32> confidence = {};
        std::snprintf(confidence.data(), confidence.size(), "confidence %.2f", artifact.Confidence);
        parts.push_back(confidence.data());
    }

    if (artifact.VerifierIssueCount != 0)
    {
        parts.push_back("issues " + std::to_string(static_cast<unsigned long long>(artifact.VerifierIssueCount)));
    }

    return decomp::JoinStrings(parts, "  ");
}

KernelBuildFacts ResolveNativeViewerCurrentKernelBuild(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response)
{
    KernelBuildFacts facts;
    const std::string currentIdentity = BuildNativeViewerRequestIdentity(request, response);

    for (const CachedAnalyzeArtifact& artifact : g_analyzeHistory)
    {
        if (BuildNativeViewerArtifactIdentity(artifact) == currentIdentity)
        {
            facts = artifact.KernelBuild;
            break;
        }
    }

    return facts;
}

bool NativeViewerArtifactMatchesKernelBuild(
    const CachedAnalyzeArtifact& artifact,
    const KernelBuildFacts& current)
{
    bool matches = false;

    do
    {
        if (current.Fingerprint.empty() || artifact.KernelBuild.Fingerprint.empty())
        {
            break;
        }

        if (EqualInsensitiveString(artifact.KernelBuild.Fingerprint, current.Fingerprint))
        {
            matches = true;
            break;
        }

        if (KernelBuildsAreCompatible(artifact.KernelBuild, current))
        {
            matches = true;
            break;
        }
    }
    while (false);

    return matches;
}

std::vector<std::string> EnumerateNativeViewerArtifactPaths(const KernelBuildFacts& current)
{
    std::vector<std::string> paths;

    do
    {
        if (current.Fingerprint.empty())
        {
            break;
        }

        const std::string directory = JoinPath(BuildDefaultArtifactDirectory(), BuildArtifactBuildKey(current));
        const std::string pattern = JoinPath(directory, "*.decomp.json");
        WIN32_FIND_DATAA data = {};
        HANDLE find = FindFirstFileA(pattern.c_str(), &data);

        if (find == INVALID_HANDLE_VALUE)
        {
            break;
        }

        do
        {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                continue;
            }

            paths.push_back(JoinPath(directory, data.cFileName));
        }
        while (FindNextFileA(find, &data) != FALSE);

        FindClose(find);
        std::sort(paths.begin(), paths.end());
    }
    while (false);

    return paths;
}

bool BuildNativeViewerHistoryEntry(
    const std::string& label,
    const std::string& secondaryLabel,
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& displayConfig,
    const decomp::DecompOptions& options,
    uint32_t cacheIndex,
    NativeViewerHistoryEntry& entry,
    std::string& error)
{
    bool success = false;

    do
    {
        PlainTextResponseOutputSink sink(cacheIndex != 0);
        decomp::DecompOptions renderOptions = options;
        renderOptions.WindowOutput = false;

        if (cacheIndex != 0)
        {
            renderOptions.LastCacheIndex = cacheIndex;
        }

        RenderResponse(request, response, displayConfig, sink, renderOptions);

        entry.Label = Utf8ToWide(label);
        entry.SecondaryLabel = Utf8ToWide(secondaryLabel);
        entry.WindowTitle = Utf8ToWide(BuildNativeViewerWindowTitle(label));
        entry.Text = Utf8ToWide(sink.GetText());
        entry.RtfText = BuildPrettyViewerRtf(request, sink.GetText());

        if (entry.Label.empty() && !label.empty())
        {
            error = "failed to convert viewer history label to UTF-16";
            break;
        }

        if (entry.SecondaryLabel.empty() && !secondaryLabel.empty())
        {
            error = "failed to convert viewer history detail to UTF-16";
            break;
        }

        if (entry.Text.empty() && !sink.GetText().empty())
        {
            error = "failed to convert viewer text to UTF-16";
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

std::string BuildNativeViewerCurrentLabel(const decomp::AnalyzeRequest& request)
{
    return BuildNativeViewerDisplayTarget(request.Facts.Module.ModuleName, request.Facts.QueryText);
}

std::string BuildNativeViewerCurrentSecondaryLabel(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response)
{
    std::vector<std::string> parts;
    parts.push_back("current");

    if (request.Facts.EntryAddress != 0)
    {
        parts.push_back(decomp::HexU64(request.Facts.EntryAddress));
    }

    if (response.Verifier.AdjustedConfidence > 0.0)
    {
        std::array<char, 32> confidence = {};
        std::snprintf(confidence.data(), confidence.size(), "confidence %.2f", response.Verifier.AdjustedConfidence);
        parts.push_back(confidence.data());
    }

    if (!response.Provider.empty())
    {
        parts.push_back(response.Provider);
    }

    return decomp::JoinStrings(parts, "  ");
}

std::string BuildNativeViewerArtifactLabel(const CachedAnalyzeArtifact& artifact)
{
    return BuildNativeViewerDisplayTarget(artifact.Module, artifact.Target);
}

std::vector<NativeViewerHistoryEntry> BuildNativeViewerHistoryEntries(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& displayConfig,
    const decomp::DecompOptions& options,
    std::string& error)
{
    std::vector<NativeViewerHistoryEntry> entries;
    NativeViewerHistoryEntry currentEntry;
    const KernelBuildFacts currentKernelBuild = ResolveNativeViewerCurrentKernelBuild(request, response);
    std::set<std::string> identities;
    const std::string currentIdentity = BuildNativeViewerRequestIdentity(request, response);
    const uint32_t currentCacheIndex = options.LastCacheIndex == 0 ? 1 : options.LastCacheIndex;

    if (!BuildNativeViewerHistoryEntry(
        BuildNativeViewerCurrentLabel(request),
        BuildNativeViewerCurrentSecondaryLabel(request, response),
        request,
        response,
        displayConfig,
        options,
        currentCacheIndex,
        currentEntry,
        error))
    {
        return entries;
    }

    entries.push_back(std::move(currentEntry));
    identities.insert(currentIdentity);

    for (size_t index = 0; index < g_analyzeHistory.size(); ++index)
    {
        const CachedAnalyzeArtifact& artifact = g_analyzeHistory[index];
        const std::string identity = BuildNativeViewerArtifactIdentity(artifact);

        if (identities.find(identity) != identities.end())
        {
            continue;
        }

        if (!NativeViewerArtifactMatchesKernelBuild(artifact, currentKernelBuild))
        {
            continue;
        }

        decomp::AnalyzeRequest cachedRequest;
        decomp::AnalyzeResponse cachedResponse;
        std::string parseError;

        if (!decomp::ParseAnalyzeRequest(artifact.RequestJson, cachedRequest, parseError))
        {
            continue;
        }

        if (!decomp::ParseAnalyzeResponse(artifact.ResponseJson, cachedResponse, parseError))
        {
            continue;
        }

        NativeViewerHistoryEntry entry;

        if (BuildNativeViewerHistoryEntry(
            BuildNativeViewerArtifactLabel(artifact),
            BuildNativeViewerEntrySecondaryLabel(artifact, false),
            cachedRequest,
            cachedResponse,
            displayConfig,
            options,
            static_cast<uint32_t>(index + 1),
            entry,
            parseError))
        {
            entries.push_back(std::move(entry));
            identities.insert(identity);
        }
    }

    for (const std::string& path : EnumerateNativeViewerArtifactPaths(currentKernelBuild))
    {
        CachedAnalyzeArtifact artifact;
        std::string parseError;

        if (!LoadCachedAnalyzeArtifact(path, artifact, parseError))
        {
            continue;
        }

        if (!NativeViewerArtifactMatchesKernelBuild(artifact, currentKernelBuild))
        {
            continue;
        }

        const std::string identity = BuildNativeViewerArtifactIdentity(artifact);

        if (identities.find(identity) != identities.end())
        {
            continue;
        }

        decomp::AnalyzeRequest cachedRequest;
        decomp::AnalyzeResponse cachedResponse;

        if (!decomp::ParseAnalyzeRequest(artifact.RequestJson, cachedRequest, parseError))
        {
            continue;
        }

        if (!decomp::ParseAnalyzeResponse(artifact.ResponseJson, cachedResponse, parseError))
        {
            continue;
        }

        NativeViewerHistoryEntry entry;

        if (BuildNativeViewerHistoryEntry(
            BuildNativeViewerArtifactLabel(artifact),
            BuildNativeViewerEntrySecondaryLabel(artifact, false),
            cachedRequest,
            cachedResponse,
            displayConfig,
            options,
            0,
            entry,
            parseError))
        {
            entries.push_back(std::move(entry));
            identities.insert(identity);
        }
    }

    return entries;
}

bool TryAppendNativeViewerArtifactEntry(
    const CachedAnalyzeArtifact& artifact,
    const decomp::LlmClientConfig& displayConfig,
    const decomp::DecompOptions& options,
    uint32_t cacheIndex,
    std::set<std::string>& identities,
    std::vector<NativeViewerHistoryEntry>& entries)
{
    bool success = false;

    do
    {
        const std::string identity = BuildNativeViewerArtifactIdentity(artifact);

        if (identities.find(identity) != identities.end())
        {
            break;
        }

        decomp::AnalyzeRequest cachedRequest;
        decomp::AnalyzeResponse cachedResponse;
        std::string parseError;

        if (!decomp::ParseAnalyzeRequest(artifact.RequestJson, cachedRequest, parseError))
        {
            break;
        }

        if (!decomp::ParseAnalyzeResponse(artifact.ResponseJson, cachedResponse, parseError))
        {
            break;
        }

        NativeViewerHistoryEntry entry;

        if (!BuildNativeViewerHistoryEntry(
                BuildNativeViewerArtifactLabel(artifact),
                BuildNativeViewerEntrySecondaryLabel(artifact, false),
                cachedRequest,
                cachedResponse,
                displayConfig,
                options,
                cacheIndex,
                entry,
                parseError))
        {
            break;
        }

        entries.push_back(std::move(entry));
        identities.insert(identity);
        success = true;
    }
    while (false);

    return success;
}

std::vector<NativeViewerHistoryEntry> BuildNativeViewerCachedHistoryEntries(
    const KernelBuildFacts& currentKernelBuild,
    const decomp::LlmClientConfig& displayConfig,
    const decomp::DecompOptions& options)
{
    std::vector<NativeViewerHistoryEntry> entries;
    std::set<std::string> identities;
    const bool hasKernelBuild = !currentKernelBuild.Fingerprint.empty();

    for (size_t index = 0; index < g_analyzeHistory.size(); ++index)
    {
        const CachedAnalyzeArtifact& artifact = g_analyzeHistory[index];

        if (hasKernelBuild && !NativeViewerArtifactMatchesKernelBuild(artifact, currentKernelBuild))
        {
            continue;
        }

        TryAppendNativeViewerArtifactEntry(
            artifact,
            displayConfig,
            options,
            static_cast<uint32_t>(index + 1),
            identities,
            entries);
    }

    if (hasKernelBuild)
    {
        for (const std::string& path : EnumerateNativeViewerArtifactPaths(currentKernelBuild))
        {
            CachedAnalyzeArtifact artifact;
            std::string loadError;

            if (!LoadCachedAnalyzeArtifact(path, artifact, loadError))
            {
                continue;
            }

            if (!NativeViewerArtifactMatchesKernelBuild(artifact, currentKernelBuild))
            {
                continue;
            }

            TryAppendNativeViewerArtifactEntry(
                artifact,
                displayConfig,
                options,
                0,
                identities,
                entries);
        }
    }

    return entries;
}

std::string FormatWindowHandle(HWND window)
{
    return decomp::HexU64(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(window)));
}

bool OpenNativeViewerEntries(
    std::vector<NativeViewerHistoryEntry> historyEntries,
    const std::wstring& fallbackTitle,
    std::string& viewerDescription,
    std::string& error)
{
    bool success = false;
    std::shared_ptr<NativeViewerLaunchSync> sync = std::make_shared<NativeViewerLaunchSync>();
    HMODULE module = nullptr;
    size_t viewerHistoryCount = 0;

    do
    {
        if (historyEntries.empty())
        {
            if (error.empty())
            {
                error = "no cached !decomp results are available for the native viewer";
            }

            break;
        }

        sync->ReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        if (sync->ReadyEvent == nullptr)
        {
            error = "failed to create native viewer launch event: " + FormatWin32Error(GetLastError());
            break;
        }

        std::unique_ptr<NativeViewerWindowState> state = std::make_unique<NativeViewerWindowState>();
        viewerHistoryCount = historyEntries.size();
        state->HistoryEntries = std::move(historyEntries);
        state->Title = !state->HistoryEntries.front().WindowTitle.empty()
            ? state->HistoryEntries.front().WindowTitle
            : fallbackTitle;
        state->Text = state->HistoryEntries.front().Text;
        state->RtfText = state->HistoryEntries.front().RtfText;

        std::unique_ptr<NativeViewerThreadContext> context = std::make_unique<NativeViewerThreadContext>();
        context->State = state.release();
        context->Sync = sync;
        context->Owner = FindDebuggerOwnerWindow();

        if (!PinNativeViewerModule(module, error))
        {
            delete context->State;
            context->State = nullptr;
            break;
        }

        context->Module = module;

        try
        {
            std::thread viewerThread(NativeViewerThreadMain, context.get());
            context.release();
            viewerThread.detach();
            module = nullptr;
        }
        catch (const std::exception& ex)
        {
            delete context->State;
            context->State = nullptr;
            error = std::string("failed to start native viewer thread: ") + ex.what();
            break;
        }
        catch (...)
        {
            delete context->State;
            context->State = nullptr;
            error = "failed to start native viewer thread";
            break;
        }

        const DWORD waitResult = WaitForSingleObject(sync->ReadyEvent, kNativeViewerLaunchTimeoutMs);

        if (waitResult != WAIT_OBJECT_0)
        {
            {
                std::lock_guard<std::mutex> lock(sync->Mutex);
                sync->Abandoned = true;
            }

            if (waitResult == WAIT_TIMEOUT)
            {
                error = "native viewer launch timed out";
            }
            else
            {
                error = "failed to wait for native viewer launch: " + FormatWin32Error(GetLastError());
            }

            break;
        }

        bool launchSuccess = false;
        HWND windowHandle = nullptr;
        HWND ownerHandle = nullptr;
        std::string launchError;

        {
            std::lock_guard<std::mutex> lock(sync->Mutex);
            launchSuccess = sync->Success;
            windowHandle = sync->WindowHandle;
            ownerHandle = sync->OwnerHandle;
            launchError = sync->Error;
        }

        if (!launchSuccess)
        {
            error = launchError.empty() ? std::string("failed to open native viewer") : launchError;
            break;
        }

        viewerDescription = "hwnd=" + FormatWindowHandle(windowHandle);

        if (viewerHistoryCount > 1)
        {
            viewerDescription += " functions=" + std::to_string(static_cast<unsigned long long>(viewerHistoryCount));
        }

        if (ownerHandle != nullptr)
        {
            viewerDescription += " owner=" + FormatWindowHandle(ownerHandle);
        }

        success = true;
    }
    while (false);

    if (module != nullptr)
    {
        FreeLibrary(module);
        module = nullptr;
    }

    return success;
}

bool OpenResponseViewer(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& displayConfig,
    const decomp::DecompOptions& options,
    std::string& viewerDescription,
    std::string& error)
{
    std::vector<NativeViewerHistoryEntry> historyEntries = BuildNativeViewerHistoryEntries(
        request,
        response,
        displayConfig,
        options,
        error);

    return OpenNativeViewerEntries(
        std::move(historyEntries),
        Utf8ToWide(BuildNativeViewerWindowTitle(BuildNativeViewerCurrentLabel(request))),
        viewerDescription,
        error);
}

bool OpenAnalyzeHistoryViewer(
    const DebugApi& api,
    const decomp::DecompOptions& options,
    std::string& viewerDescription,
    std::string& error)
{
    decomp::LlmClientConfig displayConfig;
    std::string displayConfigError;
    decomp::LoadLlmClientConfig(displayConfig, displayConfigError, false);

    const KernelBuildFacts kernelBuild = CollectKernelBuildFacts(
        api.Control.Get(),
        api.Control4.Get(),
        api.DataSpaces.Get());
    std::vector<NativeViewerHistoryEntry> historyEntries = BuildNativeViewerCachedHistoryEntries(
        kernelBuild,
        displayConfig,
        options);

    if (historyEntries.empty())
    {
        if (kernelBuild.Fingerprint.empty())
        {
            error = "no cached !decomp results are available and current kernel_build fingerprint is unavailable";
        }
        else
        {
            error = "no cached !decomp results are available for the current kernel_build";
        }

        return false;
    }

    return OpenNativeViewerEntries(
        std::move(historyEntries),
        L"Decompile Viewer - Analyzed functions",
        viewerDescription,
        error);
}

void PrintResponse(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& displayConfig,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2,
    const decomp::DecompOptions& options)
{
    ConsoleResponseOutputSink consoleSink(control, control4, advanced2);

    if (options.JsonOutput || options.FactsOnlyOutput || options.DataModelOutput)
    {
        RenderResponse(request, response, displayConfig, consoleSink, options);
        return;
    }

    if (options.WindowOutput)
    {
        std::string viewerDescription;
        std::string error;

        if (OpenResponseViewer(request, response, displayConfig, options, viewerDescription, error))
        {
            OutputLine(control, control4, "decomp native viewer opened: %s\n", viewerDescription.c_str());
            return;
        }

        OutputLine(control, control4, "warning: decomp native viewer failed: %s\n", error.c_str());
        OutputLine(control, control4, "warning: falling back to console output\n");
    }

    RenderResponse(request, response, displayConfig, consoleSink, options);
}

bool PrintCachedAnalyzeResult(
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2,
    decomp::DecompOptions options,
    std::string& error)
{
    const CachedAnalyzeArtifact* artifact = GetCachedAnalyzeArtifact(options.LastCacheIndex);

    if (artifact == nullptr)
    {
        error = "no cached !decomp result at history index " + std::to_string(options.LastCacheIndex);
        return false;
    }

    decomp::AnalyzeRequest cachedRequest;
    decomp::AnalyzeResponse cachedResponse;

    if (!decomp::ParseAnalyzeRequest(artifact->RequestJson, cachedRequest, error))
    {
        error = "failed to parse cached request: " + error;
        return false;
    }

    if (!decomp::ParseAnalyzeResponse(artifact->ResponseJson, cachedResponse, error))
    {
        error = "failed to parse cached response: " + error;
        return false;
    }

    decomp::LlmClientConfig displayConfig;
    std::string displayConfigError;

    decomp::LoadLlmClientConfig(displayConfig, displayConfigError, false);

    if (options.LastExplainOutput)
    {
        options.ExplainOutput = true;
    }
    if (options.LastFactsOutput)
    {
        options.FactsOnlyOutput = true;
    }

    options.LastExplainOutput = false;
    options.LastFactsOutput = false;

    PrintResponse(cachedRequest, cachedResponse, displayConfig, control, control4, advanced2, options);
    return true;
}

bool ShouldTryPersistentArtifactReplay(const decomp::DecompOptions& options)
{
    if (options.PlanOutput)
    {
        return false;
    }

    if (options.DisableLlm)
    {
        return false;
    }

    if (options.ClearUserOverrides
        || !options.NoReturnOverrides.empty()
        || !options.TypeOverrides.empty()
        || !options.FieldOverrides.empty()
        || !options.RenameOverrides.empty())
    {
        return false;
    }

    if (options.MaxInstructions != 4096)
    {
        return false;
    }

    return true;
}

bool PrintPersistentAnalyzeArtifact(
    const DebugApi& api,
    decomp::DecompOptions options,
    const CachedAnalyzeArtifact& artifact,
    std::string& error)
{
    if (options.DebugPromptOutput)
    {
        OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n", artifact.DebugPromptDump.c_str());
        return true;
    }

    decomp::AnalyzeRequest cachedRequest;
    decomp::AnalyzeResponse cachedResponse;

    if (!decomp::ParseAnalyzeRequest(artifact.RequestJson, cachedRequest, error))
    {
        error = "failed to parse artifact request: " + error;
        return false;
    }

    if (!decomp::ParseAnalyzeResponse(artifact.ResponseJson, cachedResponse, error))
    {
        error = "failed to parse artifact response: " + error;
        return false;
    }

    decomp::LlmClientConfig displayConfig;
    std::string displayConfigError;
    decomp::LoadLlmClientConfig(displayConfig, displayConfigError, false);
    PrintResponse(cachedRequest, cachedResponse, displayConfig, api.Control.Get(), api.Control4.Get(), api.Advanced2.Get(), options);
    return true;
}

bool TryReplayPersistentAnalyzeArtifact(
    const DebugApi& api,
    const decomp::DecompOptions& options,
    const KernelBuildFacts& currentKernelBuild,
    const CachedAnalyzeArtifact& lookup,
    std::string& error)
{
    if (!ShouldTryPersistentArtifactReplay(options))
    {
        return false;
    }

    if (currentKernelBuild.Fingerprint.empty())
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact replay skipped: current kernel_build unavailable");
        return false;
    }

    const std::string path = BuildDefaultArtifactPath(lookup);

    if (!decomp::PathExistsAsFile(path))
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact miss path=%s", path.c_str());
        return false;
    }

    CachedAnalyzeArtifact artifact;
    std::string loadError;

    if (!LoadCachedAnalyzeArtifact(path, artifact, loadError))
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact load skipped path=%s error=%s", path.c_str(), loadError.c_str());
        return false;
    }

    std::string warning;
    std::string validateError;

    if (!ValidateLoadedArtifactKernelBuild(artifact, currentKernelBuild, warning, validateError))
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact replay skipped path=%s error=%s", path.c_str(), validateError.c_str());
        return false;
    }

    if (!warning.empty())
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact replay warning path=%s warning=%s", path.c_str(), warning.c_str());
    }

    artifact.ArtifactPath = path;
    RememberCachedAnalyzeArtifact(artifact);
    OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact hit path=%s", path.c_str());
    return PrintPersistentAnalyzeArtifact(api, options, artifact, error);
}

void TrySavePersistentAnalyzeArtifact(
    const DebugApi& api,
    const decomp::DecompOptions& options,
    const CachedAnalyzeArtifact& artifact)
{
    if (artifact.KernelBuild.Fingerprint.empty())
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact save skipped: kernel_build unavailable");
        return;
    }

    std::string actualPath;
    std::string saveError;

    if (!SaveCachedAnalyzeArtifact(artifact, std::string(), actualPath, saveError))
    {
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact save failed: %s", saveError.c_str());
        return;
    }

    OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "artifact saved path=%s", actualPath.c_str());
}

struct DecompCommandContext
{
    DebugApi Api;
    decomp::DecompOptions Options;
    std::string Target;
    std::string Error;
    uint64_t QueryAddress = 0;
    uint64_t EntryAddress = 0;
    decomp::ModuleInfo ModuleInfo;
    std::vector<decomp::FunctionRegion> Regions;
    std::vector<FunctionRegionBytes> RegionBytes;
    std::vector<uint8_t> Bytes;
    std::vector<decomp::DisassembledInstruction> Instructions;
    std::vector<DecodedInstructionContext> DecodedContexts;
    decomp::AnalyzeRequest Request;
    decomp::AnalyzeResponse Response;
    decomp::LlmClientConfig DisplayConfig;
};

HRESULT ResolveCommandTarget(DecompCommandContext& context)
{
    if (!ResolveTargetAddress(context.Api.Symbols.Get(), context.Target, context.QueryAddress))
    {
        OutputLine(context.Api.Control.Get(), context.Api.Control4.Get(), "error: could not resolve target %s\n", context.Target.c_str());
        return E_FAIL;
    }

    OutputVerbose(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "resolved target address=%s", decomp::HexU64(context.QueryAddress).c_str());

    if (AbortIfUserInterrupted(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "target resolution"))
    {
        return E_ABORT;
    }

    CollectModuleInfo(context.Api.Symbols.Get(), context.QueryAddress, context.ModuleInfo);
    OutputVerbose(
        context.Api.Control.Get(),
        context.Api.Control4.Get(),
        context.Options,
        "module=%s base=%s size=%u",
        context.ModuleInfo.ModuleName.c_str(),
        decomp::HexU64(context.ModuleInfo.Base).c_str(),
        context.ModuleInfo.Size);

    std::string resolvedSymbolName;
    OutputVerbose(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "recovering function regions");
    context.Regions = RecoverFunctionRegions(
        context.Api.Symbols.Get(),
        context.Api.Control.Get(),
        context.QueryAddress,
        context.ModuleInfo,
        context.EntryAddress,
        context.Options.MaxInstructions,
        &resolvedSymbolName);

    if (!resolvedSymbolName.empty())
    {
        context.Target = resolvedSymbolName;
        OutputVerbose(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "resolved symbol=%s", context.Target.c_str());
    }

    if (context.Regions.empty())
    {
        OutputLine(context.Api.Control.Get(), context.Api.Control4.Get(), "error: could not recover function range\n");
        return E_FAIL;
    }

    OutputVerbose(
        context.Api.Control.Get(),
        context.Api.Control4.Get(),
        context.Options,
        "recovered regions=%llu entry=%s",
        static_cast<unsigned long long>(context.Regions.size()),
        decomp::HexU64(context.EntryAddress).c_str());

    if (AbortIfUserInterrupted(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "function range recovery"))
    {
        return E_ABORT;
    }

    return S_OK;
}

HRESULT ReadAndDisassembleCommandTarget(DecompCommandContext& context)
{
    OutputVerbose(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "reading function bytes");
    context.RegionBytes = ReadFunctionRegionBytes(context.Api.DataSpaces.Get(), context.Regions);
    context.Bytes = FlattenFunctionRegionBytes(context.RegionBytes);
    OutputVerbose(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "read bytes=%llu", static_cast<unsigned long long>(context.Bytes.size()));

    if (AbortIfUserInterrupted(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "function byte read"))
    {
        return E_ABORT;
    }

    OutputVerbose(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "disassembling regions");
    context.Instructions = DisassembleRegions(
        context.Api.Control.Get(),
        context.RegionBytes,
        context.Options.MaxInstructions,
        context.DecodedContexts);
    OutputVerbose(
        context.Api.Control.Get(),
        context.Api.Control4.Get(),
        context.Options,
        "decoded instructions=%llu",
        static_cast<unsigned long long>(context.Instructions.size()));

    if (AbortIfUserInterrupted(context.Api.Control.Get(), context.Api.Control4.Get(), context.Options, "disassembly"))
    {
        return E_ABORT;
    }

    return S_OK;
}
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags)
{
    if (version != nullptr)
    {
        *version = 0x00010000;
    }

    if (flags != nullptr)
    {
        *flags = 0;
    }

    return S_OK;
}

extern "C" void CALLBACK DebugExtensionUninitialize(void)
{
}

extern "C" HRESULT CALLBACK DecompCommand(PDEBUG_CLIENT client, PCSTR args)
{
    DecompCommandContext context;
    DebugApi& api = context.Api;
    decomp::DecompOptions& options = context.Options;
    std::string& target = context.Target;
    std::string& error = context.Error;
    uint64_t& queryAddress = context.QueryAddress;
    uint64_t& entryAddress = context.EntryAddress;
    decomp::ModuleInfo& moduleInfo = context.ModuleInfo;
    std::vector<decomp::FunctionRegion>& regions = context.Regions;
    std::vector<FunctionRegionBytes>& regionBytes = context.RegionBytes;
    std::vector<uint8_t>& bytes = context.Bytes;
    std::vector<decomp::DisassembledInstruction>& instructions = context.Instructions;
    std::vector<DecodedInstructionContext>& decodedContexts = context.DecodedContexts;
    decomp::AnalyzeRequest& request = context.Request;
    decomp::AnalyzeResponse& response = context.Response;
    decomp::LlmClientConfig& displayConfig = context.DisplayConfig;

    do
    {
        if (!AcquireDebugApi(client, api))
        {
            return E_FAIL;
        }

        if (!ParseCommandLine(args, options, target, error))
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: %s\n", error.c_str());
            PrintUsage(api.Control.Get(), api.Control4.Get());
            return E_INVALIDARG;
        }

        if (options.DoctorOutput)
        {
            PrintDoctorOutput(api, options);

            if (target.empty())
            {
                return S_OK;
            }
        }

        if (options.HistoryOutput)
        {
            if (options.WindowOutput)
            {
                std::string viewerDescription;

                if (OpenAnalyzeHistoryViewer(api, options, viewerDescription, error))
                {
                    OutputLine(api.Control.Get(), api.Control4.Get(), "decomp native viewer opened: %s\n", viewerDescription.c_str());

                    if (target.empty())
                    {
                        return S_OK;
                    }
                }
                else
                {
                    OutputLine(api.Control.Get(), api.Control4.Get(), "error: %s\n", error.c_str());

                    if (target.empty())
                    {
                        return E_FAIL;
                    }

                    error.clear();
                }
            }
            else
            {
                PrintAnalyzeHistory(api.Control.Get(), api.Control4.Get());
            }

            if (target.empty())
            {
                return S_OK;
            }
        }

        if (target.empty() && options.WindowOutput)
        {
            std::string viewerDescription;

            if (!OpenAnalyzeHistoryViewer(api, options, viewerDescription, error))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: %s\n", error.c_str());
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "decomp native viewer opened: %s\n", viewerDescription.c_str());
            return S_OK;
        }

        if (options.ClearUserOverrides)
        {
            ApplyNoReturnOverrideEnvironment(options);
            OutputLine(api.Control.Get(), api.Control4.Get(), "user overrides cleared\n");

            if (target.empty())
            {
                return S_OK;
            }
        }

        if (options.LastExplainOutput || options.LastFactsOutput)
        {
            if (!PrintCachedAnalyzeResult(api.Control.Get(), api.Control4.Get(), api.Advanced2.Get(), options, error))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: %s\n", error.c_str());
                return E_FAIL;
            }

            return S_OK;
        }

        if (options.LastJsonOutput)
        {
            const CachedAnalyzeArtifact* artifact = GetCachedAnalyzeArtifact(options.LastCacheIndex);

            if (artifact == nullptr)
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: no cached !decomp result at history index %u\n", options.LastCacheIndex);
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n%s\n", artifact->RequestJson.c_str(), artifact->ResponseJson.c_str());

            return S_OK;
        }

        if (options.LastDataModelOutput)
        {
            const CachedAnalyzeArtifact* artifact = GetCachedAnalyzeArtifact(options.LastCacheIndex);

            if (artifact == nullptr)
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: no cached !decomp data model snapshot at history index %u\n", options.LastCacheIndex);
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n", artifact->DataModelJson.c_str());

            return S_OK;
        }

        if (options.LastDebugPromptOutput)
        {
            const CachedAnalyzeArtifact* artifact = GetCachedAnalyzeArtifact(options.LastCacheIndex);

            if (artifact == nullptr && (options.LastCacheIndex != 1 || g_lastDebugPromptDump.empty()))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: no cached !decomp prompt dump at history index %u\n", options.LastCacheIndex);
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n", artifact == nullptr ? g_lastDebugPromptDump.c_str() : artifact->DebugPromptDump.c_str());

            return S_OK;
        }

        ApplyNoReturnOverrideEnvironment(options);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "start target=%s max_instructions=%u timeout_ms=%u", target.c_str(), options.MaxInstructions, options.TimeoutMs);
        OutputProgress(api.Control.Get(), api.Control4.Get(), options, "starting analysis for %s", target.c_str());

        std::string displayConfigError;
        if (decomp::LoadLlmClientConfig(displayConfig, displayConfigError, false))
        {
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "display config loaded");
        }
        else
        {
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "display config unavailable: %s", displayConfigError.c_str());
        }
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "config load"))
        {
            return E_ABORT;
        }

        const HRESULT targetStatus = ResolveCommandTarget(context);

        if (FAILED(targetStatus))
        {
            return targetStatus;
        }

        const KernelBuildFacts kernelBuild = CollectKernelBuildFacts(api.Control.Get(), api.Control4.Get(), api.DataSpaces.Get());
        CachedAnalyzeArtifact artifactLookup;
        artifactLookup.Target = target;
        artifactLookup.Module = moduleInfo.ModuleName;
        artifactLookup.Timestamp = BuildCacheTimestamp();
        artifactLookup.EntryAddress = entryAddress;
        artifactLookup.EntryRva = moduleInfo.Base <= entryAddress ? entryAddress - moduleInfo.Base : entryAddress;
        artifactLookup.HasEntryRva = moduleInfo.Base != 0 && moduleInfo.Base <= entryAddress;
        artifactLookup.KernelBuild = kernelBuild;

        if (TryReplayPersistentAnalyzeArtifact(api, options, kernelBuild, artifactLookup, error))
        {
            return S_OK;
        }

        if (!error.empty())
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: %s\n", error.c_str());
            return E_FAIL;
        }

        const HRESULT disassemblyStatus = ReadAndDisassembleCommandTarget(context);

        if (FAILED(disassemblyStatus))
        {
            return disassemblyStatus;
        }

        request.RequestId = decomp::MakeRequestId();
        request.TimeoutMs = options.TimeoutMs;
        request.BriefOutput = options.BriefOutput;
        const decomp::DebugSessionKind sessionKind = GetSessionKind(api.Control.Get());
        decomp::SessionPolicyFacts sessionPolicy;
        bool sessionPolicyCollected = false;

        auto rebuildAnalyzerFacts = [&]()
        {
            request.Facts = decomp::BuildAnalysisFacts(
                target,
                moduleInfo,
                sessionKind,
                options,
                queryAddress,
                entryAddress,
                regions,
                bytes,
                instructions);

            if (sessionPolicyCollected)
            {
                request.Facts.SessionPolicy = sessionPolicy;
            }
        };

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "building analyzer facts request_id=%s", request.RequestId.c_str());
        rebuildAnalyzerFacts();
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "facts core blocks=%llu calls=%llu conditions=%llu", static_cast<unsigned long long>(request.Facts.Blocks.size()), static_cast<unsigned long long>(request.Facts.Calls.size()), static_cast<unsigned long long>(request.Facts.NormalizedConditions.size()));
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "analyzer facts"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "collecting session policy");
        sessionPolicy = BuildSessionPolicyFacts(api.Control.Get());
        sessionPolicyCollected = true;
        request.Facts.SessionPolicy = sessionPolicy;
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "enriching debug metadata");
        bool factsHaveDebugMetadata = false;

        for (size_t switchExpansionPass = 0; switchExpansionPass < 3; ++switchExpansionPass)
        {
            EnrichAnalysisFactsWithDebugMetadata(api.Symbols.Get(), api.DataSpaces.Get(), moduleInfo, decodedContexts, request.Facts);
            factsHaveDebugMetadata = true;

            size_t addedSwitchRegions = 0;

            if (!TryAddSwitchTargetRegions(
                    api.Control.Get(),
                    moduleInfo,
                    request.Facts,
                    options.MaxInstructions,
                    regions,
                    addedSwitchRegions))
            {
                break;
            }

            factsHaveDebugMetadata = false;
            OutputVerbose(
                api.Control.Get(),
                api.Control4.Get(),
                options,
                "switch target expansion pass=%llu added_regions=%llu",
                static_cast<unsigned long long>(switchExpansionPass + 1U),
                static_cast<unsigned long long>(addedSwitchRegions));

            regionBytes = ReadFunctionRegionBytes(api.DataSpaces.Get(), regions);
            bytes = FlattenFunctionRegionBytes(regionBytes);
            decodedContexts.clear();
            instructions = DisassembleRegions(api.Control.Get(), regionBytes, options.MaxInstructions, decodedContexts);
            rebuildAnalyzerFacts();
        }

        if (!factsHaveDebugMetadata)
        {
            EnrichAnalysisFactsWithDebugMetadata(api.Symbols.Get(), api.DataSpaces.Get(), moduleInfo, decodedContexts, request.Facts);
        }
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "debug metadata enrichment"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "collecting PDB facts");
        CollectPdbFacts(api.Symbols.Get(), api.Symbols5.Get(), moduleInfo, regions, request.Facts);
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "PDB fact collection"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "applying user corrections");
        ApplyUserCorrections(options, request.Facts);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "collecting observed behavior facts");
        CollectObservedBehaviorFacts(api.Registers.Get(), api.DataSpaces.Get(), api.Symbols.Get(), regions, request.Facts);
        ApplyPreferredNaturalLanguage(displayConfig, request.Facts);
        decomp::RefreshEvidenceGraph(request.Facts);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "facts ready pre_llm_confidence=%.2f type_hints=%llu idioms=%llu callee_summaries=%llu", request.Facts.PreLlmConfidence, static_cast<unsigned long long>(request.Facts.TypeHints.size()), static_cast<unsigned long long>(request.Facts.Idioms.size()), static_cast<unsigned long long>(request.Facts.CalleeSummaries.size()));
        OutputProgress(
            api.Control.Get(),
            api.Control4.Get(),
            options,
            "local analysis complete: %llu instructions, %llu blocks, %llu calls",
            static_cast<unsigned long long>(instructions.size()),
            static_cast<unsigned long long>(request.Facts.Blocks.size()),
            static_cast<unsigned long long>(request.Facts.Calls.size()));
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "observed behavior collection"))
        {
            return E_ABORT;
        }

        if (options.PlanOutput)
        {
            decomp::LlmClientConfig planConfig;
            std::string planConfigError;

            if (!decomp::LoadLlmClientConfig(planConfig, planConfigError, false))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "warning: plan config load failed (DECOMP_PLAN_CONFIG_INVALID): %s\n", planConfigError.c_str());
            }

            if (options.TimeoutMs != 5000 || planConfig.TimeoutMs == 5000)
            {
                planConfig.TimeoutMs = options.TimeoutMs;
            }

            PrintPlanOutput(request, planConfig, options, api.Control.Get(), api.Control4.Get());
            return S_OK;
        }

        if (options.DebugPromptOutput)
        {
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "building prompt dump without LLM request");
            g_lastDebugPromptDump = decomp::BuildDebugPromptDump(request);
            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n", g_lastDebugPromptDump.c_str());
            return S_OK;
        }

        if (options.DisableLlm)
        {
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "LLM disabled; building analyzer-only response");
            OutputProgress(api.Control.Get(), api.Control4.Get(), options, "LLM disabled; preparing analyzer-only result");
            response = BuildAnalyzerOnlyResponse(request);
        }
        else
        {
            decomp::LlmClientConfig llmConfig;
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "loading LLM config");
            if (!decomp::LoadLlmClientConfig(llmConfig, error))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: llm config load failed: %s\n", error.c_str());
                return E_FAIL;
            }

            if (options.TimeoutMs != 5000 || llmConfig.TimeoutMs == 5000)
            {
                llmConfig.TimeoutMs = options.TimeoutMs;
            }

            const std::string endpointDisplay = llmConfig.Endpoint.empty() ? std::string("<mock>") : SanitizeEndpointForDisplay(llmConfig.Endpoint);
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "starting LLM analysis endpoint=%s model=%s timeout_ms=%u", endpointDisplay.c_str(), llmConfig.Model.c_str(), llmConfig.TimeoutMs);
            OutputProgress(
                api.Control.Get(),
                api.Control4.Get(),
                options,
                "LLM analysis started: model=%s timeout=%us, Ctrl+Break cancels",
                llmConfig.Model.c_str(),
                llmConfig.TimeoutMs / 1000);
            bool cancelled = false;

            if (!AnalyzeWithLlmInterruptible(request, llmConfig, api.Control.Get(), api.Control4.Get(), options, response, error, cancelled))
            {
                if (cancelled)
                {
                    return E_ABORT;
                }

                OutputLine(api.Control.Get(), api.Control4.Get(), "error: llm analyze failed: %s\n", error.c_str());
                return E_FAIL;
            }
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "LLM analysis finished provider=%s confidence=%.2f", response.Provider.c_str(), response.Confidence);
            OutputProgress(api.Control.Get(), api.Control4.Get(), options, "LLM analysis complete; verifying result");
        }

        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "LLM analysis"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "tokenizing pseudo-code");
        decomp::EnsurePseudoCodeTokens(response);
        ApplyResponseRenames(options, response);
        response.PseudoCTokens.clear();
        decomp::EnsurePseudoCodeTokens(response);
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "pseudo-code tokenization"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "running verifier");
        decomp::VerifyResponse(request, response);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "verifier adjusted=%.2f conflicts=%u missing_evidence=%u issues=%llu", response.Verifier.AdjustedConfidence, response.Verifier.FactConflicts, response.Verifier.MissingEvidence, static_cast<unsigned long long>(response.Verifier.Issues.size()));
        OutputProgress(api.Control.Get(), api.Control4.Get(), options, "verification complete; printing result");
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "verifier"))
        {
            return E_ABORT;
        }

        StoreCachedAnalyzeResult(request, response, kernelBuild);
        const CachedAnalyzeArtifact* storedArtifact = GetCachedAnalyzeArtifact(1);

        if (storedArtifact != nullptr && !options.DisableLlm)
        {
            TrySavePersistentAnalyzeArtifact(api, options, *storedArtifact);
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "printing response");
        PrintResponse(request, response, displayConfig, api.Control.Get(), api.Control4.Get(), api.Advanced2.Get(), options);
        return S_OK;
    }
    while (false);

    return E_FAIL;
}
