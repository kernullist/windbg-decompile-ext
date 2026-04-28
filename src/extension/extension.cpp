#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

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
#include <deque>
#include <exception>
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
    bool IsIndirect = false;
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
        && !options.LastDebugPromptOutput;
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

void OutputDmlLine(
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2,
    const std::string& text,
    const std::string& command)
{
    if (AreOutputCallbacksDmlAware(advanced2))
    {
        OutputDmlRaw(control, control4, BuildDmlLink(text, command) + "\n");
        return;
    }

    OutputLine(control, control4, "%s\n", text.c_str());
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
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    if (response.PseudoC.empty())
    {
        return;
    }

    if (!AreOutputCallbacksDmlAware(advanced2) || response.PseudoCTokens.empty())
    {
        OutputTextRaw(control, control4, response.PseudoC);
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
            OutputDmlRaw(control, control4, token.Text);
            continue;
        }

        const PseudoCodeTokenStyle style = GetPseudoCodeTokenStyle(token.Kind, config.Highlight);
        const std::string escapedText = EscapeDmlText(token.Text);

        if (style.Foreground.empty())
        {
            OutputDmlRaw(control, control4, escapedText);
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
        OutputDmlRaw(control, control4, markup);
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

    if (value == "analyzer" || value == "no-llm")
    {
        options.DisableLlm = true;
        return true;
    }

    error = "unknown view: " + rawValue;
    return false;
}

bool ApplyLastOption(const std::string& rawValue, decomp::DecompOptions& options, std::string& error)
{
    const std::string value = decomp::ToLowerAscii(decomp::TrimCopy(rawValue));

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
            else if (option == "no-llm")
            {
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

    std::vector<decomp::DisassembledInstruction> probe;
    const uint64_t endAddress = DisassembleUntilTerminal(control, entryAddress, maxInstructions, probe);

    if (endAddress > entryAddress)
    {
        regions.push_back({ entryAddress, endAddress });
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

std::vector<uint8_t> ReadFunctionBytes(IDebugDataSpaces4* dataSpaces, const std::vector<decomp::FunctionRegion>& regions)
{
    std::vector<uint8_t> combined;

    for (const auto& region : regions)
    {
        std::vector<uint8_t> part;

        if (!ReadVirtualRange(dataSpaces, region.Start, region.End, part))
        {
            continue;
        }

        combined.insert(combined.end(), part.begin(), part.end());
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
    IDebugDataSpaces4* dataSpaces,
    IDebugControl* control,
    const std::vector<decomp::FunctionRegion>& regions,
    uint32_t maxInstructions,
    std::vector<DecodedInstructionContext>& decodedContexts)
{
    std::vector<decomp::DisassembledInstruction> instructions;
    uint32_t remaining = maxInstructions;

    for (const auto& region : regions)
    {
        std::vector<uint8_t> regionBytes;

        if (!ReadVirtualRange(dataSpaces, region.Start, region.End, regionBytes))
        {
            continue;
        }

        uint64_t current = region.Start;
        size_t offset = 0;

        while (current < region.End && remaining > 0 && offset < regionBytes.size())
        {
            decomp::DisassembledInstruction instruction;
            DecodedInstructionContext context;

            if (TryDecodeInstructionWithZydis(current, regionBytes.data() + offset, regionBytes.size() - offset, instruction, context))
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
            instruction.OperationText = buffer.data();
            instruction.OperandText = ExtractOperandTextFromFormattedInstruction(buffer.data());
            context.Address = current;
            context.EndAddress = nextAddress;
            context.Mnemonic.clear();
            context.Operands = SplitOperands(instruction.OperandText);
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
        if (access.Access.empty())
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
            const std::string prefix = decomp::TrimCopy(trimmed.substr(0, firstParen));

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

        if (!context.IsCall)
        {
            continue;
        }

        decomp::CallTargetInfo call;
        call.Site = context.Address;
        call.Indirect = context.IsIndirect;

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
                call.TargetKind =
                    (calleeModule.ModuleName == moduleInfo.ModuleName)
                    ? (context.IsIndirect ? "internal_indirect" : "internal_direct")
                    : (context.IsIndirect ? "external_indirect" : "external_direct");
            }
            else
            {
                call.TargetKind = context.IsIndirect ? "indirect" : "direct";
            }
        }

        call.DisplayName = displayName;
        call.ModuleName = !calleeModule.ModuleName.empty() ? calleeModule.ModuleName : moduleInfo.ModuleName;
        call.Prototype = !typeName.empty() ? typeName : ("UNKNOWN_TYPE " + displayName + "(...)");
        call.ReturnType = ExtractReturnTypeFromPrototype(typeName, displayName);
        call.SideEffects = InferSideEffectsFromName(displayName);
        call.Confidence = decomp::Clamp01(
            0.50
            + (targetAddress != 0 ? 0.10 : 0.0)
            + (!symbol.Name.empty() ? 0.15 : 0.0)
            + (!typeName.empty() ? 0.15 : 0.0)
            + (context.HasRipRelativeMemory ? 0.05 : 0.0));
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
        summary.MemoryEffects = InferMemoryEffectsFromName(target.DisplayName);
        if (summary.MemoryEffects == "unknown")
        {
            summary.MemoryEffects = target.SideEffects;
        }
        summary.Ownership =
            (decomp::ContainsInsensitive(target.DisplayName, "Alloc") || decomp::ContainsInsensitive(target.DisplayName, "malloc") || decomp::ContainsInsensitive(target.DisplayName, "operator new")) ? "may_return_owned_resource"
            : (decomp::ContainsInsensitive(target.DisplayName, "Free") || decomp::ContainsInsensitive(target.DisplayName, "delete") || decomp::ContainsInsensitive(target.DisplayName, "Close")) ? "may_release_resource"
            : "unknown";
        summary.Source = target.Prototype.empty() ? "symbol" : "symbol_type";
        summary.Confidence = decomp::Clamp01(target.Confidence + (!target.Prototype.empty() ? 0.08 : 0.0));

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

void PrintUsage(IDebugControl* control, IDebugControl4* control4)
{
    OutputLine(control, control4, "usage: !decomp [/verbose] [/view:brief|explain|json|facts|prompt|data|analyzer] [/last:explain|facts|json|data|prompt] [/limit:deep|huge|N] [/timeout:N] <addr|module!symbol>\n");
    OutputLine(control, control4, "fix  : /fix:noreturn:name /fix:type:expr=TYPE /fix:field:expr=TYPE /fix:rename:old=new /fix:clear\n");
    OutputLine(control, control4, "compat: legacy switches such as /brief, /json, /facts-only, /debug-prompt, /data-model, /last-json, /deep, and /noreturn: still work\n");
    OutputLine(control, control4, "cfg  : decomp.llm.json beside decomp.dll\n");
    OutputLine(control, control4, "env  : DECOMP_LLM_*, OPENAI_API_KEY may override config values\n");
}

void PrintFactsOnly(
    const decomp::AnalyzeRequest& request,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    OutputLine(control, control4, "%s\n", decomp::SerializeAnalyzeRequest(request, true).c_str());

    if (!request.Facts.Blocks.empty())
    {
        OutputLine(control, control4, "\nlinks:\n");

        for (const auto& block : request.Facts.Blocks)
        {
            OutputDmlLine(
                control,
                control4,
                advanced2,
                "- " + block.Id + " " + decomp::HexU64(block.StartAddress) + "-" + decomp::HexU64(block.EndAddress),
                BuildDisassembleCommand(block.StartAddress, block.EndAddress));
        }
    }
}

void PrintDataModelOutput(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    OutputLine(control, control4, "%s", BuildDataModelSnapshotJson(request, response).c_str());

    if (request.Facts.EntryAddress != 0)
    {
        OutputLine(control, control4, "\nautomation links:\n");
        OutputDmlLine(control, control4, advanced2, "- disassemble entry", BuildDisassembleCommand(request.Facts.EntryAddress, request.Facts.EntryAddress + 0x40));
        OutputDmlLine(control, control4, advanced2, "- break on entry", "bp " + decomp::HexU64(request.Facts.EntryAddress));
    }
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
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2,
    const decomp::AnalysisFacts& facts,
    const std::string& label,
    const std::vector<std::string>& blockIds)
{
    if (blockIds.empty())
    {
        return;
    }

    OutputLine(control, control4, "  %s:\n", label.c_str());

    for (const auto& blockId : blockIds)
    {
        const decomp::BasicBlock* block = FindBlockById(facts, blockId);

        if (block == nullptr)
        {
            OutputLine(control, control4, "    - %s\n", blockId.c_str());
            continue;
        }

        OutputDmlLine(
            control,
            control4,
            advanced2,
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
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    if (issues.empty())
    {
        return;
    }

    OutputLine(control, control4, "\n%s:\n", title);

    for (const auto& issue : issues)
    {
        const std::string command = BuildIssueNavigationCommand(request, issue);

        if (command.empty())
        {
            OutputLine(control, control4, "- %s\n", issue.c_str());
            continue;
        }

        OutputDmlLine(control, control4, advanced2, "- " + issue, command);
    }
}

void PrintLinkedIssueLine(
    const std::string& label,
    const std::string& issue,
    const decomp::AnalyzeRequest& request,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    const std::string text = label + issue;
    const std::string command = BuildIssueNavigationCommand(request, issue);

    if (command.empty())
    {
        OutputLine(control, control4, "%s\n", text.c_str());
        return;
    }

    OutputDmlLine(control, control4, advanced2, text, command);
}

void PrintActionLinks(
    const decomp::AnalyzeRequest& request,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    if (!AreOutputCallbacksDmlAware(advanced2))
    {
        return;
    }

    OutputDmlRaw(control, control4, "actions     : "
        + BuildDmlLink("explain", "!decomp /last:explain")
        + " "
        + BuildDmlLink("json", "!decomp /last:json")
        + " "
        + BuildDmlLink("facts", "!decomp /last:facts")
        + " "
        + BuildDmlLink("prompt", "!decomp /last:prompt")
        + " "
        + BuildDmlLink("data-model", "!decomp /last:data")
        + "\n");

    OutputDmlRaw(control, control4, "nav         : "
        + BuildDmlLink("entry", BuildDisassembleAddressCommand(request.Facts.EntryAddress))
        + " "
        + BuildDmlLink("bp-entry", "bp " + decomp::HexU64(request.Facts.EntryAddress))
        + " "
        + BuildDmlLink("last-json", "!decomp /last:json")
        + " "
        + BuildDmlLink("last-dx", "!decomp /last:data")
        + " "
        + BuildDmlLink("last-prompt", "!decomp /last:prompt")
        + "\n");
}

void PrintExplainOutput(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2)
{
    OutputLine(control, control4, "\nevidence:\n");

    for (const auto& evidence : response.Evidence)
    {
        OutputLine(control, control4, "- %s\n", evidence.Claim.c_str());

        for (const auto& blockId : evidence.Blocks)
        {
            const decomp::BasicBlock* block = FindBlockById(request.Facts, blockId);

            if (block == nullptr)
            {
                OutputLine(control, control4, "  - %s\n", blockId.c_str());
                continue;
            }

            OutputDmlLine(
                control,
                control4,
                advanced2,
                "  - " + blockId + " " + decomp::HexU64(block->StartAddress) + "-" + decomp::HexU64(block->EndAddress),
                BuildDisassembleCommand(block->StartAddress, block->EndAddress));
        }
    }

    if (!request.Facts.ControlFlow.empty())
    {
        OutputLine(control, control4, "\ncontrol_flow:\n");

        for (const auto& region : request.Facts.ControlFlow)
        {
            const std::string headerCommand = BuildBlockNavigationCommand(request.Facts, region.HeaderBlock);
            const std::string label = "- " + region.Kind
                + " header=" + region.HeaderBlock
                + " condition=" + region.Condition
                + " confidence=" + std::to_string(region.Confidence);

            if (headerCommand.empty())
            {
                OutputLine(control, control4, "%s\n", label.c_str());
            }
            else
            {
                OutputDmlLine(control, control4, advanced2, label, headerCommand);
            }

            if (!region.Evidence.empty())
            {
                OutputLine(control, control4, "  evidence: %s\n", region.Evidence.c_str());
            }

            OutputBlockLinkList(control, control4, advanced2, request.Facts, "body", region.BodyBlocks);
            OutputBlockLinkList(control, control4, advanced2, request.Facts, "latch", region.LatchBlocks);
            OutputBlockLinkList(control, control4, advanced2, request.Facts, "exit", region.ExitBlocks);
        }
    }

    if (!request.Facts.TypeHints.empty())
    {
        OutputLine(control, control4, "\ntype_hints:\n");

        for (const auto& hint : request.Facts.TypeHints)
        {
            const std::string label = "- " + hint.Expression + " => " + hint.Type
                + " [" + hint.Source + " " + std::to_string(hint.Confidence) + "]";

            if (hint.Site != 0)
            {
                OutputDmlLine(control, control4, advanced2, label, BuildDisassembleAddressCommand(hint.Site));
            }
            else
            {
                OutputLine(control, control4, "%s\n", label.c_str());
            }
        }
    }

    if (!request.Facts.CallTargets.empty())
    {
        OutputLine(control, control4, "\ncall_targets:\n");

        for (const auto& call : request.Facts.CallTargets)
        {
            const std::string label = "- " + decomp::HexU64(call.Site) + " " + call.DisplayName + " " + call.TargetKind;
            const std::string command = call.TargetAddress != 0 ? BuildDisassembleCommand(call.TargetAddress, call.TargetAddress + 0x30) : ("u " + decomp::HexU64(call.Site));
            OutputDmlLine(control, control4, advanced2, label, command);
        }
    }

    if (!request.Facts.ObservedBehavior.ArgumentSamples.empty()
        || !request.Facts.ObservedBehavior.MemoryHotspots.empty()
        || !request.Facts.ObservedBehavior.TtdQueries.empty())
    {
        OutputLine(control, control4, "\nobserved_behavior:\n");
        OutputLine(
            control,
            control4,
            "- ip=%s in_function=%s sp=%s confidence=%.2f\n",
            decomp::HexU64(request.Facts.ObservedBehavior.InstructionPointer).c_str(),
            request.Facts.ObservedBehavior.CurrentInstructionInFunction ? "true" : "false",
            decomp::HexU64(request.Facts.ObservedBehavior.StackPointer).c_str(),
            request.Facts.ObservedBehavior.Confidence);

        for (const auto& argument : request.Facts.ObservedBehavior.ArgumentSamples)
        {
            OutputLine(
                control,
                control4,
                "- %s/%s = %s %s [%.2f]\n",
                argument.Name.c_str(),
                argument.Register.c_str(),
                decomp::HexU64(argument.Value).c_str(),
                argument.Symbol.c_str(),
                argument.Confidence);
        }

        for (const auto& hotspot : request.Facts.ObservedBehavior.MemoryHotspots)
        {
            OutputLine(
                control,
                control4,
                "- hotspot %s read=%u write=%u [%.2f]\n",
                hotspot.Expression.c_str(),
                hotspot.ReadCount,
                hotspot.WriteCount,
                hotspot.Confidence);

            for (const auto& site : hotspot.Sites)
            {
                OutputDmlLine(
                    control,
                    control4,
                    advanced2,
                    "  - site " + decomp::HexU64(site),
                    BuildDisassembleAddressCommand(site));
            }
        }

        for (const auto& query : request.Facts.ObservedBehavior.TtdQueries)
        {
            OutputDmlLine(control, control4, advanced2, "- " + query, query);
        }
    }
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
    if (options.JsonOutput)
    {
        OutputLine(control, control4, "%s\n", decomp::SerializeAnalyzeRequest(request, true).c_str());
        OutputLine(control, control4, "%s\n", decomp::SerializeAnalyzeResponse(response, true).c_str());
        return;
    }

    if (options.FactsOnlyOutput)
    {
        PrintFactsOnly(request, control, control4, advanced2);
        return;
    }

    if (options.DataModelOutput)
    {
        PrintDataModelOutput(request, response, control, control4, advanced2);
        return;
    }

    OutputLine(control, control4, "target      : %s\n", request.Facts.QueryText.c_str());
    if (AreOutputCallbacksDmlAware(advanced2))
    {
        OutputDmlRaw(control, control4, "entry       : " + BuildDmlLink(decomp::HexU64(request.Facts.EntryAddress), BuildDisassembleCommand(request.Facts.EntryAddress, request.Facts.EntryAddress + 0x40)) + "\n");
    }
    else
    {
        OutputLine(control, control4, "entry       : %s\n", decomp::HexU64(request.Facts.EntryAddress).c_str());
    }
    OutputLine(control, control4, "query       : %s\n", decomp::HexU64(request.Facts.QueryAddress).c_str());
    OutputLine(control, control4, "module      : %s\n", request.Facts.Module.ModuleName.c_str());
    OutputLine(control, control4, "regions     : %llu\n", static_cast<unsigned long long>(request.Facts.Regions.size()));
    OutputLine(control, control4, "session     : %s/%s\n", request.Facts.SessionPolicy.ExecutionKind.c_str(), request.Facts.SessionPolicy.AnalysisStrategy.c_str());
    OutputLine(control, control4, "analyzer    : %.2f\n", request.Facts.PreLlmConfidence);
    OutputLine(control, control4, "llm         : %.2f\n", response.Confidence);
    OutputLine(control, control4, "verified    : %.2f\n", response.Verifier.AdjustedConfidence);
    OutputLine(control, control4, "provider    : %s\n\n", response.Provider.c_str());
    PrintActionLinks(request, control, control4, advanced2);

    if (!response.Summary.empty())
    {
        const std::string formattedSummary = FormatSummaryForDisplay(response.Summary);
        OutputLine(control, control4, "summary:\n%s\n\n", formattedSummary.c_str());
    }

    if (options.BriefOutput)
    {
        if (!response.Uncertainties.empty())
        {
            PrintLinkedIssueLine("top_uncertainty: ", response.Uncertainties.front(), request, control, control4, advanced2);
        }

        if (!response.Verifier.Warnings.empty())
        {
            PrintLinkedIssueLine("top_warning    : ", response.Verifier.Warnings.front(), request, control, control4, advanced2);
        }

        return;
    }

    if (!response.PseudoC.empty())
    {
        OutputLine(control, control4, "pseudo_c:\n");
        PrintPseudoCodeHighlighted(response, displayConfig, control, control4, advanced2);
        OutputLine(control, control4, "\n");
    }
    if (!response.Uncertainties.empty())
    {
        PrintLinkedIssueList("uncertainties", response.Uncertainties, request, control, control4, advanced2);
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

            PrintLinkedIssueList("verifier issues", issueLines, request, control, control4, advanced2);
        }
        else
        {
            PrintLinkedIssueList("verifier warnings", response.Verifier.Warnings, request, control, control4, advanced2);
        }
    }

    if (options.ExplainOutput)
    {
        PrintExplainOutput(request, response, control, control4, advanced2);
    }
}

bool PrintCachedAnalyzeResult(
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2,
    decomp::DecompOptions options,
    std::string& error)
{
    if (g_lastRequestJson.empty() || g_lastResponseJson.empty())
    {
        error = "no previous !decomp result is cached";
        return false;
    }

    decomp::AnalyzeRequest cachedRequest;
    decomp::AnalyzeResponse cachedResponse;

    if (!decomp::ParseAnalyzeRequest(g_lastRequestJson, cachedRequest, error))
    {
        error = "failed to parse cached request: " + error;
        return false;
    }

    if (!decomp::ParseAnalyzeResponse(g_lastResponseJson, cachedResponse, error))
    {
        error = "failed to parse cached response: " + error;
        return false;
    }

    decomp::LlmClientConfig displayConfig;

    if (!decomp::LoadLlmClientConfig(displayConfig, error, false))
    {
        error = "cached display config load failed: " + error;
        return false;
    }

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
    DebugApi api;
    decomp::DecompOptions options;
    std::string target;
    std::string error;
    uint64_t queryAddress = 0;
    uint64_t entryAddress = 0;
    decomp::ModuleInfo moduleInfo;
    std::vector<decomp::FunctionRegion> regions;
    std::vector<uint8_t> bytes;
    std::vector<decomp::DisassembledInstruction> instructions;
    std::vector<DecodedInstructionContext> decodedContexts;
    decomp::AnalyzeRequest request;
    decomp::AnalyzeResponse response;
    decomp::LlmClientConfig displayConfig;

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

            if (target.empty())
            {
                return S_OK;
            }
        }

        if (options.LastJsonOutput)
        {
            if (g_lastRequestJson.empty() && g_lastResponseJson.empty())
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: no previous !decomp result is cached\n");
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n%s\n", g_lastRequestJson.c_str(), g_lastResponseJson.c_str());

            if (target.empty())
            {
                return S_OK;
            }
        }

        if (options.LastDataModelOutput)
        {
            if (g_lastDataModelJson.empty())
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: no previous !decomp data model snapshot is cached\n");
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n", g_lastDataModelJson.c_str());

            if (target.empty())
            {
                return S_OK;
            }
        }

        if (options.LastDebugPromptOutput)
        {
            if (g_lastDebugPromptDump.empty())
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: no previous !decomp prompt dump is cached\n");
                return E_FAIL;
            }

            OutputLine(api.Control.Get(), api.Control4.Get(), "%s\n", g_lastDebugPromptDump.c_str());

            if (target.empty())
            {
                return S_OK;
            }
        }

        ApplyNoReturnOverrideEnvironment(options);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "start target=%s max_instructions=%u timeout_ms=%u", target.c_str(), options.MaxInstructions, options.TimeoutMs);
        OutputProgress(api.Control.Get(), api.Control4.Get(), options, "starting analysis for %s", target.c_str());

        if (!decomp::LoadLlmClientConfig(displayConfig, error, false))
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: config load failed: %s\n", error.c_str());
            return E_FAIL;
        }
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "display config loaded");
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "config load"))
        {
            return E_ABORT;
        }

        if (!ResolveTargetAddress(api.Symbols.Get(), target, queryAddress))
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: could not resolve target %s\n", target.c_str());
            return E_FAIL;
        }
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "resolved target address=%s", decomp::HexU64(queryAddress).c_str());
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "target resolution"))
        {
            return E_ABORT;
        }

        CollectModuleInfo(api.Symbols.Get(), queryAddress, moduleInfo);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "module=%s base=%s size=%u", moduleInfo.ModuleName.c_str(), decomp::HexU64(moduleInfo.Base).c_str(), moduleInfo.Size);

        std::string resolvedSymbolName;
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "recovering function regions");
        regions = RecoverFunctionRegions(api.Symbols.Get(), api.Control.Get(), queryAddress, moduleInfo, entryAddress, options.MaxInstructions, &resolvedSymbolName);

        if (!resolvedSymbolName.empty())
        {
            target = resolvedSymbolName;
            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "resolved symbol=%s", target.c_str());
        }

        if (regions.empty())
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: could not recover function range\n");
            return E_FAIL;
        }
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "recovered regions=%llu entry=%s", static_cast<unsigned long long>(regions.size()), decomp::HexU64(entryAddress).c_str());
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "function range recovery"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "reading function bytes");
        bytes = ReadFunctionBytes(api.DataSpaces.Get(), regions);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "read bytes=%llu", static_cast<unsigned long long>(bytes.size()));
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "function byte read"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "disassembling regions");
        instructions = DisassembleRegions(api.DataSpaces.Get(), api.Control.Get(), regions, options.MaxInstructions, decodedContexts);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "decoded instructions=%llu", static_cast<unsigned long long>(instructions.size()));
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "disassembly"))
        {
            return E_ABORT;
        }

        request.RequestId = decomp::MakeRequestId();
        request.TimeoutMs = options.TimeoutMs;
        request.BriefOutput = options.BriefOutput;
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "building analyzer facts request_id=%s", request.RequestId.c_str());
        request.Facts = decomp::BuildAnalysisFacts(
            target,
            moduleInfo,
            GetSessionKind(api.Control.Get()),
            options,
            queryAddress,
            entryAddress,
            regions,
            bytes,
            instructions);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "facts core blocks=%llu calls=%llu conditions=%llu", static_cast<unsigned long long>(request.Facts.Blocks.size()), static_cast<unsigned long long>(request.Facts.Calls.size()), static_cast<unsigned long long>(request.Facts.NormalizedConditions.size()));
        if (AbortIfUserInterrupted(api.Control.Get(), api.Control4.Get(), options, "analyzer facts"))
        {
            return E_ABORT;
        }

        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "collecting session policy");
        request.Facts.SessionPolicy = BuildSessionPolicyFacts(api.Control.Get());
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "enriching debug metadata");
        EnrichAnalysisFactsWithDebugMetadata(api.Symbols.Get(), api.DataSpaces.Get(), moduleInfo, decodedContexts, request.Facts);
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

            OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "starting LLM analysis endpoint=%s model=%s timeout_ms=%u", llmConfig.Endpoint.empty() ? "<mock>" : llmConfig.Endpoint.c_str(), llmConfig.Model.c_str(), llmConfig.TimeoutMs);
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

        g_lastRequestJson = decomp::SerializeAnalyzeRequest(request, true);
        g_lastResponseJson = decomp::SerializeAnalyzeResponse(response, true);
        g_lastDataModelJson = BuildDataModelSnapshotJson(request, response);
        g_lastDebugPromptDump = decomp::BuildDebugPromptDump(request);
        OutputVerbose(api.Control.Get(), api.Control4.Get(), options, "printing response");
        PrintResponse(request, response, displayConfig, api.Control.Get(), api.Control4.Get(), api.Advanced2.Get(), options);
        return S_OK;
    }
    while (false);

    return E_FAIL;
}
