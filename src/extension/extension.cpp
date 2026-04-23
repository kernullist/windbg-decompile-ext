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
#include <array>
#include <cstdarg>
#include <cstdio>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "decomp/analyzer.h"
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
    return decomp::ContainsInsensitive(target, "__fastfail")
        || decomp::ContainsInsensitive(target, "RtlFailFast")
        || decomp::ContainsInsensitive(target, "RaiseFailFastException")
        || decomp::ContainsInsensitive(target, "TerminateProcess")
        || decomp::ContainsInsensitive(target, "ExitProcess");
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

            const std::string option = decomp::ToLowerAscii(token.substr(1));

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
            else if (decomp::StartsWithInsensitive(option, "timeout:"))
            {
                if (!ParseU32Value(option.substr(8), options.TimeoutMs))
                {
                    error = "invalid timeout value";
                    break;
                }
            }
            else if (decomp::StartsWithInsensitive(option, "maxinsn:"))
            {
                if (!ParseU32Value(option.substr(8), options.MaxInstructions))
                {
                    error = "invalid maxinsn value";
                    break;
                }
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

        if (target.empty())
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

void PrintUsage(IDebugControl* control, IDebugControl4* control4)
{
    OutputLine(control, control4, "usage: !decomp [/live] [/brief] [/json] [/no-llm] [/deep] [/huge] [/timeout:N] [/maxinsn:N] <addr|module!symbol>\n");
    OutputLine(control, control4, "cfg  : decomp.llm.json beside decomp.dll\n");
    OutputLine(control, control4, "env  : DECOMP_LLM_*, OPENAI_API_KEY may override config values\n");
}

void PrintResponse(
    const decomp::AnalyzeRequest& request,
    const decomp::AnalyzeResponse& response,
    const decomp::LlmClientConfig& displayConfig,
    IDebugControl* control,
    IDebugControl4* control4,
    IDebugAdvanced2* advanced2,
    bool jsonOutput)
{
    if (jsonOutput)
    {
        OutputLine(control, control4, "%s\n", decomp::SerializeAnalyzeRequest(request, true).c_str());
        OutputLine(control, control4, "%s\n", decomp::SerializeAnalyzeResponse(response, true).c_str());
        return;
    }

    OutputLine(control, control4, "target      : %s\n", request.Facts.QueryText.c_str());
    OutputLine(control, control4, "entry       : %s\n", decomp::HexU64(request.Facts.EntryAddress).c_str());
    OutputLine(control, control4, "query       : %s\n", decomp::HexU64(request.Facts.QueryAddress).c_str());
    OutputLine(control, control4, "module      : %s\n", request.Facts.Module.ModuleName.c_str());
    OutputLine(control, control4, "regions     : %llu\n", static_cast<unsigned long long>(request.Facts.Regions.size()));
    OutputLine(control, control4, "analyzer    : %.2f\n", request.Facts.PreLlmConfidence);
    OutputLine(control, control4, "llm         : %.2f\n", response.Confidence);
    OutputLine(control, control4, "verified    : %.2f\n", response.Verifier.AdjustedConfidence);
    OutputLine(control, control4, "provider    : %s\n\n", response.Provider.c_str());

    if (!response.Summary.empty())
    {
        const std::string formattedSummary = FormatSummaryForDisplay(response.Summary);
        OutputLine(control, control4, "summary:\n%s\n\n", formattedSummary.c_str());
    }

    if (!response.PseudoC.empty())
    {
        OutputLine(control, control4, "pseudo_c:\n");
        PrintPseudoCodeHighlighted(response, displayConfig, control, control4, advanced2);
        OutputLine(control, control4, "\n");
    }

    if (!response.Uncertainties.empty())
    {
        OutputLine(control, control4, "\nuncertainties:\n");

        for (const auto& uncertainty : response.Uncertainties)
        {
            OutputLine(control, control4, "- %s\n", uncertainty.c_str());
        }
    }

    if (!response.Verifier.Warnings.empty())
    {
        OutputLine(control, control4, "\nverifier warnings:\n");

        for (const auto& warning : response.Verifier.Warnings)
        {
            OutputLine(control, control4, "- %s\n", warning.c_str());
        }
    }
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

        if (!decomp::LoadLlmClientConfig(displayConfig, error, false))
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: config load failed: %s\n", error.c_str());
            return E_FAIL;
        }

        if (!ResolveTargetAddress(api.Symbols.Get(), target, queryAddress))
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: could not resolve target %s\n", target.c_str());
            return E_FAIL;
        }

        CollectModuleInfo(api.Symbols.Get(), queryAddress, moduleInfo);
        std::string resolvedSymbolName;
        regions = RecoverFunctionRegions(api.Symbols.Get(), api.Control.Get(), queryAddress, moduleInfo, entryAddress, options.MaxInstructions, &resolvedSymbolName);

        if (!resolvedSymbolName.empty())
        {
            target = resolvedSymbolName;
        }

        if (regions.empty())
        {
            OutputLine(api.Control.Get(), api.Control4.Get(), "error: could not recover function range\n");
            return E_FAIL;
        }

        bytes = ReadFunctionBytes(api.DataSpaces.Get(), regions);
        instructions = DisassembleRegions(api.DataSpaces.Get(), api.Control.Get(), regions, options.MaxInstructions, decodedContexts);

        request.RequestId = decomp::MakeRequestId();
        request.TimeoutMs = options.TimeoutMs;
        request.BriefOutput = options.BriefOutput;
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
        EnrichAnalysisFactsWithDebugMetadata(api.Symbols.Get(), api.DataSpaces.Get(), moduleInfo, decodedContexts, request.Facts);
        CollectPdbFacts(api.Symbols.Get(), api.Symbols5.Get(), moduleInfo, regions, request.Facts);
        ApplyPreferredNaturalLanguage(displayConfig, request.Facts);

        if (options.DisableLlm)
        {
            response = BuildAnalyzerOnlyResponse(request);
        }
        else
        {
            decomp::LlmClientConfig llmConfig;
            if (!decomp::LoadLlmClientConfig(llmConfig, error))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: llm config load failed: %s\n", error.c_str());
                return E_FAIL;
            }

            if (options.TimeoutMs != 5000 || llmConfig.TimeoutMs == 5000)
            {
                llmConfig.TimeoutMs = options.TimeoutMs;
            }

            if (!decomp::AnalyzeWithLlm(request, llmConfig, response, error))
            {
                OutputLine(api.Control.Get(), api.Control4.Get(), "error: llm analyze failed: %s\n", error.c_str());
                return E_FAIL;
            }
        }

        decomp::EnsurePseudoCodeTokens(response);
        decomp::VerifyResponse(request, response);
        PrintResponse(request, response, displayConfig, api.Control.Get(), api.Control4.Get(), api.Advanced2.Get(), options.JsonOutput);
        return S_OK;
    }
    while (false);

    return E_FAIL;
}













