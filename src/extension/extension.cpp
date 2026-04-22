#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <dbgeng.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <string>
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
    ComPtr<IDebugDataSpaces4> DataSpaces;
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

std::vector<decomp::DisassembledInstruction> DisassembleRegions(IDebugControl* control, const std::vector<decomp::FunctionRegion>& regions, uint32_t maxInstructions)
{
    std::vector<decomp::DisassembledInstruction> instructions;
    uint32_t remaining = maxInstructions;

    for (const auto& region : regions)
    {
        uint64_t current = region.Start;

        while (current < region.End && remaining > 0)
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
            --remaining;
            current = nextAddress;
        }
    }

    return instructions;
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
    response.PseudoC = "UNKNOWN_TYPE " + functionName + "(UNKNOWN_TYPE arg0)\n{\n    /* LLM disabled. Review analyzer facts. */\n    return UNKNOWN_VALUE;\n}\n";
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
        instructions = DisassembleRegions(api.Control.Get(), regions, options.MaxInstructions);

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













