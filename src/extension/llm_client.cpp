#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "decomp/json.h"
#include "decomp/llm_client.h"
#include "decomp/pseudo_tokens.h"
#include "decomp/protocol.h"
#include "decomp/string_utils.h"
#include "decomp/verifier.h"

namespace decomp
{
namespace
{
constexpr const char* kDefaultLlmConfigFileName = "decomp.llm.json";

void LogVerbose(const LlmClientConfig& config, const std::string& message)
{
    if (config.VerboseLog)
    {
        config.VerboseLog(message);
    }
}

void LogProgress(const LlmClientConfig& config, const std::string& message)
{
    if (config.ProgressLog)
    {
        config.ProgressLog(message);
    }
}

bool IsCancellationRequested(const LlmClientConfig& config)
{
    return config.ShouldCancel && config.ShouldCancel();
}

bool FailIfCancellationRequested(const LlmClientConfig& config, std::string& error)
{
    if (!IsCancellationRequested(config))
    {
        return false;
    }

    error = "operation cancelled by user";
    LogVerbose(config, error);
    return true;
}

uint64_t ElapsedMs(std::chrono::steady_clock::time_point start)
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
}

std::wstring Utf8ToWide(const std::string& text)
{
    if (text.empty())
    {
        return std::wstring();
    }

    const int count = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring wide(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), count);
    return wide;
}

std::string ReadEnvironmentVariable(const char* name)
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

std::string ReadFirstEnvironmentVariable(const std::vector<const char*>& names)
{
    for (const char* name : names)
    {
        const std::string value = ReadEnvironmentVariable(name);

        if (!value.empty())
        {
            return value;
        }
    }

    return std::string();
}

bool TryGetCurrentModulePath(std::string& modulePath)
{
    bool success = false;
    HMODULE module = nullptr;
    std::array<char, MAX_PATH> buffer = {};

    do
    {
        if (!GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&TryGetCurrentModulePath),
                &module))
        {
            break;
        }

        const DWORD length = GetModuleFileNameA(module, buffer.data(), static_cast<DWORD>(buffer.size()));

        if (length == 0 || length >= buffer.size())
        {
            break;
        }

        modulePath.assign(buffer.data(), length);
        success = true;
    }
    while (false);

    return success;
}

std::string BuildDefaultConfigPath()
{
    std::string modulePath;

    if (!TryGetCurrentModulePath(modulePath))
    {
        return kDefaultLlmConfigFileName;
    }

    const size_t slash = modulePath.find_last_of("\\/");

    if (slash == std::string::npos)
    {
        return kDefaultLlmConfigFileName;
    }

    return modulePath.substr(0, slash + 1) + kDefaultLlmConfigFileName;
}

std::string TrimErrorMessage(std::string text)
{
    while (!text.empty())
    {
        const char tail = text.back();

        if (tail == '\r' || tail == '\n' || tail == ' ' || tail == '\t' || tail == '.')
        {
            text.pop_back();
            continue;
        }

        break;
    }

    return text;
}

std::string FormatWin32ErrorMessage(DWORD errorCode)
{
    std::string text;
    LPSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageA(
        flags,
        nullptr,
        errorCode,
        0,
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr);

    if (length != 0 && buffer != nullptr)
    {
        text.assign(buffer, length);
        LocalFree(buffer);
    }

    return TrimErrorMessage(text);
}

std::string DescribeWinHttpError(const char* operation, DWORD errorCode)
{
    std::string text = std::string(operation) + " failed (" + std::to_string(errorCode) + ")";
    const std::string win32Text = FormatWin32ErrorMessage(errorCode);

    if (!win32Text.empty())
    {
        text += ": " + win32Text;
    }

    switch (errorCode)
    {
    case ERROR_WINHTTP_CANNOT_CONNECT:
        text += " [connect/proxy/firewall]";
        break;
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        text += " [dns resolution]";
        break;
    case ERROR_WINHTTP_TIMEOUT:
        text += " [timeout]";
        break;
    case ERROR_WINHTTP_SECURE_FAILURE:
        text += " [tls/certificate validation]";
        break;
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
        text += " [client certificate required]";
        break;
    case ERROR_WINHTTP_AUTODETECTION_FAILED:
        text += " [proxy auto-detection failed]";
        break;
    default:
        break;
    }

    return text;
}

bool ReadTextFile(const std::string& path, std::string& text, std::string& error)
{
    bool success = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        file = CreateFileA(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            error = DescribeWinHttpError("CreateFile", GetLastError()) + ": " + path;
            break;
        }

        LARGE_INTEGER size = {};

        if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 0x7FFFFFFF)
        {
            error = DescribeWinHttpError("GetFileSizeEx", GetLastError()) + ": " + path;
            break;
        }

        text.assign(static_cast<size_t>(size.QuadPart), '\0');

        if (text.empty())
        {
            success = true;
            break;
        }

        DWORD read = 0;

        if (!ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) || read != text.size())
        {
            error = DescribeWinHttpError("ReadFile", GetLastError()) + ": " + path;
            break;
        }

        success = true;
    }
    while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return success;
}

bool TryReadStringMember(
    const JsonValue& root,
    const char* name,
    std::string& value,
    std::string& error)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (!member->IsString())
    {
        error = std::string("config field '") + name + "' must be a string";
        return false;
    }

    value = member->GetString();
    return true;
}

bool TryReadFirstStringMember(
    const JsonValue& root,
    const std::vector<const char*>& names,
    std::string& value,
    std::string& error)
{
    std::string localValue;

    for (const char* name : names)
    {
        localValue.clear();

        if (!TryReadStringMember(root, name, localValue, error))
        {
            return false;
        }

        if (!localValue.empty())
        {
            value = localValue;
            return true;
        }
    }

    return true;
}

const JsonValue* FindFirstObjectMember(
    const JsonValue& root,
    const std::vector<const char*>& names,
    std::string& error)
{
    for (const char* name : names)
    {
        const JsonValue* member = root.Find(name);

        if (member == nullptr)
        {
            continue;
        }

        if (!member->IsObject())
        {
            error = std::string("config field '") + name + "' must be an object";
            return nullptr;
        }

        return member;
    }

    return nullptr;
}

bool TryParseBooleanString(
    const std::string& text,
    bool& value)
{
    std::string lowered;
    lowered.reserve(text.size());

    for (const char character : text)
    {
        lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }

    if (lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on")
    {
        value = true;
        return true;
    }

    if (lowered == "0" || lowered == "false" || lowered == "no" || lowered == "off")
    {
        value = false;
        return true;
    }

    return false;
}

bool TryReadBoolMember(
    const JsonValue& root,
    const char* name,
    bool& value,
    std::string& error)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (member->IsBoolean())
    {
        value = member->GetBoolean();
        return true;
    }

    if (member->IsString())
    {
        bool parsed = false;

        if (!TryParseBooleanString(member->GetString(), parsed))
        {
            error = std::string("config field '") + name + "' must be a boolean";
            return false;
        }

        value = parsed;
        return true;
    }

    error = std::string("config field '") + name + "' must be a boolean or string";
    return false;
}

bool TryReadFirstBoolMember(
    const JsonValue& root,
    const std::vector<const char*>& names,
    bool& value,
    std::string& error)
{
    for (const char* name : names)
    {
        if (root.Find(name) == nullptr)
        {
            continue;
        }

        return TryReadBoolMember(root, name, value, error);
    }

    return true;
}

bool TryReadUint32Member(
    const JsonValue& root,
    const char* name,
    uint32_t& value,
    std::string& error)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (member->IsNumber())
    {
        const double number = member->GetNumber();

        if (number < 0.0 || number > 4294967295.0)
        {
            error = std::string("config field '") + name + "' is out of range";
            return false;
        }

        value = static_cast<uint32_t>(number);
        return true;
    }

    if (member->IsString())
    {
        uint64_t parsed = 0;

        if (!TryParseUnsigned(member->GetString(), parsed) || parsed > 0xFFFFFFFFULL)
        {
            error = std::string("config field '") + name + "' must be a uint32 value";
            return false;
        }

        value = static_cast<uint32_t>(parsed);
        return true;
    }

    error = std::string("config field '") + name + "' must be a number or string";
    return false;
}

bool TryReadFirstUint32Member(
    const JsonValue& root,
    const std::vector<const char*>& names,
    uint32_t& value,
    std::string& error)
{
    for (const char* name : names)
    {
        if (root.Find(name) == nullptr)
        {
            continue;
        }

        return TryReadUint32Member(root, name, value, error);
    }

    return true;
}

bool TryLoadConfigFile(LlmClientConfig& config, std::string& error)
{
    bool success = false;
    const std::string configPath = BuildDefaultConfigPath();

    do
    {
        const DWORD attributes = GetFileAttributesA(configPath.c_str());

        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            success = true;
            break;
        }

        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            error = "config path is a directory: " + configPath;
            break;
        }

        std::string text;

        if (!ReadTextFile(configPath, text, error))
        {
            break;
        }

        const JsonParseResult parsed = ParseJson(text);

        if (!parsed.Success)
        {
            error = "invalid config JSON in " + configPath + ": " + parsed.Error;
            break;
        }

        if (!parsed.Value.IsObject())
        {
            error = "config root must be a JSON object: " + configPath;
            break;
        }

        std::string endpointValue;
        std::string modelValue;
        std::string apiKeyValue;
        std::string apiKeyEnvironmentName;
        uint32_t timeoutValue = config.TimeoutMs;
        uint32_t maxCompletionTokensValue = config.MaxCompletionTokens;
        bool forceChunkedValue = config.ForceChunked;
        uint32_t chunkTriggerInstructionsValue = config.ChunkTriggerInstructions;
        uint32_t chunkTriggerBlocksValue = config.ChunkTriggerBlocks;
        uint32_t chunkBlockLimitValue = config.ChunkBlockLimit;
        uint32_t chunkCountLimitValue = config.ChunkCountLimit;
        uint32_t chunkCompletionTokensValue = config.ChunkCompletionTokens;
        uint32_t mergeCompletionTokensValue = config.MergeCompletionTokens;
        DisplayLanguageConfig displayLanguageValue = config.DisplayLanguage;
        PseudoCodeHighlightConfig highlightValue = config.Highlight;

        if (!TryReadFirstStringMember(parsed.Value, { "endpoint", "url" }, endpointValue, error))
        {
            break;
        }

        if (!TryReadFirstStringMember(parsed.Value, { "model", "model_name", "modelName" }, modelValue, error))
        {
            break;
        }

        if (!TryReadFirstStringMember(parsed.Value, { "api_key", "apiKey", "key" }, apiKeyValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "timeout_ms", "timeoutMs" }, timeoutValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "max_completion_tokens", "maxCompletionTokens" }, maxCompletionTokensValue, error))
        {
            break;
        }

        if (!TryReadFirstStringMember(parsed.Value, { "api_key_env", "apiKeyEnv" }, apiKeyEnvironmentName, error))
        {
            break;
        }

        if (!TryReadFirstBoolMember(parsed.Value, { "force_chunked", "forceChunked" }, forceChunkedValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "chunk_trigger_instructions", "chunkTriggerInstructions" }, chunkTriggerInstructionsValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "chunk_trigger_blocks", "chunkTriggerBlocks" }, chunkTriggerBlocksValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "chunk_block_limit", "chunkBlockLimit" }, chunkBlockLimitValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "chunk_count_limit", "chunkCountLimit" }, chunkCountLimitValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "chunk_completion_tokens", "chunkCompletionTokens" }, chunkCompletionTokensValue, error))
        {
            break;
        }

        if (!TryReadFirstUint32Member(parsed.Value, { "merge_completion_tokens", "mergeCompletionTokens" }, mergeCompletionTokensValue, error))
        {
            break;
        }

        const JsonValue* displayLanguage = FindFirstObjectMember(parsed.Value, { "display_language", "displayLanguage" }, error);

        if (!error.empty())
        {
            break;
        }

        if (displayLanguage != nullptr)
        {
            if (!TryReadFirstStringMember(*displayLanguage, { "mode" }, displayLanguageValue.Mode, error)
                || !TryReadFirstStringMember(*displayLanguage, { "tag", "locale", "locale_tag", "localeTag" }, displayLanguageValue.Tag, error)
                || !TryReadFirstStringMember(*displayLanguage, { "name", "language", "language_name", "languageName" }, displayLanguageValue.Name, error))
            {
                break;
            }

            displayLanguageValue.Mode = ToLowerAscii(TrimCopy(displayLanguageValue.Mode));

            if (displayLanguageValue.Mode.empty())
            {
                displayLanguageValue.Mode = "auto";
            }

            if (displayLanguageValue.Mode != "auto" && displayLanguageValue.Mode != "fixed")
            {
                error = "config field 'display_language.mode' must be 'auto' or 'fixed'";
                break;
            }

            if (displayLanguageValue.Mode == "fixed"
                && TrimCopy(displayLanguageValue.Tag).empty()
                && TrimCopy(displayLanguageValue.Name).empty())
            {
                error = "config field 'display_language' requires 'tag' or 'name' when mode is 'fixed'";
                break;
            }
        }

        const JsonValue* syntaxHighlighting = FindFirstObjectMember(parsed.Value, { "syntax_highlighting", "syntaxHighlighting" }, error);

        if (!error.empty())
        {
            break;
        }

        if (syntaxHighlighting != nullptr)
        {
            if (!TryReadFirstStringMember(*syntaxHighlighting, { "keyword_color", "keywordColor" }, highlightValue.KeywordColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "type_color", "typeColor" }, highlightValue.TypeColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "function_name_color", "functionNameColor" }, highlightValue.FunctionNameColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "identifier_color", "identifierColor" }, highlightValue.IdentifierColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "number_color", "numberColor" }, highlightValue.NumberColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "string_color", "stringColor" }, highlightValue.StringColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "char_color", "charColor" }, highlightValue.CharColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "comment_color", "commentColor" }, highlightValue.CommentColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "preprocessor_color", "preprocessorColor" }, highlightValue.PreprocessorColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "operator_color", "operatorColor" }, highlightValue.OperatorColor, error)
                || !TryReadFirstStringMember(*syntaxHighlighting, { "punctuation_color", "punctuationColor" }, highlightValue.PunctuationColor, error))
            {
                break;
            }
        }

        if (!endpointValue.empty())
        {
            config.Endpoint = endpointValue;
        }

        if (!modelValue.empty())
        {
            config.Model = modelValue;
        }

        if (!apiKeyValue.empty())
        {
            config.ApiKey = apiKeyValue;
        }

        config.TimeoutMs = timeoutValue;
        config.MaxCompletionTokens = maxCompletionTokensValue;
        config.ForceChunked = forceChunkedValue;
        config.ChunkTriggerInstructions = chunkTriggerInstructionsValue;
        config.ChunkTriggerBlocks = chunkTriggerBlocksValue;
        config.ChunkBlockLimit = chunkBlockLimitValue;
        config.ChunkCountLimit = chunkCountLimitValue;
        config.ChunkCompletionTokens = chunkCompletionTokensValue;
        config.MergeCompletionTokens = mergeCompletionTokensValue;
        config.DisplayLanguage = displayLanguageValue;
        config.Highlight = highlightValue;

        if (config.ApiKey.empty() && !apiKeyEnvironmentName.empty())
        {
            config.ApiKey = ReadEnvironmentVariable(apiKeyEnvironmentName.c_str());
        }

        success = true;
    }
    while (false);

    return success;
}

void ApplyEnvironmentOverrides(LlmClientConfig& config)
{
    const std::string endpoint = ReadFirstEnvironmentVariable({ "DECOMP_LLM_ENDPOINT" });
    const std::string model = ReadFirstEnvironmentVariable({ "DECOMP_LLM_MODEL" });
    const std::string apiKey = ReadFirstEnvironmentVariable({ "DECOMP_LLM_API_KEY", "OPENAI_API_KEY" });
    const std::string timeout = ReadFirstEnvironmentVariable({ "DECOMP_LLM_TIMEOUT_MS" });
    const std::string maxCompletionTokens = ReadFirstEnvironmentVariable({ "DECOMP_LLM_MAX_COMPLETION_TOKENS" });
    const std::string forceChunked = ReadFirstEnvironmentVariable({ "DECOMP_LLM_FORCE_CHUNKED" });
    const std::string chunkTriggerInstructions = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_TRIGGER_INSTRUCTIONS" });
    const std::string chunkTriggerBlocks = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_TRIGGER_BLOCKS" });
    const std::string chunkBlockLimit = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_BLOCK_LIMIT" });
    const std::string chunkCountLimit = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_COUNT_LIMIT" });
    const std::string chunkCompletionTokens = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_COMPLETION_TOKENS" });
    const std::string mergeCompletionTokens = ReadFirstEnvironmentVariable({ "DECOMP_LLM_MERGE_COMPLETION_TOKENS" });

    if (!endpoint.empty())
    {
        config.Endpoint = endpoint;
    }

    if (!model.empty())
    {
        config.Model = model;
    }

    if (!apiKey.empty())
    {
        config.ApiKey = apiKey;
    }

    if (!timeout.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(timeout, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.TimeoutMs = static_cast<uint32_t>(parsed);
        }
    }

    if (!maxCompletionTokens.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(maxCompletionTokens, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.MaxCompletionTokens = static_cast<uint32_t>(parsed);
        }
    }

    if (!forceChunked.empty())
    {
        bool parsed = false;

        if (TryParseBooleanString(forceChunked, parsed))
        {
            config.ForceChunked = parsed;
        }
    }

    if (!chunkTriggerInstructions.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(chunkTriggerInstructions, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.ChunkTriggerInstructions = static_cast<uint32_t>(parsed);
        }
    }

    if (!chunkTriggerBlocks.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(chunkTriggerBlocks, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.ChunkTriggerBlocks = static_cast<uint32_t>(parsed);
        }
    }

    if (!chunkBlockLimit.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(chunkBlockLimit, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.ChunkBlockLimit = static_cast<uint32_t>(parsed);
        }
    }

    if (!chunkCountLimit.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(chunkCountLimit, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.ChunkCountLimit = static_cast<uint32_t>(parsed);
        }
    }

    if (!chunkCompletionTokens.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(chunkCompletionTokens, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.ChunkCompletionTokens = static_cast<uint32_t>(parsed);
        }
    }

    if (!mergeCompletionTokens.empty())
    {
        uint64_t parsed = 0;

        if (TryParseUnsigned(mergeCompletionTokens, parsed) && parsed <= 0xFFFFFFFFULL)
        {
            config.MergeCompletionTokens = static_cast<uint32_t>(parsed);
        }
    }
}
std::string SanitizeIdentifier(const std::string& value)
{
    std::string sanitized;

    for (const char ch : value)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0)
        {
            sanitized.push_back(ch);
        }
        else
        {
            sanitized.push_back('_');
        }
    }

    if (sanitized.empty())
    {
        sanitized = "analyzed_function";
    }

    return sanitized;
}

std::vector<std::string> EstimateParameters(const AnalyzeRequest& request)
{
    std::vector<std::string> params;
    const std::vector<std::pair<std::string, std::string>> candidates = {
        { "rcx", "arg0" },
        { "rdx", "arg1" },
        { "r8", "arg2" },
        { "r9", "arg3" }
    };

    for (const auto& candidate : candidates)
    {
        bool used = false;

        for (size_t index = 0; index < request.Facts.Instructions.size() && index < 32; ++index)
        {
            if (ContainsInsensitive(request.Facts.Instructions[index].OperationText, candidate.first))
            {
                used = true;
                break;
            }
        }

        if (used)
        {
            params.push_back(candidate.second);
        }
    }

    if (params.empty())
    {
        params.push_back("arg0");
    }

    return params;
}

std::vector<TypedNameConfidence> BuildAnalyzerSkeletonParams(const AnalyzeRequest& request)
{
    std::vector<TypedNameConfidence> params;

    if (!request.Facts.Pdb.Params.empty())
    {
        for (const PdbScopedSymbol& param : request.Facts.Pdb.Params)
        {
            TypedNameConfidence item;
            item.Name = SanitizeIdentifier(param.Name);
            item.Type = param.Type.empty() ? "UNKNOWN_TYPE" : param.Type;
            item.Confidence = param.Confidence;
            params.push_back(std::move(item));
        }
    }
    else if (!request.Facts.RecoveredArguments.empty())
    {
        for (const RecoveredArgument& argument : request.Facts.RecoveredArguments)
        {
            TypedNameConfidence item;
            item.Name = SanitizeIdentifier(argument.Name);
            item.Type = argument.TypeHint.empty() ? "UNKNOWN_TYPE" : argument.TypeHint;
            item.Confidence = argument.Confidence;
            params.push_back(std::move(item));
        }
    }
    else
    {
        const std::vector<std::string> parameterNames = EstimateParameters(request);

        for (const std::string& name : parameterNames)
        {
            TypedNameConfidence item;
            item.Name = name;
            item.Type = "UNKNOWN_TYPE";
            item.Confidence = 0.35;
            params.push_back(std::move(item));
        }
    }

    return params;
}

std::string BuildAnalyzerSkeletonPseudoC(const AnalyzeRequest& request)
{
    const std::vector<TypedNameConfidence> params = BuildAnalyzerSkeletonParams(request);
    const std::string functionName = !request.Facts.Pdb.FunctionName.empty()
        ? SanitizeIdentifier(request.Facts.Pdb.FunctionName)
        : SanitizeIdentifier(request.Facts.QueryText);
    const std::string returnType = !request.Facts.Pdb.ReturnType.empty() ? request.Facts.Pdb.ReturnType : "UNKNOWN_TYPE";
    std::string text;

    text += returnType + " " + functionName + "(";

    for (size_t index = 0; index < params.size(); ++index)
    {
        if (index != 0)
        {
            text += ", ";
        }

        text += params[index].Type + " " + params[index].Name;
    }

    text += ")\n{\n";
    text += "    /* analyzer skeleton: refine this, do not replace evidence with guesses */\n";
    text += "    /* blocks=" + std::to_string(request.Facts.Blocks.size())
        + ", ir_values=" + std::to_string(request.Facts.IrValues.size())
        + ", type_hints=" + std::to_string(request.Facts.TypeHints.size())
        + ", idioms=" + std::to_string(request.Facts.Idioms.size())
        + " */\n";

    for (size_t index = 0; index < request.Facts.ControlFlow.size() && index < 8; ++index)
    {
        const ControlFlowRegion& region = request.Facts.ControlFlow[index];
        text += "    /* region " + region.Kind + " header=" + region.HeaderBlock;

        if (!region.Condition.empty())
        {
            text += " condition=" + region.Condition;
        }

        text += " */\n";
    }

    for (size_t index = 0; index < request.Facts.NormalizedConditions.size() && index < 8; ++index)
    {
        const NormalizedCondition& condition = request.Facts.NormalizedConditions[index];
        text += "    /* if (" + condition.Expression + ") goto " + condition.TrueTargetBlock
            + " else " + condition.FalseTargetBlock + " */\n";
    }

    for (size_t index = 0; index < request.Facts.Idioms.size() && index < 8; ++index)
    {
        const IdiomPattern& idiom = request.Facts.Idioms[index];
        text += "    /* idiom " + idiom.Name + ": " + idiom.Replacement + " */\n";
    }

    for (size_t index = 0; index < request.Facts.CalleeSummaries.size() && index < 8; ++index)
    {
        const CalleeSummary& summary = request.Facts.CalleeSummaries[index];
        text += "    /* call " + summary.Callee + ": returns " + summary.ReturnType
            + ", effects=" + summary.SideEffects + " */\n";
    }

    if (!request.Facts.Abi.NoReturnCalls.empty())
    {
        text += "    /* no-return calls: " + JoinStrings(request.Facts.Abi.NoReturnCalls, "; ") + " */\n";
    }

    text += "    return UNKNOWN_VALUE;\n";
    text += "}\n";
    return text;
}

std::string BuildMockPseudoC(const AnalyzeRequest& request, std::vector<TypedNameConfidence>& params)
{
    params = BuildAnalyzerSkeletonParams(request);
    return BuildAnalyzerSkeletonPseudoC(request);
}

constexpr size_t kPromptRegionLimit = 8;
constexpr size_t kPromptBlockLimit = 48;
constexpr size_t kPromptBlockInstructionLimit = 8;
constexpr size_t kPromptDirectCallLimit = 32;
constexpr size_t kPromptIndirectCallLimit = 24;
constexpr size_t kPromptFactLimit = 32;
constexpr size_t kPromptUncertaintyLimit = 12;
constexpr size_t kPromptSwitchLimit = 10;
constexpr size_t kPromptMemoryAccessLimit = 32;
constexpr size_t kPromptInstructionWindowLimit = 20;
constexpr size_t kPromptRecoveredArgumentLimit = 8;
constexpr size_t kPromptRecoveredLocalLimit = 24;
constexpr size_t kPromptValueMergeLimit = 16;
constexpr size_t kPromptIrValueLimit = 32;
constexpr size_t kPromptControlFlowLimit = 24;
constexpr size_t kPromptTypeHintLimit = 32;
constexpr size_t kPromptIdiomLimit = 24;
constexpr size_t kPromptCalleeSummaryLimit = 32;
constexpr size_t kPromptDataReferenceLimit = 24;
constexpr size_t kPromptCallTargetLimit = 24;
constexpr size_t kPromptNormalizedConditionLimit = 24;
constexpr size_t kPromptPdbParamLimit = 12;
constexpr size_t kPromptPdbLocalLimit = 24;
constexpr size_t kPromptPdbFieldHintLimit = 24;
constexpr size_t kPromptPdbEnumHintLimit = 16;
constexpr size_t kPromptPdbSourceLocationLimit = 16;
constexpr size_t kPromptPdbConflictLimit = 12;
constexpr size_t kPromptObservedArgumentLimit = 8;
constexpr size_t kPromptObservedHotspotLimit = 12;
constexpr size_t kPromptTtdQueryLimit = 8;

std::string BuildInstructionSummary(const DisassembledInstruction& instruction)
{
    if (!instruction.OperationText.empty())
    {
        return instruction.OperationText;
    }

    if (!instruction.Text.empty())
    {
        return instruction.Text;
    }

    return instruction.Mnemonic;
}

std::string BuildInstructionPreview(const DisassembledInstruction& instruction)
{
    return HexU64(instruction.Address) + ": " + BuildInstructionSummary(instruction);
}

const DisassembledInstruction* FindInstructionByAddress(
    const AnalyzeRequest& request,
    uint64_t address)
{
    for (const DisassembledInstruction& instruction : request.Facts.Instructions)
    {
        if (instruction.Address == address)
        {
            return &instruction;
        }
    }

    return nullptr;
}

bool BlockContainsCallKind(
    const AnalyzeRequest& request,
    const BasicBlock& block,
    bool indirectOnly)
{
    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, address);

        if (instruction == nullptr)
        {
            continue;
        }

        if (instruction->IsCall && instruction->IsIndirect == indirectOnly)
        {
            return true;
        }
    }

    return false;
}

bool BlockContainsReturn(
    const AnalyzeRequest& request,
    const BasicBlock& block)
{
    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, address);

        if (instruction != nullptr && instruction->IsReturn)
        {
            return true;
        }
    }

    return false;
}

bool BlockContainsConditionalBranch(
    const AnalyzeRequest& request,
    const BasicBlock& block)
{
    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, address);

        if (instruction != nullptr && instruction->IsConditionalBranch)
        {
            return true;
        }
    }

    return false;
}

size_t CountBlockMemoryAccesses(
    const AnalyzeRequest& request,
    const BasicBlock& block)
{
    size_t count = 0;

    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, address);

        if (instruction != nullptr && instruction->OperandText.find('[') != std::string::npos)
        {
            ++count;
        }
    }

    return count;
}

std::vector<size_t> SelectSpreadIndices(size_t totalCount, size_t limit)
{
    std::vector<size_t> indices;

    if (totalCount == 0 || limit == 0)
    {
        return indices;
    }

    if (totalCount <= limit)
    {
        for (size_t index = 0; index < totalCount; ++index)
        {
            indices.push_back(index);
        }

        return indices;
    }

    std::set<size_t> selected;

    for (size_t slot = 0; slot < limit; ++slot)
    {
        const size_t index = (slot * (totalCount - 1)) / (limit - 1);

        if (selected.insert(index).second)
        {
            indices.push_back(index);
        }
    }

    for (size_t index = 0; index < totalCount && indices.size() < limit; ++index)
    {
        if (selected.insert(index).second)
        {
            indices.push_back(index);
        }
    }

    std::sort(indices.begin(), indices.end());
    return indices;
}

std::vector<size_t> SelectRepresentativeBlockIndices(const AnalyzeRequest& request)
{
    struct BlockScore
    {
        size_t Index = 0;
        size_t Score = 0;
    };

    std::vector<size_t> indices;
    const size_t totalBlocks = request.Facts.Blocks.size();

    if (totalBlocks == 0)
    {
        return indices;
    }

    const size_t limit = totalBlocks < kPromptBlockLimit ? totalBlocks : kPromptBlockLimit;
    std::set<size_t> selected;
    indices.push_back(0);
    selected.insert(0);

    std::vector<BlockScore> scores;
    scores.reserve(totalBlocks);

    for (size_t index = 0; index < totalBlocks; ++index)
    {
        const BasicBlock& block = request.Facts.Blocks[index];
        size_t score = 0;

        if (index == 0)
        {
            score += 1000;
        }

        if (BlockContainsCallKind(request, block, false))
        {
            score += 280;
        }

        if (BlockContainsCallKind(request, block, true))
        {
            score += 320;
        }

        if (block.Successors.size() >= 2)
        {
            score += 180;
        }

        if (BlockContainsConditionalBranch(request, block))
        {
            score += 140;
        }

        if (BlockContainsReturn(request, block))
        {
            score += 160;
        }

        const size_t memoryAccessCount = CountBlockMemoryAccesses(request, block);
        score += (memoryAccessCount > 8 ? 8 : memoryAccessCount) * 12;
        score += (block.InstructionAddresses.size() > 12 ? 12 : block.InstructionAddresses.size()) * 4;

        if (block.HasTerminal)
        {
            score += 40;
        }

        scores.push_back({ index, score });
    }

    std::sort(
        scores.begin(),
        scores.end(),
        [&request](const BlockScore& left, const BlockScore& right)
        {
            if (left.Score != right.Score)
            {
                return left.Score > right.Score;
            }

            return request.Facts.Blocks[left.Index].StartAddress < request.Facts.Blocks[right.Index].StartAddress;
        });

    const size_t featureBudget = limit / 2;

    for (const BlockScore& blockScore : scores)
    {
        if (indices.size() >= featureBudget)
        {
            break;
        }

        if (selected.insert(blockScore.Index).second)
        {
            indices.push_back(blockScore.Index);
        }
    }

    const std::vector<size_t> spread = SelectSpreadIndices(totalBlocks, limit);

    for (size_t index : spread)
    {
        if (indices.size() >= limit)
        {
            break;
        }

        if (selected.insert(index).second)
        {
            indices.push_back(index);
        }
    }

    std::sort(
        indices.begin(),
        indices.end(),
        [&request](size_t left, size_t right)
        {
            return request.Facts.Blocks[left].StartAddress < request.Facts.Blocks[right].StartAddress;
        });

    return indices;
}

JsonValue BuildStringArray(
    const std::vector<std::string>& values,
    size_t limit,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();

    if (truncated != nullptr)
    {
        *truncated = values.size() > limit;
    }

    const size_t count = values.size() < limit ? values.size() : limit;

    for (size_t index = 0; index < count; ++index)
    {
        array.PushBack(JsonValue::MakeString(values[index]));
    }

    return array;
}

JsonValue BuildRegionsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue regions = JsonValue::MakeArray();

    if (truncated != nullptr)
    {
        *truncated = request.Facts.Regions.size() > kPromptRegionLimit;
    }

    const size_t count = request.Facts.Regions.size() < kPromptRegionLimit ? request.Facts.Regions.size() : kPromptRegionLimit;

    for (size_t index = 0; index < count; ++index)
    {
        const FunctionRegion& region = request.Facts.Regions[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("start", JsonValue::MakeString(HexU64(region.Start)));
        item.Set("end", JsonValue::MakeString(HexU64(region.End)));
        regions.PushBack(item);
    }

    return regions;
}

JsonValue BuildInstructionWindowJson(const AnalyzeRequest& request, bool tail)
{
    JsonValue window = JsonValue::MakeArray();
    const size_t total = request.Facts.Instructions.size();

    if (total == 0)
    {
        return window;
    }

    size_t startIndex = 0;
    size_t count = total < kPromptInstructionWindowLimit ? total : kPromptInstructionWindowLimit;

    if (tail && total > count)
    {
        startIndex = total - count;
    }

    for (size_t index = 0; index < count; ++index)
    {
        window.PushBack(JsonValue::MakeString(BuildInstructionPreview(request.Facts.Instructions[startIndex + index])));
    }

    return window;
}

JsonValue BuildInstructionWindowJson(const AnalyzeRequest& request, size_t centerIndex)
{
    JsonValue window = JsonValue::MakeArray();
    const size_t total = request.Facts.Instructions.size();

    if (total == 0)
    {
        return window;
    }

    const size_t count = total < kPromptInstructionWindowLimit ? total : kPromptInstructionWindowLimit;
    size_t startIndex = 0;

    if (total > count)
    {
        const size_t half = count / 2;

        if (centerIndex > half)
        {
            startIndex = centerIndex - half;
        }

        if (startIndex + count > total)
        {
            startIndex = total - count;
        }
    }

    for (size_t index = 0; index < count; ++index)
    {
        window.PushBack(JsonValue::MakeString(BuildInstructionPreview(request.Facts.Instructions[startIndex + index])));
    }

    return window;
}

std::optional<size_t> FindMiddleInterestingInstructionIndex(const AnalyzeRequest& request)
{
    if (request.Facts.Instructions.empty())
    {
        return std::nullopt;
    }

    const size_t middle = request.Facts.Instructions.size() / 2;

    for (size_t radius = 0; radius < request.Facts.Instructions.size(); ++radius)
    {
        if (middle >= radius)
        {
            const size_t index = middle - radius;
            const DisassembledInstruction& instruction = request.Facts.Instructions[index];

            if (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || instruction.OperandText.find('[') != std::string::npos)
            {
                return index;
            }
        }

        const size_t forward = middle + radius;

        if (forward < request.Facts.Instructions.size())
        {
            const DisassembledInstruction& instruction = request.Facts.Instructions[forward];

            if (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || instruction.OperandText.find('[') != std::string::npos)
            {
                return forward;
            }
        }
    }

    return middle;
}

JsonValue BuildBlocksJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue blocks = JsonValue::MakeArray();
    const std::vector<size_t> selectedIndices = SelectRepresentativeBlockIndices(request);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.Blocks.size() > selectedIndices.size();
    }

    for (size_t selectedIndex : selectedIndices)
    {
        const BasicBlock& block = request.Facts.Blocks[selectedIndex];
        JsonValue item = JsonValue::MakeObject();
        JsonValue instructionHeadSample = JsonValue::MakeArray();
        JsonValue instructionTailSample = JsonValue::MakeArray();
        const size_t headCount = block.InstructionAddresses.size() < kPromptBlockInstructionLimit ? block.InstructionAddresses.size() : kPromptBlockInstructionLimit;
        const size_t tailCount = block.InstructionAddresses.size() < 4 ? block.InstructionAddresses.size() : 4;

        for (size_t instructionIndex = 0; instructionIndex < headCount; ++instructionIndex)
        {
            const DisassembledInstruction* instruction = FindInstructionByAddress(request, block.InstructionAddresses[instructionIndex]);

            if (instruction != nullptr)
            {
                instructionHeadSample.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instruction)));
            }
        }

        if (block.InstructionAddresses.size() > tailCount)
        {
            for (size_t instructionIndex = block.InstructionAddresses.size() - tailCount; instructionIndex < block.InstructionAddresses.size(); ++instructionIndex)
            {
                const DisassembledInstruction* instruction = FindInstructionByAddress(request, block.InstructionAddresses[instructionIndex]);

                if (instruction != nullptr)
                {
                    instructionTailSample.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instruction)));
                }
            }
        }

        item.Set("id", JsonValue::MakeString(block.Id));
        item.Set("start", JsonValue::MakeString(HexU64(block.StartAddress)));
        item.Set("end", JsonValue::MakeString(HexU64(block.EndAddress)));
        item.Set("succ", BuildStringArray(block.Successors, 8, nullptr));
        item.Set("terminal", JsonValue::MakeBoolean(block.HasTerminal));
        item.Set("instruction_count", JsonValue::MakeNumber(static_cast<double>(block.InstructionAddresses.size())));
        item.Set("memory_access_count", JsonValue::MakeNumber(static_cast<double>(CountBlockMemoryAccesses(request, block))));
        item.Set("has_direct_call", JsonValue::MakeBoolean(BlockContainsCallKind(request, block, false)));
        item.Set("has_indirect_call", JsonValue::MakeBoolean(BlockContainsCallKind(request, block, true)));
        item.Set("has_return", JsonValue::MakeBoolean(BlockContainsReturn(request, block)));
        item.Set("has_conditional_branch", JsonValue::MakeBoolean(BlockContainsConditionalBranch(request, block)));
        item.Set("insn_head_sample", instructionHeadSample);
        item.Set("insn_tail_sample", instructionTailSample);
        blocks.PushBack(item);
    }

    return blocks;
}

JsonValue BuildCallsJson(
    const std::vector<CallSite>& calls,
    size_t limit,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(calls.size(), limit);

    if (truncated != nullptr)
    {
        *truncated = calls.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const CallSite& call = calls[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(call.Site)));
        item.Set("target", JsonValue::MakeString(call.Target));
        item.Set("kind", JsonValue::MakeString(call.Kind));
        item.Set("returns", JsonValue::MakeBoolean(call.Returns));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildSwitchesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.Switches.size(), kPromptSwitchLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.Switches.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const SwitchInfo& info = request.Facts.Switches[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(info.Site)));
        item.Set("case_count", JsonValue::MakeNumber(static_cast<double>(info.CaseCount)));
        item.Set("detail", JsonValue::MakeString(info.Detail));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildMemoryAccessesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.MemoryAccesses.size(), kPromptMemoryAccessLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.MemoryAccesses.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const MemoryAccess& access = request.Facts.MemoryAccesses[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(access.Site)));
        item.Set("access", JsonValue::MakeString(access.Access));
        item.Set("kind", JsonValue::MakeString(access.Kind));
        item.Set("size", JsonValue::MakeString(access.Size));
        item.Set("width_bits", JsonValue::MakeNumber(static_cast<double>(access.WidthBits)));
        item.Set("base_register", JsonValue::MakeString(access.BaseRegister));
        item.Set("index_register", JsonValue::MakeString(access.IndexRegister));
        item.Set("scale", JsonValue::MakeNumber(static_cast<double>(access.Scale)));
        item.Set("displacement", JsonValue::MakeString(access.Displacement));
        item.Set("rip_relative", JsonValue::MakeBoolean(access.RipRelative));
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, access.Site);
        item.Set("instruction", JsonValue::MakeString(instruction != nullptr ? BuildInstructionPreview(*instruction) : std::string()));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildRecoveredArgumentsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.RecoveredArguments.size(), kPromptRecoveredArgumentLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.RecoveredArguments.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const RecoveredArgument& argument = request.Facts.RecoveredArguments[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(argument.Name));
        item.Set("register", JsonValue::MakeString(argument.Register));
        item.Set("type_hint", JsonValue::MakeString(argument.TypeHint));
        item.Set("role_hint", JsonValue::MakeString(argument.RoleHint));
        item.Set("first_use_site", JsonValue::MakeString(HexU64(argument.FirstUseSite)));
        item.Set("use_count", JsonValue::MakeNumber(static_cast<double>(argument.UseCount)));
        item.Set("confidence", JsonValue::MakeNumber(argument.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildRecoveredLocalsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.RecoveredLocals.size(), kPromptRecoveredLocalLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.RecoveredLocals.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const RecoveredLocal& local = request.Facts.RecoveredLocals[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(local.Name));
        item.Set("base_register", JsonValue::MakeString(local.BaseRegister));
        item.Set("offset", JsonValue::MakeString(HexS64(local.Offset)));
        item.Set("storage", JsonValue::MakeString(local.Storage));
        item.Set("type_hint", JsonValue::MakeString(local.TypeHint));
        item.Set("role_hint", JsonValue::MakeString(local.RoleHint));
        item.Set("first_site", JsonValue::MakeString(HexU64(local.FirstSite)));
        item.Set("last_site", JsonValue::MakeString(HexU64(local.LastSite)));
        item.Set("read_count", JsonValue::MakeNumber(static_cast<double>(local.ReadCount)));
        item.Set("write_count", JsonValue::MakeNumber(static_cast<double>(local.WriteCount)));
        item.Set("confidence", JsonValue::MakeNumber(local.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildValueMergesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.ValueMerges.size(), kPromptValueMergeLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.ValueMerges.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const ValueMerge& merge = request.Facts.ValueMerges[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("block_id", JsonValue::MakeString(merge.BlockId));
        item.Set("variable", JsonValue::MakeString(merge.Variable));
        item.Set("predecessors", BuildStringArray(merge.Predecessors, 8, nullptr));
        item.Set("incoming_values", BuildStringArray(merge.IncomingValues, 8, nullptr));
        item.Set("confidence", JsonValue::MakeNumber(merge.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildIrValuesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.IrValues.size(), kPromptIrValueLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.IrValues.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const IrValue& value = request.Facts.IrValues[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("id", JsonValue::MakeString(value.Id));
        item.Set("block_id", JsonValue::MakeString(value.BlockId));
        item.Set("def_site", JsonValue::MakeString(HexU64(value.DefSite)));
        item.Set("target", JsonValue::MakeString(value.Target));
        item.Set("expression", JsonValue::MakeString(value.Expression));
        item.Set("canonical", JsonValue::MakeString(value.Canonical));
        item.Set("kind", JsonValue::MakeString(value.Kind));
        item.Set("uses", BuildStringArray(value.Uses, 8, nullptr));
        item.Set("is_constant", JsonValue::MakeBoolean(value.IsConstant));
        item.Set("is_copy", JsonValue::MakeBoolean(value.IsCopy));
        item.Set("is_dead", JsonValue::MakeBoolean(value.IsDead));
        item.Set("confidence", JsonValue::MakeNumber(value.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildControlFlowJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.ControlFlow.size(), kPromptControlFlowLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.ControlFlow.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const ControlFlowRegion& region = request.Facts.ControlFlow[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("kind", JsonValue::MakeString(region.Kind));
        item.Set("header_block", JsonValue::MakeString(region.HeaderBlock));
        item.Set("body_blocks", BuildStringArray(region.BodyBlocks, 16, nullptr));
        item.Set("latch_blocks", BuildStringArray(region.LatchBlocks, 8, nullptr));
        item.Set("exit_blocks", BuildStringArray(region.ExitBlocks, 8, nullptr));
        item.Set("condition", JsonValue::MakeString(region.Condition));
        item.Set("evidence", JsonValue::MakeString(region.Evidence));
        item.Set("confidence", JsonValue::MakeNumber(region.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildAbiJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    bool anyTruncated = false;
    bool memberTruncated = false;

    object.Set("shadow_space_bytes", JsonValue::MakeNumber(static_cast<double>(request.Facts.Abi.ShadowSpaceBytes)));
    object.Set("prolog_recognized", JsonValue::MakeBoolean(request.Facts.Abi.PrologRecognized));
    object.Set("epilog_recognized", JsonValue::MakeBoolean(request.Facts.Abi.EpilogRecognized));
    object.Set("frame_pointer_established", JsonValue::MakeBoolean(request.Facts.Abi.FramePointerEstablished));
    object.Set("frame_base", JsonValue::MakeString(request.Facts.Abi.FrameBase));
    object.Set("home_slots", BuildStringArray(request.Facts.Abi.HomeSlots, 16, &memberTruncated));
    anyTruncated = anyTruncated || memberTruncated;
    object.Set("no_return_calls", BuildStringArray(request.Facts.Abi.NoReturnCalls, 12, &memberTruncated));
    anyTruncated = anyTruncated || memberTruncated;
    object.Set("tail_calls", BuildStringArray(request.Facts.Abi.TailCalls, 12, &memberTruncated));
    anyTruncated = anyTruncated || memberTruncated;
    object.Set("thunks", BuildStringArray(request.Facts.Abi.Thunks, 8, &memberTruncated));
    anyTruncated = anyTruncated || memberTruncated;
    object.Set("import_wrappers", BuildStringArray(request.Facts.Abi.ImportWrappers, 8, &memberTruncated));
    anyTruncated = anyTruncated || memberTruncated;
    object.Set("notes", BuildStringArray(request.Facts.Abi.Notes, 12, &memberTruncated));
    anyTruncated = anyTruncated || memberTruncated;
    object.Set("confidence", JsonValue::MakeNumber(request.Facts.Abi.Confidence));

    if (truncated != nullptr)
    {
        *truncated = anyTruncated;
    }

    return object;
}

JsonValue BuildTypeHintsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.TypeHints.size(), kPromptTypeHintLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.TypeHints.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const TypeRecoveryHint& hint = request.Facts.TypeHints[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(hint.Site)));
        item.Set("expression", JsonValue::MakeString(hint.Expression));
        item.Set("type", JsonValue::MakeString(hint.Type));
        item.Set("source", JsonValue::MakeString(hint.Source));
        item.Set("kind", JsonValue::MakeString(hint.Kind));
        item.Set("evidence", JsonValue::MakeString(hint.Evidence));
        item.Set("pointer_like", JsonValue::MakeBoolean(hint.PointerLike));
        item.Set("array_like", JsonValue::MakeBoolean(hint.ArrayLike));
        item.Set("enum_like", JsonValue::MakeBoolean(hint.EnumLike));
        item.Set("bitflag_like", JsonValue::MakeBoolean(hint.BitflagLike));
        item.Set("confidence", JsonValue::MakeNumber(hint.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildIdiomsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.Idioms.size(), kPromptIdiomLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.Idioms.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const IdiomPattern& idiom = request.Facts.Idioms[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(idiom.Site)));
        item.Set("kind", JsonValue::MakeString(idiom.Kind));
        item.Set("name", JsonValue::MakeString(idiom.Name));
        item.Set("summary", JsonValue::MakeString(idiom.Summary));
        item.Set("replacement", JsonValue::MakeString(idiom.Replacement));
        item.Set("evidence", JsonValue::MakeString(idiom.Evidence));
        item.Set("confidence", JsonValue::MakeNumber(idiom.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildCalleeSummariesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.CalleeSummaries.size(), kPromptCalleeSummaryLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.CalleeSummaries.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const CalleeSummary& summary = request.Facts.CalleeSummaries[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(summary.Site)));
        item.Set("callee", JsonValue::MakeString(summary.Callee));
        item.Set("return_type", JsonValue::MakeString(summary.ReturnType));
        item.Set("parameter_model", JsonValue::MakeString(summary.ParameterModel));
        item.Set("side_effects", JsonValue::MakeString(summary.SideEffects));
        item.Set("memory_effects", JsonValue::MakeString(summary.MemoryEffects));
        item.Set("ownership", JsonValue::MakeString(summary.Ownership));
        item.Set("source", JsonValue::MakeString(summary.Source));
        item.Set("confidence", JsonValue::MakeNumber(summary.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildDataReferencesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.DataReferences.size(), kPromptDataReferenceLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.DataReferences.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const DataReference& reference = request.Facts.DataReferences[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(reference.Site)));
        item.Set("target_address", JsonValue::MakeString(HexU64(reference.TargetAddress)));
        item.Set("kind", JsonValue::MakeString(reference.Kind));
        item.Set("symbol", JsonValue::MakeString(reference.Symbol));
        item.Set("module_name", JsonValue::MakeString(reference.ModuleName));
        item.Set("display", JsonValue::MakeString(reference.Display));
        item.Set("preview", JsonValue::MakeString(reference.Preview));
        item.Set("rip_relative", JsonValue::MakeBoolean(reference.RipRelative));
        item.Set("dereferenced", JsonValue::MakeBoolean(reference.Dereferenced));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildCallTargetsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.CallTargets.size(), kPromptCallTargetLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.CallTargets.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const CallTargetInfo& call = request.Facts.CallTargets[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(call.Site)));
        item.Set("target_address", JsonValue::MakeString(HexU64(call.TargetAddress)));
        item.Set("display_name", JsonValue::MakeString(call.DisplayName));
        item.Set("target_kind", JsonValue::MakeString(call.TargetKind));
        item.Set("module_name", JsonValue::MakeString(call.ModuleName));
        item.Set("prototype", JsonValue::MakeString(call.Prototype));
        item.Set("return_type", JsonValue::MakeString(call.ReturnType));
        item.Set("side_effects", JsonValue::MakeString(call.SideEffects));
        item.Set("indirect", JsonValue::MakeBoolean(call.Indirect));
        item.Set("confidence", JsonValue::MakeNumber(call.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildNormalizedConditionsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.NormalizedConditions.size(), kPromptNormalizedConditionLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.NormalizedConditions.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const NormalizedCondition& condition = request.Facts.NormalizedConditions[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(condition.Site)));
        item.Set("block_id", JsonValue::MakeString(condition.BlockId));
        item.Set("branch_mnemonic", JsonValue::MakeString(condition.BranchMnemonic));
        item.Set("expression", JsonValue::MakeString(condition.Expression));
        item.Set("true_target_block", JsonValue::MakeString(condition.TrueTargetBlock));
        item.Set("false_target_block", JsonValue::MakeString(condition.FalseTargetBlock));
        item.Set("confidence", JsonValue::MakeNumber(condition.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildPdbFactsJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue params = JsonValue::MakeArray();
    JsonValue locals = JsonValue::MakeArray();
    JsonValue fieldHints = JsonValue::MakeArray();
    JsonValue enumHints = JsonValue::MakeArray();
    JsonValue sourceLocations = JsonValue::MakeArray();
    JsonValue conflicts = JsonValue::MakeArray();
    bool anyTruncated = false;

    const std::vector<size_t> paramIndices = SelectSpreadIndices(request.Facts.Pdb.Params.size(), kPromptPdbParamLimit);
    const std::vector<size_t> localIndices = SelectSpreadIndices(request.Facts.Pdb.Locals.size(), kPromptPdbLocalLimit);
    const std::vector<size_t> fieldIndices = SelectSpreadIndices(request.Facts.Pdb.FieldHints.size(), kPromptPdbFieldHintLimit);
    const std::vector<size_t> enumIndices = SelectSpreadIndices(request.Facts.Pdb.EnumHints.size(), kPromptPdbEnumHintLimit);
    const std::vector<size_t> sourceIndices = SelectSpreadIndices(request.Facts.Pdb.SourceLocations.size(), kPromptPdbSourceLocationLimit);
    const std::vector<size_t> conflictIndices = SelectSpreadIndices(request.Facts.Pdb.Conflicts.size(), kPromptPdbConflictLimit);

    anyTruncated = anyTruncated
        || request.Facts.Pdb.Params.size() > paramIndices.size()
        || request.Facts.Pdb.Locals.size() > localIndices.size()
        || request.Facts.Pdb.FieldHints.size() > fieldIndices.size()
        || request.Facts.Pdb.EnumHints.size() > enumIndices.size()
        || request.Facts.Pdb.SourceLocations.size() > sourceIndices.size()
        || request.Facts.Pdb.Conflicts.size() > conflictIndices.size();

    for (size_t index : paramIndices)
    {
        const PdbScopedSymbol& symbol = request.Facts.Pdb.Params[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(symbol.Name));
        item.Set("type", JsonValue::MakeString(symbol.Type));
        item.Set("storage", JsonValue::MakeString(symbol.Storage));
        item.Set("location", JsonValue::MakeString(symbol.Location));
        item.Set("site", JsonValue::MakeString(HexU64(symbol.Site)));
        item.Set("confidence", JsonValue::MakeNumber(symbol.Confidence));
        params.PushBack(item);
    }

    for (size_t index : localIndices)
    {
        const PdbScopedSymbol& symbol = request.Facts.Pdb.Locals[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(symbol.Name));
        item.Set("type", JsonValue::MakeString(symbol.Type));
        item.Set("storage", JsonValue::MakeString(symbol.Storage));
        item.Set("location", JsonValue::MakeString(symbol.Location));
        item.Set("site", JsonValue::MakeString(HexU64(symbol.Site)));
        item.Set("confidence", JsonValue::MakeNumber(symbol.Confidence));
        locals.PushBack(item);
    }

    for (size_t index : fieldIndices)
    {
        const PdbFieldHint& hint = request.Facts.Pdb.FieldHints[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("base_name", JsonValue::MakeString(hint.BaseName));
        item.Set("base_type", JsonValue::MakeString(hint.BaseType));
        item.Set("field_name", JsonValue::MakeString(hint.FieldName));
        item.Set("field_type", JsonValue::MakeString(hint.FieldType));
        item.Set("base_register", JsonValue::MakeString(hint.BaseRegister));
        item.Set("offset", JsonValue::MakeString(HexS64(hint.Offset)));
        item.Set("site", JsonValue::MakeString(HexU64(hint.Site)));
        item.Set("confidence", JsonValue::MakeNumber(hint.Confidence));
        fieldHints.PushBack(item);
    }

    for (size_t index : enumIndices)
    {
        const PdbEnumHint& hint = request.Facts.Pdb.EnumHints[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("type_name", JsonValue::MakeString(hint.TypeName));
        item.Set("constant_name", JsonValue::MakeString(hint.ConstantName));
        item.Set("expression", JsonValue::MakeString(hint.Expression));
        item.Set("value", JsonValue::MakeString(HexU64(hint.Value)));
        item.Set("site", JsonValue::MakeString(HexU64(hint.Site)));
        item.Set("confidence", JsonValue::MakeNumber(hint.Confidence));
        enumHints.PushBack(item);
    }

    for (size_t index : sourceIndices)
    {
        const PdbSourceLocation& source = request.Facts.Pdb.SourceLocations[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(source.Site)));
        item.Set("file", JsonValue::MakeString(source.File));
        item.Set("line", JsonValue::MakeNumber(static_cast<double>(source.Line)));
        item.Set("displacement", JsonValue::MakeString(HexU64(source.Displacement)));
        item.Set("confidence", JsonValue::MakeNumber(source.Confidence));
        sourceLocations.PushBack(item);
    }

    for (size_t index : conflictIndices)
    {
        conflicts.PushBack(JsonValue::MakeString(request.Facts.Pdb.Conflicts[index]));
    }

    object.Set("availability", JsonValue::MakeString(request.Facts.Pdb.Availability));
    object.Set("scope_kind", JsonValue::MakeString(request.Facts.Pdb.ScopeKind));
    object.Set("symbol_file", JsonValue::MakeString(request.Facts.Pdb.SymbolFile));
    object.Set("function_name", JsonValue::MakeString(request.Facts.Pdb.FunctionName));
    object.Set("prototype", JsonValue::MakeString(request.Facts.Pdb.Prototype));
    object.Set("return_type", JsonValue::MakeString(request.Facts.Pdb.ReturnType));
    object.Set("params", params);
    object.Set("locals", locals);
    object.Set("field_hints", fieldHints);
    object.Set("enum_hints", enumHints);
    object.Set("source_locations", sourceLocations);
    object.Set("conflicts", conflicts);
    object.Set("confidence", JsonValue::MakeNumber(request.Facts.Pdb.Confidence));

    if (truncated != nullptr)
    {
        *truncated = anyTruncated;
    }

    return object;
}

JsonValue BuildSessionPolicyJson(const AnalyzeRequest& request)
{
    JsonValue object = JsonValue::MakeObject();
    const SessionPolicyFacts& policy = request.Facts.SessionPolicy;

    object.Set("debug_class", JsonValue::MakeString(policy.DebugClass));
    object.Set("qualifier", JsonValue::MakeString(policy.Qualifier));
    object.Set("execution_kind", JsonValue::MakeString(policy.ExecutionKind));
    object.Set("analysis_strategy", JsonValue::MakeString(policy.AnalysisStrategy));
    object.Set("is_live", JsonValue::MakeBoolean(policy.IsLive));
    object.Set("is_dump", JsonValue::MakeBoolean(policy.IsDump));
    object.Set("is_kernel", JsonValue::MakeBoolean(policy.IsKernel));
    object.Set("is_trace_like", JsonValue::MakeBoolean(policy.IsTraceLike));
    object.Set("ttd_available", JsonValue::MakeBoolean(policy.TtdAvailable));
    object.Set("notes", BuildStringArray(policy.Notes, 12, nullptr));
    return object;
}

JsonValue BuildObservedBehaviorJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue arguments = JsonValue::MakeArray();
    JsonValue hotspots = JsonValue::MakeArray();
    bool anyTruncated = false;

    const ObservedBehaviorFacts& observed = request.Facts.ObservedBehavior;
    const std::vector<size_t> argumentIndices = SelectSpreadIndices(observed.ArgumentSamples.size(), kPromptObservedArgumentLimit);
    const std::vector<size_t> hotspotIndices = SelectSpreadIndices(observed.MemoryHotspots.size(), kPromptObservedHotspotLimit);

    anyTruncated = observed.ArgumentSamples.size() > argumentIndices.size()
        || observed.MemoryHotspots.size() > hotspotIndices.size()
        || observed.TtdQueries.size() > kPromptTtdQueryLimit;

    for (const size_t index : argumentIndices)
    {
        const ObservedArgumentValue& argument = observed.ArgumentSamples[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(argument.Name));
        item.Set("register", JsonValue::MakeString(argument.Register));
        item.Set("value", JsonValue::MakeString(HexU64(argument.Value)));
        item.Set("symbol", JsonValue::MakeString(argument.Symbol));
        item.Set("source", JsonValue::MakeString(argument.Source));
        item.Set("confidence", JsonValue::MakeNumber(argument.Confidence));
        arguments.PushBack(item);
    }

    for (const size_t index : hotspotIndices)
    {
        const ObservedMemoryHotspot& hotspot = observed.MemoryHotspots[index];
        JsonValue item = JsonValue::MakeObject();
        JsonValue sites = JsonValue::MakeArray();

        for (const auto site : hotspot.Sites)
        {
            sites.PushBack(JsonValue::MakeString(HexU64(site)));
        }

        item.Set("expression", JsonValue::MakeString(hotspot.Expression));
        item.Set("kind", JsonValue::MakeString(hotspot.Kind));
        item.Set("read_count", JsonValue::MakeNumber(static_cast<double>(hotspot.ReadCount)));
        item.Set("write_count", JsonValue::MakeNumber(static_cast<double>(hotspot.WriteCount)));
        item.Set("sites", sites);
        item.Set("confidence", JsonValue::MakeNumber(hotspot.Confidence));
        hotspots.PushBack(item);
    }

    object.Set("current_instruction_in_function", JsonValue::MakeBoolean(observed.CurrentInstructionInFunction));
    object.Set("instruction_pointer", JsonValue::MakeString(HexU64(observed.InstructionPointer)));
    object.Set("stack_pointer", JsonValue::MakeString(HexU64(observed.StackPointer)));
    object.Set("return_address", JsonValue::MakeString(HexU64(observed.ReturnAddress)));
    object.Set("argument_samples", arguments);
    object.Set("memory_hotspots", hotspots);
    object.Set("ttd_queries", BuildStringArray(observed.TtdQueries, kPromptTtdQueryLimit, nullptr));
    object.Set("notes", BuildStringArray(observed.Notes, 12, nullptr));
    object.Set("confidence", JsonValue::MakeNumber(observed.Confidence));

    if (truncated != nullptr)
    {
        *truncated = anyTruncated;
    }

    return object;
}

JsonValue BuildCountsJson(const AnalyzeRequest& request)
{
    JsonValue counts = JsonValue::MakeObject();
    counts.Set("instructions_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Instructions.size())));
    counts.Set("blocks_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Blocks.size())));
    counts.Set("direct_calls_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Calls.size())));
    counts.Set("indirect_calls_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.IndirectCalls.size())));
    counts.Set("switches_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Switches.size())));
    counts.Set("memory_accesses_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.MemoryAccesses.size())));
    counts.Set("recovered_arguments_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.RecoveredArguments.size())));
    counts.Set("recovered_locals_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.RecoveredLocals.size())));
    counts.Set("value_merges_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.ValueMerges.size())));
    counts.Set("ir_values_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.IrValues.size())));
    counts.Set("control_flow_regions_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.ControlFlow.size())));
    counts.Set("type_hints_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.TypeHints.size())));
    counts.Set("idioms_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Idioms.size())));
    counts.Set("callee_summaries_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.CalleeSummaries.size())));
    counts.Set("data_references_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.DataReferences.size())));
    counts.Set("call_targets_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.CallTargets.size())));
    counts.Set("normalized_conditions_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.NormalizedConditions.size())));
    counts.Set("pdb_params_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.Params.size())));
    counts.Set("pdb_locals_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.Locals.size())));
    counts.Set("pdb_field_hints_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.FieldHints.size())));
    counts.Set("pdb_enum_hints_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.EnumHints.size())));
    counts.Set("pdb_source_locations_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.SourceLocations.size())));
    counts.Set("facts_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Facts.size())));
    counts.Set("uncertainties_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.UncertainPoints.size())));
    return counts;
}

JsonValue BuildGraphSummaryJson(const AnalyzeRequest& request)
{
    JsonValue graph = JsonValue::MakeObject();
    JsonValue entry = JsonValue::MakeObject();
    JsonValue regions = JsonValue::MakeArray();
    JsonValue conditions = JsonValue::MakeArray();
    JsonValue importantBlocks = JsonValue::MakeArray();

    if (!request.Facts.Blocks.empty())
    {
        const BasicBlock& first = request.Facts.Blocks.front();
        entry.Set("id", JsonValue::MakeString(first.Id));
        entry.Set("start", JsonValue::MakeString(HexU64(first.StartAddress)));
        entry.Set("successors", BuildStringArray(first.Successors, 8, nullptr));
    }

    for (size_t index = 0; index < request.Facts.ControlFlow.size() && index < kPromptControlFlowLimit; ++index)
    {
        const ControlFlowRegion& region = request.Facts.ControlFlow[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("kind", JsonValue::MakeString(region.Kind));
        item.Set("header", JsonValue::MakeString(region.HeaderBlock));
        item.Set("condition", JsonValue::MakeString(region.Condition));
        item.Set("body", BuildStringArray(region.BodyBlocks, 16, nullptr));
        item.Set("latches", BuildStringArray(region.LatchBlocks, 8, nullptr));
        item.Set("exits", BuildStringArray(region.ExitBlocks, 8, nullptr));
        item.Set("confidence", JsonValue::MakeNumber(region.Confidence));
        regions.PushBack(item);
    }

    for (size_t index = 0; index < request.Facts.NormalizedConditions.size() && index < kPromptNormalizedConditionLimit; ++index)
    {
        const NormalizedCondition& condition = request.Facts.NormalizedConditions[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("block", JsonValue::MakeString(condition.BlockId));
        item.Set("expression", JsonValue::MakeString(condition.Expression));
        item.Set("true_target", JsonValue::MakeString(condition.TrueTargetBlock));
        item.Set("false_target", JsonValue::MakeString(condition.FalseTargetBlock));
        item.Set("confidence", JsonValue::MakeNumber(condition.Confidence));
        conditions.PushBack(item);
    }

    const std::vector<size_t> blockIndices = SelectRepresentativeBlockIndices(request);

    for (size_t selectedIndex : blockIndices)
    {
        const BasicBlock& block = request.Facts.Blocks[selectedIndex];
        JsonValue item = JsonValue::MakeObject();
        item.Set("id", JsonValue::MakeString(block.Id));
        item.Set("succ", BuildStringArray(block.Successors, 8, nullptr));
        item.Set("instruction_count", JsonValue::MakeNumber(static_cast<double>(block.InstructionAddresses.size())));
        item.Set("has_direct_call", JsonValue::MakeBoolean(BlockContainsCallKind(request, block, false)));
        item.Set("has_indirect_call", JsonValue::MakeBoolean(BlockContainsCallKind(request, block, true)));
        item.Set("has_conditional_branch", JsonValue::MakeBoolean(BlockContainsConditionalBranch(request, block)));
        item.Set("has_return", JsonValue::MakeBoolean(BlockContainsReturn(request, block)));
        importantBlocks.PushBack(item);
    }

    graph.Set("entry", entry);
    graph.Set("regions", regions);
    graph.Set("conditions", conditions);
    graph.Set("important_blocks", importantBlocks);
    graph.Set("truncated_policy", JsonValue::MakeString("When any truncation flag is true, keep the omitted graph portions uncertain unless supported by listed evidence."));
    return graph;
}

JsonValue BuildPromptFactsJson(const AnalyzeRequest& request)
{
    JsonValue root = JsonValue::MakeObject();
    JsonValue module = JsonValue::MakeObject();
    JsonValue naturalLanguage = JsonValue::MakeObject();
    JsonValue stackFrame = JsonValue::MakeObject();
    JsonValue truncation = JsonValue::MakeObject();
    JsonValue selection = JsonValue::MakeObject();
    bool regionsTruncated = false;
    bool blocksTruncated = false;
    bool directCallsTruncated = false;
    bool indirectCallsTruncated = false;
    bool switchesTruncated = false;
    bool memoryAccessesTruncated = false;
    bool recoveredArgumentsTruncated = false;
    bool recoveredLocalsTruncated = false;
    bool valueMergesTruncated = false;
    bool irValuesTruncated = false;
    bool controlFlowTruncated = false;
    bool abiTruncated = false;
    bool typeHintsTruncated = false;
    bool idiomsTruncated = false;
    bool calleeSummariesTruncated = false;
    bool dataReferencesTruncated = false;
    bool callTargetsTruncated = false;
    bool normalizedConditionsTruncated = false;
    bool pdbTruncated = false;
    bool observedBehaviorTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("base", JsonValue::MakeString(HexU64(request.Facts.Module.Base)));
    module.Set("size", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.Size)));
    module.Set("symbol_type", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.SymbolType)));

    naturalLanguage.Set("tag", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageTag));
    naturalLanguage.Set("name", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageName));

    stackFrame.Set("stack_alloc", JsonValue::MakeNumber(static_cast<double>(request.Facts.StackFrame.StackAlloc)));
    stackFrame.Set("saved_nonvolatile", BuildStringArray(request.Facts.StackFrame.SavedNonvolatile, 8, nullptr));
    stackFrame.Set("uses_cookie", JsonValue::MakeBoolean(request.Facts.StackFrame.UsesCookie));
    stackFrame.Set("frame_pointer", JsonValue::MakeBoolean(request.Facts.StackFrame.FramePointer));

    selection.Set("block_strategy", JsonValue::MakeString("entry + feature-heavy blocks + spread sampling"));
    selection.Set("instruction_window_limit", JsonValue::MakeNumber(static_cast<double>(kPromptInstructionWindowLimit)));
    selection.Set("block_limit", JsonValue::MakeNumber(static_cast<double>(kPromptBlockLimit)));

    root.Set("arch", JsonValue::MakeString(request.Facts.Arch));
    root.Set("mode", JsonValue::MakeString(request.Facts.Mode == AnalysisMode::LiveMemory ? "live" : "file"));
    root.Set("query_text", JsonValue::MakeString(request.Facts.QueryText));
    root.Set("query_address", JsonValue::MakeString(HexU64(request.Facts.QueryAddress)));
    root.Set("entry_address", JsonValue::MakeString(HexU64(request.Facts.EntryAddress)));
    root.Set("rva", JsonValue::MakeString(HexU64(request.Facts.Rva)));
    root.Set("natural_language", naturalLanguage);
    root.Set("calling_convention", JsonValue::MakeString(request.Facts.CallingConvention));
    root.Set("module", module);
    root.Set("regions", BuildRegionsJson(request, &regionsTruncated));
    root.Set("stack_frame", stackFrame);
    root.Set("counts", BuildCountsJson(request));
    root.Set("analyzer_skeleton", JsonValue::MakeString(BuildAnalyzerSkeletonPseudoC(request)));
    root.Set("graph_summary", BuildGraphSummaryJson(request));
    root.Set("selection", selection);
    root.Set("instruction_window_head", BuildInstructionWindowJson(request, false));
    const std::optional<size_t> middleInstructionIndex = FindMiddleInterestingInstructionIndex(request);
    root.Set("instruction_window_middle", middleInstructionIndex.has_value() ? BuildInstructionWindowJson(request, middleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("instruction_window_tail", BuildInstructionWindowJson(request, true));
    root.Set("blocks", BuildBlocksJson(request, &blocksTruncated));
    root.Set("direct_calls", BuildCallsJson(request.Facts.Calls, kPromptDirectCallLimit, &directCallsTruncated));
    root.Set("indirect_calls", BuildCallsJson(request.Facts.IndirectCalls, kPromptIndirectCallLimit, &indirectCallsTruncated));
    root.Set("switches", BuildSwitchesJson(request, &switchesTruncated));
    root.Set("memory_accesses", BuildMemoryAccessesJson(request, &memoryAccessesTruncated));
    root.Set("recovered_arguments", BuildRecoveredArgumentsJson(request, &recoveredArgumentsTruncated));
    root.Set("recovered_locals", BuildRecoveredLocalsJson(request, &recoveredLocalsTruncated));
    root.Set("value_merges", BuildValueMergesJson(request, &valueMergesTruncated));
    root.Set("ir_values", BuildIrValuesJson(request, &irValuesTruncated));
    root.Set("control_flow", BuildControlFlowJson(request, &controlFlowTruncated));
    root.Set("abi", BuildAbiJson(request, &abiTruncated));
    root.Set("type_hints", BuildTypeHintsJson(request, &typeHintsTruncated));
    root.Set("idioms", BuildIdiomsJson(request, &idiomsTruncated));
    root.Set("callee_summaries", BuildCalleeSummariesJson(request, &calleeSummariesTruncated));
    root.Set("data_references", BuildDataReferencesJson(request, &dataReferencesTruncated));
    root.Set("call_targets", BuildCallTargetsJson(request, &callTargetsTruncated));
    root.Set("normalized_conditions", BuildNormalizedConditionsJson(request, &normalizedConditionsTruncated));
    root.Set("pdb", BuildPdbFactsJson(request, &pdbTruncated));
    root.Set("session_policy", BuildSessionPolicyJson(request));
    root.Set("observed_behavior", BuildObservedBehaviorJson(request, &observedBehaviorTruncated));
    root.Set("facts", BuildStringArray(request.Facts.Facts, kPromptFactLimit, &factsTruncated));
    root.Set("uncertainties", BuildStringArray(request.Facts.UncertainPoints, kPromptUncertaintyLimit, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));
    root.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));

    truncation.Set("regions", JsonValue::MakeBoolean(regionsTruncated));
    truncation.Set("blocks", JsonValue::MakeBoolean(blocksTruncated));
    truncation.Set("direct_calls", JsonValue::MakeBoolean(directCallsTruncated));
    truncation.Set("indirect_calls", JsonValue::MakeBoolean(indirectCallsTruncated));
    truncation.Set("switches", JsonValue::MakeBoolean(switchesTruncated));
    truncation.Set("memory_accesses", JsonValue::MakeBoolean(memoryAccessesTruncated));
    truncation.Set("recovered_arguments", JsonValue::MakeBoolean(recoveredArgumentsTruncated));
    truncation.Set("recovered_locals", JsonValue::MakeBoolean(recoveredLocalsTruncated));
    truncation.Set("value_merges", JsonValue::MakeBoolean(valueMergesTruncated));
    truncation.Set("ir_values", JsonValue::MakeBoolean(irValuesTruncated));
    truncation.Set("control_flow", JsonValue::MakeBoolean(controlFlowTruncated));
    truncation.Set("abi", JsonValue::MakeBoolean(abiTruncated));
    truncation.Set("type_hints", JsonValue::MakeBoolean(typeHintsTruncated));
    truncation.Set("idioms", JsonValue::MakeBoolean(idiomsTruncated));
    truncation.Set("callee_summaries", JsonValue::MakeBoolean(calleeSummariesTruncated));
    truncation.Set("data_references", JsonValue::MakeBoolean(dataReferencesTruncated));
    truncation.Set("call_targets", JsonValue::MakeBoolean(callTargetsTruncated));
    truncation.Set("normalized_conditions", JsonValue::MakeBoolean(normalizedConditionsTruncated));
    truncation.Set("pdb", JsonValue::MakeBoolean(pdbTruncated));
    truncation.Set("observed_behavior", JsonValue::MakeBoolean(observedBehaviorTruncated));
    truncation.Set("facts", JsonValue::MakeBoolean(factsTruncated));
    truncation.Set("uncertainties", JsonValue::MakeBoolean(uncertaintiesTruncated));
    root.Set("truncation", truncation);

    return root;
}

struct ChunkPlan
{
    std::string Id;
    size_t SlotIndex = 0;
    size_t TotalChunks = 0;
    std::vector<size_t> BlockIndices;
};

struct ChunkAnalysis
{
    std::string ChunkId;
    std::string SummaryLocalized;
    std::vector<std::string> PseudoSteps;
    std::vector<std::string> StateUpdates;
    std::vector<std::string> ObservedCalls;
    std::vector<std::string> ObservedMemory;
    std::vector<std::string> Uncertainties;
    std::vector<EvidenceItem> Evidence;
    double Confidence = 0.0;
};

constexpr size_t kChunkOverlapBlocks = 2;
constexpr size_t kChunkPromptFactLimit = 16;
constexpr size_t kChunkPromptUncertaintyLimit = 8;

std::string DescribePreferredNaturalLanguage(const AnalyzeRequest& request)
{
    if (!request.Facts.PreferredNaturalLanguageName.empty() && !request.Facts.PreferredNaturalLanguageTag.empty())
    {
        return request.Facts.PreferredNaturalLanguageName + " (" + request.Facts.PreferredNaturalLanguageTag + ")";
    }

    if (!request.Facts.PreferredNaturalLanguageName.empty())
    {
        return request.Facts.PreferredNaturalLanguageName;
    }

    if (!request.Facts.PreferredNaturalLanguageTag.empty())
    {
        return request.Facts.PreferredNaturalLanguageTag;
    }

    return "English (en-US)";
}

std::vector<ChunkPlan> BuildChunkPlans(
    const AnalyzeRequest& request,
    const LlmClientConfig& config)
{
    std::vector<ChunkPlan> plans;
    const size_t totalBlocks = request.Facts.Blocks.size();

    if (totalBlocks == 0)
    {
        return plans;
    }

    const size_t minimumBlocksPerChunk = (std::max)(static_cast<size_t>(4), static_cast<size_t>(config.ChunkBlockLimit));
    const size_t maxChunkCount = (std::max)(static_cast<size_t>(1), static_cast<size_t>(config.ChunkCountLimit));
    size_t blocksPerChunk = minimumBlocksPerChunk;

    if ((totalBlocks + blocksPerChunk - 1) / blocksPerChunk > maxChunkCount)
    {
        blocksPerChunk = (totalBlocks + maxChunkCount - 1) / maxChunkCount;
    }

    const size_t slotCount = (totalBlocks + blocksPerChunk - 1) / blocksPerChunk;

    std::set<std::string> seenRanges;

    for (size_t localIndex = 0; localIndex < slotCount; ++localIndex)
    {
        const size_t slot = localIndex;
        size_t startBlock = slot * blocksPerChunk;

        if (startBlock > kChunkOverlapBlocks)
        {
            startBlock -= kChunkOverlapBlocks;
        }
        else
        {
            startBlock = 0;
        }

        size_t endBlock = slot * blocksPerChunk + blocksPerChunk + kChunkOverlapBlocks;

        if (endBlock > totalBlocks)
        {
            endBlock = totalBlocks;
        }

        if (startBlock >= endBlock)
        {
            continue;
        }

        const std::string rangeKey = std::to_string(startBlock) + ":" + std::to_string(endBlock);

        if (!seenRanges.insert(rangeKey).second)
        {
            continue;
        }

        ChunkPlan plan;
        plan.Id = "chunk_" + std::to_string(localIndex);
        plan.SlotIndex = localIndex;
        plan.TotalChunks = slotCount;

        for (size_t blockIndex = startBlock; blockIndex < endBlock; ++blockIndex)
        {
            plan.BlockIndices.push_back(blockIndex);
        }

        plans.push_back(plan);
    }

    for (ChunkPlan& plan : plans)
    {
        plan.TotalChunks = plans.size();
    }

    return plans;
}

bool ShouldUseChunkedAnalysis(
    const AnalyzeRequest& request,
    const LlmClientConfig& config)
{
    if (config.ForceChunked)
    {
        return true;
    }

    if (request.Facts.Instructions.size() >= config.ChunkTriggerInstructions)
    {
        return true;
    }

    if (request.Facts.Blocks.size() >= config.ChunkTriggerBlocks)
    {
        return true;
    }

    return false;
}

std::vector<const DisassembledInstruction*> CollectInstructionsForBlocks(
    const AnalyzeRequest& request,
    const std::vector<size_t>& blockIndices)
{
    std::set<uint64_t> addresses;
    std::vector<const DisassembledInstruction*> instructions;

    for (size_t blockIndex : blockIndices)
    {
        if (blockIndex >= request.Facts.Blocks.size())
        {
            continue;
        }

        const BasicBlock& block = request.Facts.Blocks[blockIndex];

        for (uint64_t address : block.InstructionAddresses)
        {
            addresses.insert(address);
        }
    }

    for (const DisassembledInstruction& instruction : request.Facts.Instructions)
    {
        if (addresses.find(instruction.Address) != addresses.end())
        {
            instructions.push_back(&instruction);
        }
    }

    return instructions;
}

std::optional<size_t> FindMiddleInterestingInstructionIndex(
    const std::vector<const DisassembledInstruction*>& instructions)
{
    if (instructions.empty())
    {
        return std::nullopt;
    }

    const size_t middle = instructions.size() / 2;

    for (size_t radius = 0; radius < instructions.size(); ++radius)
    {
        if (middle >= radius)
        {
            const size_t index = middle - radius;
            const DisassembledInstruction& instruction = *instructions[index];

            if (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || instruction.OperandText.find('[') != std::string::npos)
            {
                return index;
            }
        }

        const size_t forward = middle + radius;

        if (forward < instructions.size())
        {
            const DisassembledInstruction& instruction = *instructions[forward];

            if (instruction.IsCall || instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || instruction.OperandText.find('[') != std::string::npos)
            {
                return forward;
            }
        }
    }

    return middle;
}

JsonValue BuildInstructionWindowFromPointers(
    const std::vector<const DisassembledInstruction*>& instructions,
    bool tail)
{
    JsonValue window = JsonValue::MakeArray();
    const size_t total = instructions.size();

    if (total == 0)
    {
        return window;
    }

    size_t startIndex = 0;
    size_t count = total < kPromptInstructionWindowLimit ? total : kPromptInstructionWindowLimit;

    if (tail && total > count)
    {
        startIndex = total - count;
    }

    for (size_t index = 0; index < count; ++index)
    {
        window.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instructions[startIndex + index])));
    }

    return window;
}

JsonValue BuildInstructionWindowFromPointers(
    const std::vector<const DisassembledInstruction*>& instructions,
    size_t centerIndex)
{
    JsonValue window = JsonValue::MakeArray();
    const size_t total = instructions.size();

    if (total == 0)
    {
        return window;
    }

    const size_t count = total < kPromptInstructionWindowLimit ? total : kPromptInstructionWindowLimit;
    size_t startIndex = 0;

    if (total > count)
    {
        const size_t half = count / 2;

        if (centerIndex > half)
        {
            startIndex = centerIndex - half;
        }

        if (startIndex + count > total)
        {
            startIndex = total - count;
        }
    }

    for (size_t index = 0; index < count; ++index)
    {
        window.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instructions[startIndex + index])));
    }

    return window;
}

void CollectChunkAddressMetadata(
    const AnalyzeRequest& request,
    const ChunkPlan& plan,
    std::set<uint64_t>& instructionAddresses,
    std::set<std::string>& blockIds,
    uint64_t& startAddress,
    uint64_t& endAddress)
{
    startAddress = 0;
    endAddress = 0;

    for (size_t blockIndex : plan.BlockIndices)
    {
        if (blockIndex >= request.Facts.Blocks.size())
        {
            continue;
        }

        const BasicBlock& block = request.Facts.Blocks[blockIndex];
        blockIds.insert(block.Id);

        if (startAddress == 0 || block.StartAddress < startAddress)
        {
            startAddress = block.StartAddress;
        }

        if (block.EndAddress > endAddress)
        {
            endAddress = block.EndAddress;
        }

        for (uint64_t address : block.InstructionAddresses)
        {
            instructionAddresses.insert(address);
        }
    }
}
JsonValue BuildBlocksJsonForIndices(
    const AnalyzeRequest& request,
    const std::vector<size_t>& indices)
{
    JsonValue blocks = JsonValue::MakeArray();

    for (size_t selectedIndex : indices)
    {
        if (selectedIndex >= request.Facts.Blocks.size())
        {
            continue;
        }

        const BasicBlock& block = request.Facts.Blocks[selectedIndex];
        JsonValue item = JsonValue::MakeObject();
        JsonValue instructionHeadSample = JsonValue::MakeArray();
        JsonValue instructionTailSample = JsonValue::MakeArray();
        const size_t headCount = block.InstructionAddresses.size() < kPromptBlockInstructionLimit ? block.InstructionAddresses.size() : kPromptBlockInstructionLimit;
        const size_t tailCount = block.InstructionAddresses.size() < 6 ? block.InstructionAddresses.size() : 6;

        for (size_t instructionIndex = 0; instructionIndex < headCount; ++instructionIndex)
        {
            const DisassembledInstruction* instruction = FindInstructionByAddress(request, block.InstructionAddresses[instructionIndex]);

            if (instruction != nullptr)
            {
                instructionHeadSample.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instruction)));
            }
        }

        if (block.InstructionAddresses.size() > tailCount)
        {
            for (size_t instructionIndex = block.InstructionAddresses.size() - tailCount; instructionIndex < block.InstructionAddresses.size(); ++instructionIndex)
            {
                const DisassembledInstruction* instruction = FindInstructionByAddress(request, block.InstructionAddresses[instructionIndex]);

                if (instruction != nullptr)
                {
                    instructionTailSample.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instruction)));
                }
            }
        }

        item.Set("id", JsonValue::MakeString(block.Id));
        item.Set("start", JsonValue::MakeString(HexU64(block.StartAddress)));
        item.Set("end", JsonValue::MakeString(HexU64(block.EndAddress)));
        item.Set("succ", BuildStringArray(block.Successors, 12, nullptr));
        item.Set("terminal", JsonValue::MakeBoolean(block.HasTerminal));
        item.Set("instruction_count", JsonValue::MakeNumber(static_cast<double>(block.InstructionAddresses.size())));
        item.Set("memory_access_count", JsonValue::MakeNumber(static_cast<double>(CountBlockMemoryAccesses(request, block))));
        item.Set("has_direct_call", JsonValue::MakeBoolean(BlockContainsCallKind(request, block, false)));
        item.Set("has_indirect_call", JsonValue::MakeBoolean(BlockContainsCallKind(request, block, true)));
        item.Set("has_return", JsonValue::MakeBoolean(BlockContainsReturn(request, block)));
        item.Set("has_conditional_branch", JsonValue::MakeBoolean(BlockContainsConditionalBranch(request, block)));
        item.Set("insn_head_sample", instructionHeadSample);
        item.Set("insn_tail_sample", instructionTailSample);
        blocks.PushBack(item);
    }

    return blocks;
}

JsonValue BuildCallsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::vector<CallSite>& calls,
    const std::set<uint64_t>& instructionAddresses,
    size_t limit,
    bool* truncated)
{
    (void)request;
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < calls.size(); ++index)
    {
        if (instructionAddresses.find(calls[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > limit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), limit);

    for (size_t relativeIndex : sampled)
    {
        const CallSite& call = calls[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(call.Site)));
        item.Set("target", JsonValue::MakeString(call.Target));
        item.Set("kind", JsonValue::MakeString(call.Kind));
        item.Set("returns", JsonValue::MakeBoolean(call.Returns));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildSwitchesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.Switches.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.Switches[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptSwitchLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptSwitchLimit);

    for (size_t relativeIndex : sampled)
    {
        const SwitchInfo& info = request.Facts.Switches[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(info.Site)));
        item.Set("case_count", JsonValue::MakeNumber(static_cast<double>(info.CaseCount)));
        item.Set("detail", JsonValue::MakeString(info.Detail));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildMemoryAccessesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.MemoryAccesses.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.MemoryAccesses[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptMemoryAccessLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptMemoryAccessLimit);

    for (size_t relativeIndex : sampled)
    {
        const MemoryAccess& access = request.Facts.MemoryAccesses[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(access.Site)));
        item.Set("access", JsonValue::MakeString(access.Access));
        item.Set("kind", JsonValue::MakeString(access.Kind));
        item.Set("size", JsonValue::MakeString(access.Size));
        item.Set("width_bits", JsonValue::MakeNumber(static_cast<double>(access.WidthBits)));
        item.Set("base_register", JsonValue::MakeString(access.BaseRegister));
        item.Set("index_register", JsonValue::MakeString(access.IndexRegister));
        item.Set("scale", JsonValue::MakeNumber(static_cast<double>(access.Scale)));
        item.Set("displacement", JsonValue::MakeString(access.Displacement));
        item.Set("rip_relative", JsonValue::MakeBoolean(access.RipRelative));
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, access.Site);
        item.Set("instruction", JsonValue::MakeString(instruction != nullptr ? BuildInstructionPreview(*instruction) : std::string()));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildDataReferencesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.DataReferences.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.DataReferences[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptDataReferenceLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptDataReferenceLimit);

    for (size_t relativeIndex : sampled)
    {
        const DataReference& reference = request.Facts.DataReferences[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(reference.Site)));
        item.Set("target_address", JsonValue::MakeString(HexU64(reference.TargetAddress)));
        item.Set("kind", JsonValue::MakeString(reference.Kind));
        item.Set("symbol", JsonValue::MakeString(reference.Symbol));
        item.Set("module_name", JsonValue::MakeString(reference.ModuleName));
        item.Set("display", JsonValue::MakeString(reference.Display));
        item.Set("preview", JsonValue::MakeString(reference.Preview));
        item.Set("rip_relative", JsonValue::MakeBoolean(reference.RipRelative));
        item.Set("dereferenced", JsonValue::MakeBoolean(reference.Dereferenced));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildCallTargetsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.CallTargets.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.CallTargets[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptCallTargetLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptCallTargetLimit);

    for (size_t relativeIndex : sampled)
    {
        const CallTargetInfo& call = request.Facts.CallTargets[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(call.Site)));
        item.Set("target_address", JsonValue::MakeString(HexU64(call.TargetAddress)));
        item.Set("display_name", JsonValue::MakeString(call.DisplayName));
        item.Set("target_kind", JsonValue::MakeString(call.TargetKind));
        item.Set("module_name", JsonValue::MakeString(call.ModuleName));
        item.Set("prototype", JsonValue::MakeString(call.Prototype));
        item.Set("return_type", JsonValue::MakeString(call.ReturnType));
        item.Set("side_effects", JsonValue::MakeString(call.SideEffects));
        item.Set("indirect", JsonValue::MakeBoolean(call.Indirect));
        item.Set("confidence", JsonValue::MakeNumber(call.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildNormalizedConditionsJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.NormalizedConditions.size(); ++index)
    {
        if (blockIds.find(request.Facts.NormalizedConditions[index].BlockId) != blockIds.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptNormalizedConditionLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptNormalizedConditionLimit);

    for (size_t relativeIndex : sampled)
    {
        const NormalizedCondition& condition = request.Facts.NormalizedConditions[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(condition.Site)));
        item.Set("block_id", JsonValue::MakeString(condition.BlockId));
        item.Set("branch_mnemonic", JsonValue::MakeString(condition.BranchMnemonic));
        item.Set("expression", JsonValue::MakeString(condition.Expression));
        item.Set("true_target_block", JsonValue::MakeString(condition.TrueTargetBlock));
        item.Set("false_target_block", JsonValue::MakeString(condition.FalseTargetBlock));
        item.Set("confidence", JsonValue::MakeNumber(condition.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildValueMergesJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.ValueMerges.size(); ++index)
    {
        if (blockIds.find(request.Facts.ValueMerges[index].BlockId) != blockIds.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptValueMergeLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptValueMergeLimit);

    for (size_t relativeIndex : sampled)
    {
        const ValueMerge& merge = request.Facts.ValueMerges[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("block_id", JsonValue::MakeString(merge.BlockId));
        item.Set("variable", JsonValue::MakeString(merge.Variable));
        item.Set("predecessors", BuildStringArray(merge.Predecessors, 8, nullptr));
        item.Set("incoming_values", BuildStringArray(merge.IncomingValues, 8, nullptr));
        item.Set("confidence", JsonValue::MakeNumber(merge.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildChunkFactsJson(
    const AnalyzeRequest& request,
    const ChunkPlan& plan)
{
    JsonValue root = JsonValue::MakeObject();
    JsonValue functionOverview = JsonValue::MakeObject();
    JsonValue module = JsonValue::MakeObject();
    JsonValue naturalLanguage = JsonValue::MakeObject();
    JsonValue stackFrame = JsonValue::MakeObject();
    JsonValue chunk = JsonValue::MakeObject();
    JsonValue truncation = JsonValue::MakeObject();
    std::set<uint64_t> instructionAddresses;
    std::set<std::string> blockIds;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
    bool directCallsTruncated = false;
    bool indirectCallsTruncated = false;
    bool switchesTruncated = false;
    bool memoryAccessesTruncated = false;
    bool recoveredArgumentsTruncated = false;
    bool recoveredLocalsTruncated = false;
    bool valueMergesTruncated = false;
    bool dataReferencesTruncated = false;
    bool callTargetsTruncated = false;
    bool normalizedConditionsTruncated = false;
    bool pdbTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;

    CollectChunkAddressMetadata(request, plan, instructionAddresses, blockIds, startAddress, endAddress);
    const std::vector<const DisassembledInstruction*> chunkInstructions = CollectInstructionsForBlocks(request, plan.BlockIndices);
    const std::optional<size_t> middleInstructionIndex = FindMiddleInterestingInstructionIndex(chunkInstructions);
    const std::optional<size_t> globalMiddleInstructionIndex = FindMiddleInterestingInstructionIndex(request);

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("base", JsonValue::MakeString(HexU64(request.Facts.Module.Base)));
    module.Set("size", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.Size)));

    naturalLanguage.Set("tag", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageTag));
    naturalLanguage.Set("name", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageName));

    stackFrame.Set("stack_alloc", JsonValue::MakeNumber(static_cast<double>(request.Facts.StackFrame.StackAlloc)));
    stackFrame.Set("saved_nonvolatile", BuildStringArray(request.Facts.StackFrame.SavedNonvolatile, 8, nullptr));
    stackFrame.Set("uses_cookie", JsonValue::MakeBoolean(request.Facts.StackFrame.UsesCookie));
    stackFrame.Set("frame_pointer", JsonValue::MakeBoolean(request.Facts.StackFrame.FramePointer));

    functionOverview.Set("query_text", JsonValue::MakeString(request.Facts.QueryText));
    functionOverview.Set("entry_address", JsonValue::MakeString(HexU64(request.Facts.EntryAddress)));
    functionOverview.Set("natural_language", naturalLanguage);
    functionOverview.Set("calling_convention", JsonValue::MakeString(request.Facts.CallingConvention));
    functionOverview.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));
    functionOverview.Set("counts", BuildCountsJson(request));
    functionOverview.Set("module", module);
    functionOverview.Set("stack_frame", stackFrame);

    chunk.Set("id", JsonValue::MakeString(plan.Id));
    chunk.Set("slot_index", JsonValue::MakeNumber(static_cast<double>(plan.SlotIndex)));
    chunk.Set("total_chunks", JsonValue::MakeNumber(static_cast<double>(plan.TotalChunks)));
    chunk.Set("block_count", JsonValue::MakeNumber(static_cast<double>(plan.BlockIndices.size())));
    chunk.Set("start", JsonValue::MakeString(HexU64(startAddress)));
    chunk.Set("end", JsonValue::MakeString(HexU64(endAddress)));

    JsonValue chunkBlockIds = JsonValue::MakeArray();

    for (const std::string& blockId : blockIds)
    {
        chunkBlockIds.PushBack(JsonValue::MakeString(blockId));
    }

    chunk.Set("block_ids", chunkBlockIds);

    if (!plan.BlockIndices.empty())
    {
        chunk.Set("first_block", JsonValue::MakeString(request.Facts.Blocks[plan.BlockIndices.front()].Id));
        chunk.Set("last_block", JsonValue::MakeString(request.Facts.Blocks[plan.BlockIndices.back()].Id));
    }

    root.Set("function_overview", functionOverview);
    root.Set("chunk", chunk);
    root.Set("graph_summary", BuildGraphSummaryJson(request));
    root.Set("global_instruction_window_head", BuildInstructionWindowJson(request, false));
    root.Set("global_instruction_window_middle", globalMiddleInstructionIndex.has_value() ? BuildInstructionWindowJson(request, globalMiddleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("global_instruction_window_tail", BuildInstructionWindowJson(request, true));
    root.Set("chunk_instruction_window_head", BuildInstructionWindowFromPointers(chunkInstructions, false));
    root.Set("chunk_instruction_window_middle", middleInstructionIndex.has_value() ? BuildInstructionWindowFromPointers(chunkInstructions, middleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("chunk_instruction_window_tail", BuildInstructionWindowFromPointers(chunkInstructions, true));
    root.Set("blocks", BuildBlocksJsonForIndices(request, plan.BlockIndices));
    root.Set("direct_calls", BuildCallsJsonForAddresses(request, request.Facts.Calls, instructionAddresses, 24, &directCallsTruncated));
    root.Set("indirect_calls", BuildCallsJsonForAddresses(request, request.Facts.IndirectCalls, instructionAddresses, 24, &indirectCallsTruncated));
    root.Set("switches", BuildSwitchesJsonForAddresses(request, instructionAddresses, &switchesTruncated));
    root.Set("memory_accesses", BuildMemoryAccessesJsonForAddresses(request, instructionAddresses, &memoryAccessesTruncated));
    root.Set("recovered_arguments", BuildRecoveredArgumentsJson(request, &recoveredArgumentsTruncated));
    root.Set("recovered_locals", BuildRecoveredLocalsJson(request, &recoveredLocalsTruncated));
    root.Set("value_merges", BuildValueMergesJsonForBlocks(request, blockIds, &valueMergesTruncated));
    root.Set("data_references", BuildDataReferencesJsonForAddresses(request, instructionAddresses, &dataReferencesTruncated));
    root.Set("call_targets", BuildCallTargetsJsonForAddresses(request, instructionAddresses, &callTargetsTruncated));
    root.Set("normalized_conditions", BuildNormalizedConditionsJsonForBlocks(request, blockIds, &normalizedConditionsTruncated));
    root.Set("pdb", BuildPdbFactsJson(request, &pdbTruncated));
    root.Set("global_facts", BuildStringArray(request.Facts.Facts, kChunkPromptFactLimit, &factsTruncated));
    root.Set("global_uncertainties", BuildStringArray(request.Facts.UncertainPoints, kChunkPromptUncertaintyLimit, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));

    truncation.Set("direct_calls", JsonValue::MakeBoolean(directCallsTruncated));
    truncation.Set("indirect_calls", JsonValue::MakeBoolean(indirectCallsTruncated));
    truncation.Set("switches", JsonValue::MakeBoolean(switchesTruncated));
    truncation.Set("memory_accesses", JsonValue::MakeBoolean(memoryAccessesTruncated));
    truncation.Set("recovered_arguments", JsonValue::MakeBoolean(recoveredArgumentsTruncated));
    truncation.Set("recovered_locals", JsonValue::MakeBoolean(recoveredLocalsTruncated));
    truncation.Set("value_merges", JsonValue::MakeBoolean(valueMergesTruncated));
    truncation.Set("data_references", JsonValue::MakeBoolean(dataReferencesTruncated));
    truncation.Set("call_targets", JsonValue::MakeBoolean(callTargetsTruncated));
    truncation.Set("normalized_conditions", JsonValue::MakeBoolean(normalizedConditionsTruncated));
    truncation.Set("pdb", JsonValue::MakeBoolean(pdbTruncated));
    truncation.Set("facts", JsonValue::MakeBoolean(factsTruncated));
    truncation.Set("uncertainties", JsonValue::MakeBoolean(uncertaintiesTruncated));
    root.Set("truncation", truncation);

    return root;
}
bool TryGetOptionalString(
    const JsonValue& root,
    const char* name,
    std::string& value)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (!member->IsString())
    {
        return false;
    }

    value = member->GetString();
    return true;
}

bool TryGetOptionalDouble(
    const JsonValue& root,
    const char* name,
    double& value)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (!member->IsNumber())
    {
        return false;
    }

    value = member->GetNumber();
    return true;
}

bool TryReadStringArrayField(
    const JsonValue& root,
    const char* name,
    std::vector<std::string>& values)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (member->IsString())
    {
        values.push_back(member->GetString());
        return true;
    }

    if (!member->IsArray())
    {
        return false;
    }

    for (const JsonValue& item : member->GetArray())
    {
        if (item.IsString())
        {
            values.push_back(item.GetString());
        }
    }

    return true;
}

void AppendEvidenceItem(
    std::vector<EvidenceItem>& values,
    const EvidenceItem& evidence)
{
    if (evidence.Claim.empty() && evidence.Blocks.empty())
    {
        return;
    }

    values.push_back(evidence);
}

bool TryParseEvidenceObject(
    const JsonValue& item,
    EvidenceItem& evidence)
{
    if (!item.IsObject())
    {
        return false;
    }

    if (!TryGetOptionalString(item, "claim", evidence.Claim))
    {
        return false;
    }

    const JsonValue* blocks = item.Find("blocks");

    if (blocks == nullptr)
    {
        blocks = item.Find("block_ids");
    }

    if (blocks != nullptr)
    {
        if (blocks->IsString())
        {
            evidence.Blocks.push_back(blocks->GetString());
        }
        else if (blocks->IsArray())
        {
            for (const JsonValue& block : blocks->GetArray())
            {
                if (block.IsString())
                {
                    evidence.Blocks.push_back(block.GetString());
                }
            }
        }
    }

    if (evidence.Claim.empty())
    {
        const JsonValue* summary = item.Find("summary");

        if (summary != nullptr && summary->IsString())
        {
            evidence.Claim = summary->GetString();
        }
    }

    return true;
}

bool TryReadEvidenceArrayField(
    const JsonValue& root,
    const char* name,
    std::vector<EvidenceItem>& values)
{
    const JsonValue* member = root.Find(name);

    if (member == nullptr)
    {
        return true;
    }

    if (member->IsString())
    {
        EvidenceItem evidence;
        evidence.Claim = member->GetString();
        AppendEvidenceItem(values, evidence);
        return true;
    }

    if (member->IsObject())
    {
        EvidenceItem evidence;

        if (!TryParseEvidenceObject(*member, evidence))
        {
            return false;
        }

        AppendEvidenceItem(values, evidence);
        return true;
    }

    if (!member->IsArray())
    {
        return false;
    }

    for (const JsonValue& item : member->GetArray())
    {
        if (item.IsString())
        {
            EvidenceItem evidence;
            evidence.Claim = item.GetString();
            AppendEvidenceItem(values, evidence);
            continue;
        }

        if (!item.IsObject())
        {
            continue;
        }

        EvidenceItem evidence;

        if (!TryParseEvidenceObject(item, evidence))
        {
            continue;
        }

        AppendEvidenceItem(values, evidence);
    }

    return true;
}
bool ParseChunkAnalysis(
    const std::string& text,
    ChunkAnalysis& analysis,
    std::string& error)
{
    const JsonParseResult parsed = ParseJson(text);

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        error = parsed.Error.empty() ? "chunk response must be a JSON object" : parsed.Error;
        return false;
    }

    const JsonValue& root = parsed.Value;

    if (!TryGetOptionalString(root, "chunk_id", analysis.ChunkId))
    {
        error = "chunk_id must be a string";
        return false;
    }

    if (!TryGetOptionalString(root, "summary_localized", analysis.SummaryLocalized))
    {
        error = "summary_localized must be a string";
        return false;
    }

    if (analysis.SummaryLocalized.empty() && !TryGetOptionalString(root, "summary_ko", analysis.SummaryLocalized))
    {
        error = "summary_ko must be a string";
        return false;
    }

    if (analysis.SummaryLocalized.empty() && !TryGetOptionalString(root, "summary", analysis.SummaryLocalized))
    {
        error = "summary must be a string";
        return false;
    }

    if (!TryReadStringArrayField(root, "pseudo_steps", analysis.PseudoSteps))
    {
        error = "pseudo_steps must be a string or array of strings";
        return false;
    }

    if (!TryReadStringArrayField(root, "state_updates", analysis.StateUpdates))
    {
        error = "state_updates must be a string or array of strings";
        return false;
    }

    if (!TryReadStringArrayField(root, "observed_calls", analysis.ObservedCalls))
    {
        error = "observed_calls must be a string or array of strings";
        return false;
    }

    if (!TryReadStringArrayField(root, "observed_memory", analysis.ObservedMemory))
    {
        error = "observed_memory must be a string or array of strings";
        return false;
    }

    if (!TryReadStringArrayField(root, "uncertainties", analysis.Uncertainties))
    {
        error = "uncertainties must be a string or array of strings";
        return false;
    }

    if (!TryReadEvidenceArrayField(root, "evidence", analysis.Evidence))
    {
        error = "evidence must be a string, object, or array";
        return false;
    }

    if (!TryGetOptionalDouble(root, "confidence", analysis.Confidence))
    {
        error = "confidence must be a number";
        return false;
    }

    if (analysis.SummaryLocalized.empty())
    {
        error = "chunk response is missing summary_localized";
        return false;
    }

    return true;
}

JsonValue BuildChunkSummariesJson(
    const std::vector<ChunkAnalysis>& chunkAnalyses)
{
    JsonValue array = JsonValue::MakeArray();

    for (const ChunkAnalysis& analysis : chunkAnalyses)
    {
        JsonValue item = JsonValue::MakeObject();
        item.Set("chunk_id", JsonValue::MakeString(analysis.ChunkId));
        item.Set("summary_localized", JsonValue::MakeString(analysis.SummaryLocalized));
        item.Set("pseudo_steps", BuildStringArray(analysis.PseudoSteps, 32, nullptr));
        item.Set("state_updates", BuildStringArray(analysis.StateUpdates, 32, nullptr));
        item.Set("observed_calls", BuildStringArray(analysis.ObservedCalls, 24, nullptr));
        item.Set("observed_memory", BuildStringArray(analysis.ObservedMemory, 24, nullptr));
        item.Set("uncertainties", BuildStringArray(analysis.Uncertainties, 16, nullptr));
        item.Set("confidence", JsonValue::MakeNumber(analysis.Confidence));

        JsonValue evidenceArray = JsonValue::MakeArray();

        for (const EvidenceItem& evidence : analysis.Evidence)
        {
            JsonValue evidenceItem = JsonValue::MakeObject();
            evidenceItem.Set("claim", JsonValue::MakeString(evidence.Claim));
            evidenceItem.Set("blocks", BuildStringArray(evidence.Blocks, 12, nullptr));
            evidenceArray.PushBack(evidenceItem);
        }

        item.Set("evidence", evidenceArray);
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildMergeFactsJson(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses)
{
    JsonValue root = JsonValue::MakeObject();
    JsonValue module = JsonValue::MakeObject();
    JsonValue naturalLanguage = JsonValue::MakeObject();
    JsonValue stackFrame = JsonValue::MakeObject();
    JsonValue chunking = JsonValue::MakeObject();
    bool regionsTruncated = false;
    bool recoveredArgumentsTruncated = false;
    bool recoveredLocalsTruncated = false;
    bool valueMergesTruncated = false;
    bool dataReferencesTruncated = false;
    bool callTargetsTruncated = false;
    bool normalizedConditionsTruncated = false;
    bool pdbTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;
    const std::optional<size_t> middleInstructionIndex = FindMiddleInterestingInstructionIndex(request);
    std::set<size_t> coveredBlocks;

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("base", JsonValue::MakeString(HexU64(request.Facts.Module.Base)));
    module.Set("size", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.Size)));

    naturalLanguage.Set("tag", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageTag));
    naturalLanguage.Set("name", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageName));

    stackFrame.Set("stack_alloc", JsonValue::MakeNumber(static_cast<double>(request.Facts.StackFrame.StackAlloc)));
    stackFrame.Set("saved_nonvolatile", BuildStringArray(request.Facts.StackFrame.SavedNonvolatile, 8, nullptr));
    stackFrame.Set("uses_cookie", JsonValue::MakeBoolean(request.Facts.StackFrame.UsesCookie));
    stackFrame.Set("frame_pointer", JsonValue::MakeBoolean(request.Facts.StackFrame.FramePointer));

    for (const ChunkPlan& plan : chunkPlans)
    {
        for (size_t blockIndex : plan.BlockIndices)
        {
            coveredBlocks.insert(blockIndex);
        }
    }

    chunking.Set("chunk_count", JsonValue::MakeNumber(static_cast<double>(chunkPlans.size())));
    chunking.Set("chunk_summaries_count", JsonValue::MakeNumber(static_cast<double>(chunkAnalyses.size())));
    chunking.Set("covered_block_count", JsonValue::MakeNumber(static_cast<double>(coveredBlocks.size())));
    chunking.Set("coverage_ratio", JsonValue::MakeNumber(request.Facts.Blocks.empty() ? 0.0 : static_cast<double>(coveredBlocks.size()) / static_cast<double>(request.Facts.Blocks.size())));

    root.Set("query_text", JsonValue::MakeString(request.Facts.QueryText));
    root.Set("query_address", JsonValue::MakeString(HexU64(request.Facts.QueryAddress)));
    root.Set("entry_address", JsonValue::MakeString(HexU64(request.Facts.EntryAddress)));
    root.Set("rva", JsonValue::MakeString(HexU64(request.Facts.Rva)));
    root.Set("natural_language", naturalLanguage);
    root.Set("calling_convention", JsonValue::MakeString(request.Facts.CallingConvention));
    root.Set("module", module);
    root.Set("stack_frame", stackFrame);
    root.Set("counts", BuildCountsJson(request));
    root.Set("analyzer_skeleton", JsonValue::MakeString(BuildAnalyzerSkeletonPseudoC(request)));
    root.Set("graph_summary", BuildGraphSummaryJson(request));
    root.Set("regions", BuildRegionsJson(request, &regionsTruncated));
    root.Set("instruction_window_head", BuildInstructionWindowJson(request, false));
    root.Set("instruction_window_middle", middleInstructionIndex.has_value() ? BuildInstructionWindowJson(request, middleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("instruction_window_tail", BuildInstructionWindowJson(request, true));
    root.Set("recovered_arguments", BuildRecoveredArgumentsJson(request, &recoveredArgumentsTruncated));
    root.Set("recovered_locals", BuildRecoveredLocalsJson(request, &recoveredLocalsTruncated));
    root.Set("value_merges", BuildValueMergesJson(request, &valueMergesTruncated));
    root.Set("data_references", BuildDataReferencesJson(request, &dataReferencesTruncated));
    root.Set("call_targets", BuildCallTargetsJson(request, &callTargetsTruncated));
    root.Set("normalized_conditions", BuildNormalizedConditionsJson(request, &normalizedConditionsTruncated));
    root.Set("pdb", BuildPdbFactsJson(request, &pdbTruncated));
    root.Set("global_facts", BuildStringArray(request.Facts.Facts, 24, &factsTruncated));
    root.Set("global_uncertainties", BuildStringArray(request.Facts.UncertainPoints, 12, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));
    root.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));
    root.Set("chunking", chunking);
    root.Set("chunk_summaries", BuildChunkSummariesJson(chunkAnalyses));

    JsonValue truncation = JsonValue::MakeObject();
    truncation.Set("regions", JsonValue::MakeBoolean(regionsTruncated));
    truncation.Set("recovered_arguments", JsonValue::MakeBoolean(recoveredArgumentsTruncated));
    truncation.Set("recovered_locals", JsonValue::MakeBoolean(recoveredLocalsTruncated));
    truncation.Set("value_merges", JsonValue::MakeBoolean(valueMergesTruncated));
    truncation.Set("data_references", JsonValue::MakeBoolean(dataReferencesTruncated));
    truncation.Set("call_targets", JsonValue::MakeBoolean(callTargetsTruncated));
    truncation.Set("normalized_conditions", JsonValue::MakeBoolean(normalizedConditionsTruncated));
    truncation.Set("pdb", JsonValue::MakeBoolean(pdbTruncated));
    truncation.Set("facts", JsonValue::MakeBoolean(factsTruncated));
    truncation.Set("uncertainties", JsonValue::MakeBoolean(uncertaintiesTruncated));
    root.Set("truncation", truncation);

    return root;
}
std::string BuildChunkSystemPrompt(const AnalyzeRequest& request)
{
    return
        "You are a reverse-engineering assistant analyzing one high-coverage chunk of a larger x64 function. "
        "Return only a JSON object with these keys: chunk_id, summary_localized, pseudo_steps, state_updates, observed_calls, observed_memory, uncertainties, evidence, confidence. "
        "Write summary_localized and uncertainties in the configured display language: " + DescribePreferredNaturalLanguage(request) + ". "
        "Keep pseudo_steps, state_updates, observed_calls, observed_memory, identifiers, and API names in English or C-style. "
        "Do not invent external call targets that are not present in the input. "
        "Use recovered_arguments, recovered_locals, normalized_conditions, data_references, call_targets, and pdb facts as high-signal semantic hints when present. "
        "Prefer explicit memory reads, writes, compares, branches, and state transitions over vague summaries. "
        "When information is incomplete, preserve only the missing part as uncertain instead of collapsing the whole chunk into a short summary. "
        "The evidence field must be an array of objects shaped like {\"claim\": string, \"blocks\": [string, ...]}. Use evidence.blocks values that reference only valid basic block ids from the input chunk.";
}

std::string BuildChunkUserPrompt(
    const AnalyzeRequest& request,
    const ChunkPlan& plan)
{
    std::string prompt;
    prompt += "Analyze this high-coverage chunk from a larger x64 function and emit the exact JSON schema requested.\n\n";
    prompt += "Function: ";
    prompt += request.Facts.QueryText;
    prompt += "\nChunk id: ";
    prompt += plan.Id;
    prompt += "\nChunk facts JSON:\n";
    prompt += SerializeJson(BuildChunkFactsJson(request, plan), false);
    prompt += "\n\nRules:\n";
    prompt += "1. Keep the output machine-readable JSON only.\n";
    prompt += "2. Write summary_localized and uncertainties in the configured display language: ";
    prompt += DescribePreferredNaturalLanguage(request);
    prompt += ".\n";
    prompt += "3. Keep pseudo_steps and state_updates concrete and operation-focused.\n";
    prompt += "4. Preserve visible reads, writes, comparisons, and branches instead of replacing them with generic comments.\n";
    prompt += "5. Use recovered_arguments, recovered_locals, normalized_conditions, data_references, call_targets, type_hints, idioms, callee_summaries, and pdb facts when they improve naming or type/side-effect hints.\n";
    prompt += "6. If the chunk is partial, say what is missing, but still describe the concrete work visible in this chunk.\n";
    prompt += "7. evidence must be an array of objects shaped like {\\\"claim\\\": string, \\\"blocks\\\": [string, ...]}.\n";
    prompt += "8. evidence.blocks must reference only block ids present in this chunk.\n";
    prompt += "9. Use graph_summary to keep chunk-local control-flow claims aligned with function-level CFG evidence.\n";
    return prompt;
}

std::string BuildMergeSystemPrompt(const AnalyzeRequest& request)
{
    return
        "You are a reverse-engineering assistant combining multiple high-coverage chunk analyses for one x64 function. "
        "Return only a JSON object with these keys: status, pseudo_c, summary, params, locals, uncertainties, evidence, confidence. "
        "Write summary and uncertainties in the configured display language: " + DescribePreferredNaturalLanguage(request) + ". "
        "Keep pseudo_c, params, locals, evidence, identifiers, and API names in English or C-style. "
        "Use the chunk summaries to produce a fuller function-level pseudocode than a single-pass summary. "
        "Use recovered_arguments, recovered_locals, normalized_conditions, data_references, call_targets, value_merges, and pdb facts to preserve semantic names and control-flow intent. "
        "Prefer reconstructing concrete reads, writes, branches, and helper interactions when the chunk evidence supports them. "
        "Do not invent calls or fields that are not grounded by the chunk summaries or global facts. "
        "Use UNKNOWN_TYPE for uncertain types and preserve only the truly unresolved parts in uncertainties. The evidence field must be an array of objects shaped like {\"claim\": string, \"blocks\": [string, ...]}.";
}

std::string BuildMergeUserPrompt(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses)
{
    std::string prompt;
    prompt += "Synthesize a full function-level analysis from the chunk summaries and global facts below. Emit the exact JSON schema requested.\n\n";
    prompt += "Function: ";
    prompt += request.Facts.QueryText;
    prompt += "\nMerge facts JSON:\n";
    prompt += SerializeJson(BuildMergeFactsJson(request, chunkPlans, chunkAnalyses), false);
    prompt += "\n\nRules:\n";
    prompt += "1. Keep the output machine-readable JSON only.\n";
    prompt += "2. Write summary and uncertainties in the configured display language: ";
    prompt += DescribePreferredNaturalLanguage(request);
    prompt += ".\n";
    prompt += "3. Build a richer pseudo_c than a short high-level summary; use the chunk evidence to cover the main body.\n";
    prompt += "4. Preserve unknowns with UNKNOWN_TYPE instead of omitting entire regions of logic.\n";
    prompt += "5. Use recovered_arguments, recovered_locals, normalized_conditions, data_references, call_targets, value_merges, type_hints, idioms, callee_summaries, and pdb facts when they help produce more concrete names or conditions.\n";
    prompt += "6. If chunks disagree or coverage remains partial, explain that in uncertainties, but still keep the visible operations explicit.\n";
    prompt += "7. evidence must be an array of objects shaped like {\\\"claim\\\": string, \\\"blocks\\\": [string, ...]}.\n";
    prompt += "8. evidence.blocks must reference block ids that appear in the chunk summaries.\n";
    prompt += "9. Treat the analyzer skeleton and graph-derived facts as a draft to refine; do not invent unsupported loops, switches, or calls during merge.\n";
    return prompt;
}


std::string BuildSystemPrompt(const AnalyzeRequest& request)
{
    return
        "You are a reverse-engineering assistant. "
        "Return only a JSON object with these keys: status, pseudo_c, summary, params, locals, uncertainties, evidence, confidence. "
        "Do not invent external call targets that are not present in the input. "
        "Use UNKNOWN_TYPE for uncertain types. "
        "Write summary and uncertainties in the configured display language: " + DescribePreferredNaturalLanguage(request) + ". "
        "Keep pseudo_c, params, locals, evidence, identifiers, and API names in English or C-style as appropriate. "
        "Use recovered_arguments, recovered_locals, normalized_conditions, data_references, call_targets, value_merges, type_hints, idioms, callee_summaries, graph_summary, session_policy, observed_behavior, and pdb facts as high-confidence semantic hints when available. "
        "Use evidence.blocks values that reference only valid basic block ids from the input. "
        "Blocks are a representative selection, not necessarily the first contiguous blocks in the function. "
        "Treat analyzer_skeleton as the draft to refine and graph_summary as the authoritative graph outline. "
        "Use instruction_window_head, instruction_window_middle, and instruction_window_tail as additional context. "
        "Prefer detailed pseudocode over high-level commentary, and avoid collapsing major logic into comments when the facts support a concrete statement. "
        "When control flow is only partially known, keep the visible operations explicit and use UNKNOWN_TYPE or temporary variables instead of hand-waving. "
        "Assume the input facts may be truncated for token budget reasons and mention truncation in uncertainties when relevant.";
}

std::string BuildUserPrompt(const AnalyzeRequest& request)
{
    std::string prompt;
    prompt += "Analyze this x64 function summary and emit the exact JSON schema requested.\n\n";
    prompt += "Facts JSON:\n";
    prompt += SerializeJson(BuildPromptFactsJson(request), false);
    prompt += "\n\nRules:\n";
    prompt += "1. Keep the output machine-readable JSON only.\n";
    prompt += "2. Do not invent function names or imported APIs.\n";
    prompt += "3. Write summary and uncertainties in the configured display language: ";
    prompt += DescribePreferredNaturalLanguage(request);
    prompt += ".\n";
    prompt += "4. Do not translate symbol names, API names, or code identifiers unless needed inside localized prose.\n";
    prompt += "5. evidence.blocks must reference existing basic block ids.\n";
    prompt += "6. Treat blocks as representative high-signal samples, not as the only reachable blocks in order.\n";
    prompt += "7. Use instruction_window_head, instruction_window_middle, and instruction_window_tail to infer prologue, body, and late-path behavior.\n";
    prompt += "8. Use recovered_arguments, recovered_locals, normalized_conditions, data_references, call_targets, value_merges, type_hints, idioms, callee_summaries, session_policy, observed_behavior, and pdb facts when they improve variable names, helper summaries, branch expressions, or observed behavior notes.\n";
    prompt += "9. Prefer concrete pseudocode statements over summary comments when a memory read, write, compare, or branch is explicitly visible in the facts.\n";
    prompt += "10. If control flow is incomplete, keep visible operations explicit and mark only the missing pieces as uncertain.\n";
    prompt += "11. If truncation flags are true, preserve that uncertainty instead of over-claiming.\n";
    prompt += "12. Refine analyzer_skeleton instead of writing from scratch; preserve its evidence-backed regions, calls, idioms, and uncertainties unless contradicted by stronger facts.\n";
    prompt += "13. Use graph_summary as the authoritative CFG/region outline; do not invent loops, switches, or branches that graph_summary and control_flow do not support.\n";
    return prompt;
}

std::optional<std::string> ExtractChatContent(const JsonValue& root)
{
    const JsonValue* choices = root.Find("choices");

    if (choices != nullptr && choices->IsArray() && !choices->GetArray().empty())
    {
        const JsonValue& choice = choices->GetArray().front();
        const JsonValue* message = choice.Find("message");

        if (message != nullptr && message->IsObject())
        {
            const JsonValue* content = message->Find("content");

            if (content != nullptr)
            {
                if (content->IsString())
                {
                    return content->GetString();
                }

                if (content->IsArray() && !content->GetArray().empty())
                {
                    const JsonValue& first = content->GetArray().front();
                    const JsonValue* text = first.Find("text");

                    if (text != nullptr && text->IsString())
                    {
                        return text->GetString();
                    }
                }
            }
        }
    }

    const JsonValue* output = root.Find("output");

    if (output != nullptr && output->IsArray() && !output->GetArray().empty())
    {
        const JsonValue& first = output->GetArray().front();
        const JsonValue* content = first.Find("content");

        if (content != nullptr && content->IsArray() && !content->GetArray().empty())
        {
            const JsonValue& item = content->GetArray().front();
            const JsonValue* text = item.Find("text");

            if (text != nullptr && text->IsString())
            {
                return text->GetString();
            }
        }
    }

    return std::nullopt;
}

std::optional<std::string> ExtractFinishReason(const JsonValue& root)
{
    const JsonValue* choices = root.Find("choices");

    if (choices == nullptr || !choices->IsArray() || choices->GetArray().empty())
    {
        return std::nullopt;
    }

    const JsonValue& choice = choices->GetArray().front();
    const JsonValue* finishReason = choice.Find("finish_reason");

    if (finishReason != nullptr && finishReason->IsString())
    {
        return finishReason->GetString();
    }

    return std::nullopt;
}

std::string BuildPreviewText(const std::string& text)
{
    constexpr size_t kPreviewLimit = 240;

    if (text.size() <= kPreviewLimit)
    {
        return text;
    }

    return text.substr(0, kPreviewLimit) + "...";
}

bool ShouldRetryWithVerifierFeedback(const VerifyReport& report)
{
    if (!report.SchemaOk || report.AdjustedConfidence < 0.55)
    {
        return true;
    }

    for (const auto& issue : report.Issues)
    {
        if (issue.Severity == "error")
        {
            return true;
        }
    }

    return report.FactConflicts != 0 || report.MissingEvidence > 1;
}

std::string BuildVerifierFeedbackPrompt(const VerifyReport& report)
{
    std::string prompt;
    prompt += "\n\nVerifier feedback from the previous attempt:\n";
    prompt += "- Adjusted confidence: ";
    prompt += std::to_string(report.AdjustedConfidence);
    prompt += "\n";

    for (const auto& issue : report.Issues)
    {
        prompt += "- [";
        prompt += issue.Severity.empty() ? "warning" : issue.Severity;
        prompt += "/";
        prompt += issue.Code.empty() ? "unknown" : issue.Code;
        prompt += "] ";
        prompt += issue.Message;

        if (!issue.Evidence.empty())
        {
            prompt += " evidence: ";
            prompt += issue.Evidence;
        }

        prompt += "\n";
    }

    prompt += "\nRevise the JSON response to satisfy the verifier. If the recovered facts are insufficient, lower confidence and explicitly list uncertainty instead of inventing unsupported code.\n";
    return prompt;
}

bool IsLengthFinishReason(const std::optional<std::string>& finishReason)
{
    return finishReason.has_value() && finishReason.value() == "length";
}
bool TryQueryStatusCode(HINTERNET request, DWORD& statusCode)
{
    DWORD size = sizeof(statusCode);
    return WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &size,
        WINHTTP_NO_HEADER_INDEX) != FALSE;
}

bool HttpPostJson(const LlmClientConfig& config, const std::string& body, std::string& responseBody, std::string& error)
{
    bool success = false;
    const auto started = std::chrono::steady_clock::now();
    URL_COMPONENTSW components = {};
    std::wstring endpoint = Utf8ToWide(config.Endpoint);
    std::wstring host(256, L'\0');
    std::wstring path(2048, L'\0');
    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET request = nullptr;

    do
    {
        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        if (endpoint.empty())
        {
            error = "endpoint is empty";
            break;
        }

        components.dwStructSize = sizeof(components);
        components.lpszHostName = host.data();
        components.dwHostNameLength = static_cast<DWORD>(host.size());
        components.lpszUrlPath = path.data();
        components.dwUrlPathLength = static_cast<DWORD>(path.size());

        if (!WinHttpCrackUrl(endpoint.c_str(), static_cast<DWORD>(endpoint.size()), 0, &components))
        {
            error = DescribeWinHttpError("WinHttpCrackUrl", GetLastError());
            break;
        }

        host.resize(components.dwHostNameLength);
        path.resize(components.dwUrlPathLength);

        if (path.empty())
        {
            path = L"/";
        }

        LogVerbose(
            config,
            "LLM HTTP prepare endpoint=" + config.Endpoint
                + " timeout_ms=" + std::to_string(config.TimeoutMs)
                + " request_bytes=" + std::to_string(body.size()));

        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        DWORD accessType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
#if defined(WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY)
        accessType = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY;
#endif
        session = WinHttpOpen(L"WindbgLlmDecompExtension/1.0", accessType, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

        if (session == nullptr && accessType != WINHTTP_ACCESS_TYPE_DEFAULT_PROXY)
        {
            session = WinHttpOpen(L"WindbgLlmDecompExtension/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        }

        if (session == nullptr)
        {
            error = DescribeWinHttpError("WinHttpOpen", GetLastError());
            break;
        }
        LogVerbose(config, "LLM HTTP session opened");

        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        WinHttpSetTimeouts(session, config.TimeoutMs, config.TimeoutMs, config.TimeoutMs, config.TimeoutMs);
        connection = WinHttpConnect(session, host.c_str(), components.nPort, 0);

        if (connection == nullptr)
        {
            error = DescribeWinHttpError("WinHttpConnect", GetLastError());
            break;
        }
        LogVerbose(config, "LLM HTTP connected");

        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        const DWORD flags = (components.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        request = WinHttpOpenRequest(connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

        if (request == nullptr)
        {
            error = DescribeWinHttpError("WinHttpOpenRequest", GetLastError());
            break;
        }
        LogVerbose(config, "LLM HTTP request opened");

        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        std::wstring headers = L"Content-Type: application/json\r\n";

        if (!config.ApiKey.empty())
        {
            headers += L"Authorization: Bearer ";
            headers += Utf8ToWide(config.ApiKey);
            headers += L"\r\n";
        }

        if (!WinHttpSendRequest(
                request,
                headers.c_str(),
                static_cast<DWORD>(headers.size()),
                const_cast<char*>(body.data()),
                static_cast<DWORD>(body.size()),
                static_cast<DWORD>(body.size()),
                0))
        {
            error = DescribeWinHttpError("WinHttpSendRequest", GetLastError());
            break;
        }
        LogVerbose(config, "LLM HTTP request body sent; waiting for response");
        LogProgress(config, "LLM request sent; waiting for provider response");

        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        if (!WinHttpReceiveResponse(request, nullptr))
        {
            error = DescribeWinHttpError("WinHttpReceiveResponse", GetLastError());
            break;
        }
        LogVerbose(config, "LLM HTTP response headers received");

        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        std::string response;
        bool readSucceeded = true;

        for (;;)
        {
            if (FailIfCancellationRequested(config, error))
            {
                readSucceeded = false;
                break;
            }

            DWORD available = 0;

            if (!WinHttpQueryDataAvailable(request, &available))
            {
                error = DescribeWinHttpError("WinHttpQueryDataAvailable", GetLastError());
                readSucceeded = false;
                break;
            }

            if (available == 0)
            {
                break;
            }

            std::string chunk(static_cast<size_t>(available), '\0');
            DWORD read = 0;

            if (!WinHttpReadData(request, chunk.data(), available, &read))
            {
                error = DescribeWinHttpError("WinHttpReadData", GetLastError());
                readSucceeded = false;
                break;
            }

            chunk.resize(read);
            response += chunk;
            LogVerbose(config, "LLM HTTP response chunk bytes=" + std::to_string(read) + " total=" + std::to_string(response.size()));
        }

        if (!readSucceeded)
        {
            break;
        }

        responseBody = response;

        DWORD statusCode = 0;

        if (!TryQueryStatusCode(request, statusCode))
        {
            error = DescribeWinHttpError("WinHttpQueryHeaders", GetLastError());
            break;
        }
        LogVerbose(config, "LLM HTTP status=" + std::to_string(statusCode) + " response_bytes=" + std::to_string(responseBody.size()));

        if (statusCode < 200 || statusCode >= 300)
        {
            error = "http status " + std::to_string(statusCode);

            if (!responseBody.empty())
            {
                error += ": " + responseBody;
            }

            break;
        }

        success = true;
    }
    while (false);

    if (success)
    {
        LogVerbose(config, "LLM HTTP completed elapsed_ms=" + std::to_string(ElapsedMs(started)) + " response_preview=" + BuildPreviewText(responseBody));
    }
    else if (!error.empty())
    {
        LogVerbose(config, "LLM HTTP failed elapsed_ms=" + std::to_string(ElapsedMs(started)) + " error=" + BuildPreviewText(error));
    }

    if (request != nullptr)
    {
        WinHttpCloseHandle(request);
    }

    if (connection != nullptr)
    {
        WinHttpCloseHandle(connection);
    }

    if (session != nullptr)
    {
        WinHttpCloseHandle(session);
    }

    return success;
}

AnalyzeResponse BuildMockResponse(const AnalyzeRequest& request)
{
    AnalyzeResponse response;
    response.Status = "ok";
    response.Provider = "mock-direct";
    response.Summary = "Mock provider based on deterministic analyzer facts.";
    response.PseudoC = BuildMockPseudoC(request, response.Params);
    response.Confidence = Clamp01(request.Facts.PreLlmConfidence + 0.05);
    response.Uncertainties = request.Facts.UncertainPoints;

    if (!request.Facts.Blocks.empty())
    {
        EvidenceItem evidence;
        evidence.Claim = "entry block contains the function prologue";
        evidence.Blocks.push_back(request.Facts.Blocks.front().Id);
        response.Evidence.push_back(evidence);
    }

    EnsurePseudoCodeTokens(response);
    response.RawModelJson = SerializeAnalyzeResponse(response, true);
    return response;
}
}

bool LoadLlmClientConfig(
    LlmClientConfig& config,
    std::string& error,
    bool validateProviderSettings)
{
    bool success = false;

    do
    {
        if (!TryLoadConfigFile(config, error))
        {
            break;
        }

        ApplyEnvironmentOverrides(config);

        if (validateProviderSettings && !config.Endpoint.empty() && config.ApiKey.empty() && ContainsInsensitive(config.Endpoint, "api.openai.com"))
        {
            error = "api key is empty; set api_key or api_key_env in " + BuildDefaultConfigPath() + ", or set DECOMP_LLM_API_KEY/OPENAI_API_KEY";
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

uint32_t GrowCompletionTokenBudget(
    uint32_t currentBudget,
    uint32_t minimumBudget)
{
    uint64_t grownBudget = static_cast<uint64_t>(currentBudget) * 2ULL;

    if (grownBudget < minimumBudget)
    {
        grownBudget = minimumBudget;
    }

    if (grownBudget > 32000ULL)
    {
        grownBudget = 32000ULL;
    }

    return static_cast<uint32_t>(grownBudget);
}

bool SubmitChatJsonAttempt(
    const LlmClientConfig& config,
    const std::string& systemPrompt,
    const std::string& userPrompt,
    uint32_t maxCompletionTokens,
    std::string& modelJson,
    std::string& error,
    bool& outputTruncated)
{
    outputTruncated = false;
    const auto started = std::chrono::steady_clock::now();
    if (FailIfCancellationRequested(config, error))
    {
        return false;
    }

    LogVerbose(
        config,
        "LLM submit attempt model=" + config.Model
            + " max_completion_tokens=" + std::to_string(maxCompletionTokens)
            + " system_chars=" + std::to_string(systemPrompt.size())
            + " user_chars=" + std::to_string(userPrompt.size()));

    JsonValue messageSystem = JsonValue::MakeObject();
    messageSystem.Set("role", JsonValue::MakeString("system"));
    messageSystem.Set("content", JsonValue::MakeString(systemPrompt));

    JsonValue messageUser = JsonValue::MakeObject();
    messageUser.Set("role", JsonValue::MakeString("user"));
    messageUser.Set("content", JsonValue::MakeString(userPrompt));

    JsonValue messages = JsonValue::MakeArray();
    messages.PushBack(messageSystem);
    messages.PushBack(messageUser);

    JsonValue responseFormat = JsonValue::MakeObject();
    responseFormat.Set("type", JsonValue::MakeString("json_object"));

    JsonValue body = JsonValue::MakeObject();
    body.Set("model", JsonValue::MakeString(config.Model));
    body.Set("temperature", JsonValue::MakeNumber(0.1));
    body.Set("max_completion_tokens", JsonValue::MakeNumber(static_cast<double>(maxCompletionTokens)));
    body.Set("response_format", responseFormat);
    body.Set("messages", messages);

    std::string requestBody = SerializeJson(body, false);
    std::string responseBody;

    if (!HttpPostJson(config, requestBody, responseBody, error))
    {
        LogVerbose(config, "LLM submit attempt failed during HTTP elapsed_ms=" + std::to_string(ElapsedMs(started)));
        return false;
    }

    LogVerbose(config, "LLM provider raw response received bytes=" + std::to_string(responseBody.size()) + " elapsed_ms=" + std::to_string(ElapsedMs(started)));

    const JsonParseResult parsed = ParseJson(responseBody);

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        error = parsed.Error.empty() ? "provider returned invalid JSON" : parsed.Error;
        LogVerbose(config, "LLM provider response JSON parse failed: " + BuildPreviewText(error));
        return false;
    }

    const auto finishReason = ExtractFinishReason(parsed.Value);
    const auto content = ExtractChatContent(parsed.Value);
    LogVerbose(config, "LLM provider finish_reason=" + (finishReason.has_value() ? finishReason.value() : std::string("<missing>")));

    if (!content.has_value())
    {
        if (IsLengthFinishReason(finishReason))
        {
            outputTruncated = true;
            error = "model output was truncated before content extraction (finish_reason=length)";
        }
        else
        {
            error = "provider response did not include message content";
        }

        return false;
    }

    modelJson = StripCodeFences(content.value());
    outputTruncated = IsLengthFinishReason(finishReason);
    LogVerbose(
        config,
        "LLM content extracted chars=" + std::to_string(modelJson.size())
            + " truncated=" + std::string(outputTruncated ? "true" : "false")
            + " preview=" + BuildPreviewText(modelJson));
    return true;
}

bool SubmitChatJsonWithRetry(
    const LlmClientConfig& config,
    const std::string& systemPrompt,
    const std::string& userPrompt,
    uint32_t initialBudget,
    uint32_t retryFloor,
    std::string& modelJson,
    std::string& error)
{
    std::string firstJson;
    std::string firstError;
    bool firstTruncated = false;
    if (FailIfCancellationRequested(config, error))
    {
        return false;
    }

    LogVerbose(config, "LLM request begin initial_budget=" + std::to_string(initialBudget) + " retry_floor=" + std::to_string(retryFloor));
    const bool firstSuccess = SubmitChatJsonAttempt(config, systemPrompt, userPrompt, initialBudget, firstJson, firstError, firstTruncated);

    if (firstSuccess && !firstTruncated)
    {
        modelJson = firstJson;
        LogVerbose(config, "LLM request accepted first attempt");
        return true;
    }

    const uint32_t retryBudget = GrowCompletionTokenBudget(initialBudget, retryFloor);

    if (retryBudget > initialBudget)
    {
        std::string retryJson;
        std::string retryError;
        bool retryTruncated = false;
        if (FailIfCancellationRequested(config, error))
        {
            return false;
        }

        LogVerbose(
            config,
            "LLM request retrying with larger token budget retry_budget=" + std::to_string(retryBudget)
                + " first_success=" + std::string(firstSuccess ? "true" : "false")
                + " first_truncated=" + std::string(firstTruncated ? "true" : "false")
                + " first_error=" + BuildPreviewText(firstError));
        LogProgress(config, "LLM output was truncated; retrying with a larger token budget");

        if (SubmitChatJsonAttempt(config, systemPrompt, userPrompt, retryBudget, retryJson, retryError, retryTruncated))
        {
            modelJson = retryJson;
            LogVerbose(config, "LLM request accepted retry attempt truncated=" + std::string(retryTruncated ? "true" : "false"));
            return true;
        }

        if (firstSuccess && !firstJson.empty())
        {
            modelJson = firstJson;
            LogVerbose(config, "LLM request using first attempt despite retry failure");
            return true;
        }

        error = retryError;
        LogVerbose(config, "LLM request failed after retry: " + BuildPreviewText(error));
        return false;
    }

    if (firstSuccess && !firstJson.empty())
    {
        modelJson = firstJson;
        LogVerbose(config, "LLM request using first attempt with no larger retry budget");
        return true;
    }

    error = firstError;
    LogVerbose(config, "LLM request failed: " + BuildPreviewText(error));
    return false;
}

bool ParseAndMaybeRetryWithVerifier(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    const std::string& systemPrompt,
    const std::string& userPrompt,
    uint32_t initialBudget,
    uint32_t retryFloor,
    const std::string& initialJson,
    const std::string& providerName,
    AnalyzeResponse& response,
    std::string& error)
{
    std::string parseError;

    if (!ParseAnalyzeResponse(initialJson, response, parseError))
    {
        error = "failed to parse model JSON: " + parseError + "; preview: " + BuildPreviewText(initialJson);
        LogVerbose(config, "LLM model JSON parse failed: " + BuildPreviewText(error));
        return false;
    }
    LogVerbose(config, "LLM model JSON parsed");

    VerifyResponse(request, response);
    LogVerbose(
        config,
        "verifier after initial LLM response adjusted=" + std::to_string(response.Verifier.AdjustedConfidence)
            + " conflicts=" + std::to_string(response.Verifier.FactConflicts)
            + " issues=" + std::to_string(response.Verifier.Issues.size()));

    if (!ShouldRetryWithVerifierFeedback(response.Verifier))
    {
        response.Provider = providerName;
        response.RawModelJson = initialJson;
        response.Status = response.Status.empty() ? "ok" : response.Status;
        return true;
    }

    const std::string retryPrompt = userPrompt + BuildVerifierFeedbackPrompt(response.Verifier);
    const uint32_t retryBudget = GrowCompletionTokenBudget(initialBudget, retryFloor);
    std::string retryJson;
    std::string retryError;
    LogVerbose(config, "verifier feedback retry begin retry_budget=" + std::to_string(retryBudget));
    LogProgress(config, "verifier requested one LLM retry");

    if (!SubmitChatJsonWithRetry(config, systemPrompt, retryPrompt, retryBudget, retryFloor, retryJson, retryError))
    {
        response.Provider = providerName + "-verifier-feedback-unrevised";
        response.RawModelJson = initialJson;
        response.Status = response.Status.empty() ? "ok" : response.Status;
        response.Uncertainties.push_back("verifier feedback retry failed: " + BuildPreviewText(retryError));
        LogVerbose(config, "verifier feedback retry failed; keeping original response");
        return true;
    }

    AnalyzeResponse retryResponse;

    if (!ParseAnalyzeResponse(retryJson, retryResponse, parseError))
    {
        response.Provider = providerName + "-verifier-feedback-unrevised";
        response.RawModelJson = initialJson;
        response.Status = response.Status.empty() ? "ok" : response.Status;
        response.Uncertainties.push_back("verifier feedback retry returned unparsable JSON: " + BuildPreviewText(parseError));
        LogVerbose(config, "verifier feedback retry returned unparsable JSON; keeping original response");
        return true;
    }

    VerifyResponse(request, retryResponse);
    LogVerbose(
        config,
        "verifier after feedback retry adjusted=" + std::to_string(retryResponse.Verifier.AdjustedConfidence)
            + " conflicts=" + std::to_string(retryResponse.Verifier.FactConflicts)
            + " issues=" + std::to_string(retryResponse.Verifier.Issues.size()));

    if (retryResponse.Verifier.AdjustedConfidence + 0.02 >= response.Verifier.AdjustedConfidence
        || retryResponse.Verifier.FactConflicts < response.Verifier.FactConflicts)
    {
        response = std::move(retryResponse);
        response.Provider = providerName + "-verifier-feedback";
        response.RawModelJson = retryJson;
        response.Status = response.Status.empty() ? "ok" : response.Status;
        response.Uncertainties.push_back("verifier feedback retry was applied");
        LogVerbose(config, "verifier feedback retry applied");
        return true;
    }

    response.Provider = providerName + "-verifier-feedback-kept-original";
    response.RawModelJson = initialJson;
    response.Status = response.Status.empty() ? "ok" : response.Status;
    response.Uncertainties.push_back("verifier feedback retry did not improve adjusted confidence enough");
    LogVerbose(config, "verifier feedback retry rejected; keeping original response");
    return true;
}

bool AnalyzeWithSinglePassLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error)
{
    std::string modelJson;
    const std::string systemPrompt = BuildSystemPrompt(request);
    const std::string userPrompt = BuildUserPrompt(request);
    LogVerbose(config, "single-pass LLM prompts built system_chars=" + std::to_string(systemPrompt.size()) + " user_chars=" + std::to_string(userPrompt.size()));
    LogProgress(config, "LLM single-pass analysis started");

    if (!SubmitChatJsonWithRetry(
            config,
            systemPrompt,
            userPrompt,
            config.MaxCompletionTokens,
            (std::max)(static_cast<uint32_t>(4000), config.MaxCompletionTokens),
            modelJson,
            error))
    {
        return false;
    }

    return ParseAndMaybeRetryWithVerifier(
        request,
        config,
        systemPrompt,
        userPrompt,
        config.MaxCompletionTokens,
        (std::max)(static_cast<uint32_t>(4000), config.MaxCompletionTokens),
        modelJson,
        "openai-compatible-direct",
        response,
        error);
}

bool AnalyzeWithChunkedLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error)
{
    const std::vector<ChunkPlan> chunkPlans = BuildChunkPlans(request, config);
    LogVerbose(config, "chunked LLM plan count=" + std::to_string(chunkPlans.size()));

    if (chunkPlans.empty())
    {
        return AnalyzeWithSinglePassLlm(request, config, response, error);
    }

    LogProgress(config, "LLM chunked analysis started: " + std::to_string(chunkPlans.size()) + " chunks");

    std::vector<ChunkAnalysis> chunkAnalyses;
    chunkAnalyses.reserve(chunkPlans.size());

    for (const ChunkPlan& plan : chunkPlans)
    {
        if (FailIfCancellationRequested(config, error))
        {
            return false;
        }

        std::string chunkJson;
        std::string chunkError;
        LogVerbose(
            config,
            "chunk LLM request begin id=" + plan.Id
                + " slot=" + std::to_string(plan.SlotIndex + 1)
                + "/" + std::to_string(plan.TotalChunks)
                + " blocks=" + std::to_string(plan.BlockIndices.size()));
        LogProgress(
            config,
            "LLM chunk " + std::to_string(plan.SlotIndex + 1)
                + "/" + std::to_string(plan.TotalChunks)
                + " started");

        if (!SubmitChatJsonWithRetry(
                config,
                BuildChunkSystemPrompt(request),
                BuildChunkUserPrompt(request, plan),
                config.ChunkCompletionTokens,
                (std::max)(static_cast<uint32_t>(4500), config.ChunkCompletionTokens),
                chunkJson,
                chunkError))
        {
            error = "chunk analysis failed for " + plan.Id + ": " + chunkError;
            return false;
        }

        ChunkAnalysis chunkAnalysis;
        std::string parseError;

        if (!ParseChunkAnalysis(chunkJson, chunkAnalysis, parseError))
        {
            error = "failed to parse chunk JSON for " + plan.Id + ": " + parseError + "; preview: " + BuildPreviewText(chunkJson);
            LogVerbose(config, "chunk LLM parse failed id=" + plan.Id + " error=" + BuildPreviewText(error));
            return false;
        }

        if (chunkAnalysis.ChunkId.empty())
        {
            chunkAnalysis.ChunkId = plan.Id;
        }

        LogVerbose(config, "chunk LLM parsed id=" + chunkAnalysis.ChunkId + " summary_chars=" + std::to_string(chunkAnalysis.SummaryLocalized.size()) + " pseudo_steps=" + std::to_string(chunkAnalysis.PseudoSteps.size()));
        LogProgress(
            config,
            "LLM chunk " + std::to_string(plan.SlotIndex + 1)
                + "/" + std::to_string(plan.TotalChunks)
                + " completed");
        chunkAnalyses.push_back(std::move(chunkAnalysis));
        Sleep(150);
    }

    std::string mergeJson;
    const std::string mergeSystemPrompt = BuildMergeSystemPrompt(request);
    const std::string mergeUserPrompt = BuildMergeUserPrompt(request, chunkPlans, chunkAnalyses);
    LogVerbose(config, "merge LLM prompts built system_chars=" + std::to_string(mergeSystemPrompt.size()) + " user_chars=" + std::to_string(mergeUserPrompt.size()));
    LogProgress(config, "LLM merge request started");

    if (!SubmitChatJsonWithRetry(
            config,
            mergeSystemPrompt,
            mergeUserPrompt,
            config.MergeCompletionTokens,
            (std::max)(static_cast<uint32_t>(9000), config.MergeCompletionTokens),
            mergeJson,
            error))
    {
        error = "merge analysis failed: " + error;
        return false;
    }

    return ParseAndMaybeRetryWithVerifier(
        request,
        config,
        mergeSystemPrompt,
        mergeUserPrompt,
        config.MergeCompletionTokens,
        (std::max)(static_cast<uint32_t>(9000), config.MergeCompletionTokens),
        mergeJson,
        "openai-compatible-direct-chunked",
        response,
        error);
}

bool AnalyzeWithLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error)
{
    if (config.Endpoint.empty())
    {
        if (FailIfCancellationRequested(config, error))
        {
            return false;
        }

        LogVerbose(config, "LLM endpoint empty; using deterministic mock provider");
        response = BuildMockResponse(request);
        return true;
    }

    if (FailIfCancellationRequested(config, error))
    {
        return false;
    }

    if (ShouldUseChunkedAnalysis(request, config))
    {
        std::string chunkedError;
        LogVerbose(config, "choosing chunked LLM path");

        if (AnalyzeWithChunkedLlm(request, config, response, chunkedError))
        {
            return true;
        }

        LogVerbose(config, "chunked LLM path failed; falling back to single-pass: " + BuildPreviewText(chunkedError));
        if (AnalyzeWithSinglePassLlm(request, config, response, error))
        {
            response.Provider = "openai-compatible-direct-fallback";
            response.Uncertainties.push_back("chunked analysis failed and single-pass fallback was used: " + BuildPreviewText(chunkedError));
            return true;
        }

        if (error.empty())
        {
            error = chunkedError;
        }

        return false;
    }

    LogVerbose(config, "choosing single-pass LLM path");
    return AnalyzeWithSinglePassLlm(request, config, response, error);
}

std::string BuildDebugPromptDump(const AnalyzeRequest& request)
{
    std::string dump;
    dump += "system_prompt:\n";
    dump += BuildSystemPrompt(request);
    dump += "\n\nuser_prompt:\n";
    dump += BuildUserPrompt(request);
    dump += "\n\nprompt_facts_json:\n";
    dump += SerializeJson(BuildPromptFactsJson(request), true);
    dump += "\n";
    return dump;
}
}
