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
#include <ctime>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "decomp/json.h"
#include "decomp/llm_client.h"
#include "decomp/llm_verifier_feedback.h"
#include "decomp/llm_prompt_facts.h"
#include "decomp/pseudo_tokens.h"
#include "decomp/protocol.h"
#include "decomp/string_utils.h"
#include "decomp/verifier.h"
#include "llm_chunk_prompt_facts.h"

namespace decomp
{
namespace
{
constexpr const char* kDefaultLlmConfigFileName = "decomp.llm.json";
constexpr const char* kChatGptProviderName = "chatgpt";
constexpr const char* kOpenAICodexProviderName = "openai-codex";
constexpr const char* kOpenAICompatibleProviderName = "openai-compatible";
constexpr const char* kChatGptDefaultEndpoint = "https://chatgpt.com/backend-api/codex/responses";
constexpr const char* kChatGptDefaultModel = "gpt-5.5";
constexpr const char* kChatGptOAuthClientId = "app_EMoamEEZ73f0CkXaXp7hrann";
constexpr const char* kChatGptOAuthTokenEndpoint = "https://auth.openai.com/oauth/token";
constexpr int64_t kChatGptTokenRefreshSkewSeconds = 120;

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

std::string NormalizeProviderName(const std::string& provider)
{
    std::string value = ToLowerAscii(TrimCopy(provider));

    if (value.empty())
    {
        return kOpenAICompatibleProviderName;
    }

    if (value == "openai" || value == "openai_compatible" || value == "chat-completions")
    {
        return kOpenAICompatibleProviderName;
    }

    if (value == "chatgpt" || value == "chatgpt-subscription" || value == "codex" || value == "openai-codex" || value == "openai_codex")
    {
        return kChatGptProviderName;
    }

    return value;
}

bool IsChatGptProvider(const LlmClientConfig& config)
{
    const std::string provider = NormalizeProviderName(config.Provider);

    if (provider == kChatGptProviderName || provider == kOpenAICodexProviderName)
    {
        return true;
    }

    return ContainsInsensitive(config.Endpoint, "chatgpt.com/backend-api/codex");
}

bool EndsWithInsensitive(const std::string& value, const std::string& suffix)
{
    if (value.size() < suffix.size())
    {
        return false;
    }

    return ToLowerAscii(value.substr(value.size() - suffix.size())) == ToLowerAscii(suffix);
}

std::string NormalizeChatGptResponsesEndpoint(const std::string& endpoint)
{
    std::string value = TrimCopy(endpoint);

    if (value.empty())
    {
        value = kChatGptDefaultEndpoint;
    }

    if (value.find("://") == std::string::npos)
    {
        value = "https://" + value;
    }

    while (!value.empty() && value.back() == '/')
    {
        value.pop_back();
    }

    if (!EndsWithInsensitive(value, "/responses"))
    {
        value += "/responses";
    }

    return value;
}

bool TryNormalizeReasoningEffort(
    const std::string& value,
    std::string& normalized,
    std::string& error)
{
    normalized = ToLowerAscii(TrimCopy(value));

    if (normalized.empty() || normalized == "default" || normalized == "undefined" || normalized == "none")
    {
        normalized.clear();
        return true;
    }

    if (normalized == "minimal"
        || normalized == "low"
        || normalized == "medium"
        || normalized == "high"
        || normalized == "xhigh")
    {
        return true;
    }

    error = "config field 'reasoning_effort' must be undefined, none, minimal, low, medium, high, or xhigh";
    return false;
}

std::string GetUserHomeDirectory()
{
    std::string home = ReadEnvironmentVariable("USERPROFILE");

    if (!home.empty())
    {
        return home;
    }

    const std::string homeDrive = ReadEnvironmentVariable("HOMEDRIVE");
    const std::string homePath = ReadEnvironmentVariable("HOMEPATH");

    if (!homeDrive.empty() && !homePath.empty())
    {
        return homeDrive + homePath;
    }

    return std::string();
}

std::string ExpandConfigPath(const std::string& path)
{
    std::string expanded = TrimCopy(path);

    if (expanded.empty())
    {
        return expanded;
    }

    if (expanded == "~" || StartsWithInsensitive(expanded, "~/") || StartsWithInsensitive(expanded, "~\\"))
    {
        const std::string home = GetUserHomeDirectory();

        if (!home.empty())
        {
            if (expanded.size() == 1)
            {
                expanded = home;
            }
            else
            {
                expanded = home + expanded.substr(1);
            }
        }
    }

    const DWORD required = ExpandEnvironmentStringsA(expanded.c_str(), nullptr, 0);

    if (required == 0)
    {
        return expanded;
    }

    std::string buffer(static_cast<size_t>(required), '\0');
    const DWORD written = ExpandEnvironmentStringsA(expanded.c_str(), buffer.data(), required);

    if (written == 0 || written > required)
    {
        return expanded;
    }

    if (!buffer.empty() && buffer.back() == '\0')
    {
        buffer.pop_back();
    }

    return buffer;
}

std::string BuildDefaultChatGptAuthFilePath()
{
    const std::string home = GetUserHomeDirectory();

    if (home.empty())
    {
        return std::string();
    }

    return home + "\\.codex\\auth.json";
}

bool FileExists(const std::string& path)
{
    if (path.empty())
    {
        return false;
    }

    const DWORD attributes = GetFileAttributesA(path.c_str());

    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string BuildChatGptAuthBootstrapHint(const LlmClientConfig& config)
{
    std::string authPath = TrimCopy(config.ChatGptAuthFile);

    if (authPath.empty())
    {
        authPath = BuildDefaultChatGptAuthFilePath();
    }

    std::string hint = "Run `codex login` outside WinDbg to create or refresh the Codex ChatGPT auth file";

    if (!authPath.empty())
    {
        hint += " (" + authPath + ")";
    }

    hint += ", or set DECOMP_LLM_CHATGPT_AUTH_FILE / DECOMP_LLM_CHATGPT_ACCESS_TOKEN. The extension does not launch a browser.";
    return hint;
}

void AppendChatGptAuthBootstrapHint(const LlmClientConfig& config, std::string& error)
{
    if (ContainsInsensitive(error, "codex login") || ContainsInsensitive(error, "does not launch a browser"))
    {
        return;
    }

    if (!error.empty())
    {
        error += ". ";
    }

    error += BuildChatGptAuthBootstrapHint(config);
}

bool IsLikelyChatGptInteractiveLoginRequired(const std::string& error)
{
    return ContainsInsensitive(error, "invalid_grant")
        || ContainsInsensitive(error, "invalid refresh")
        || ContainsInsensitive(error, "unauthorized")
        || ContainsInsensitive(error, "http status 401")
        || ContainsInsensitive(error, "http status 403");
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

        std::string providerValue = config.Provider;
        std::string endpointValue;
        std::string modelValue;
        std::string apiKeyValue;
        std::string apiKeyEnvironmentName;
        std::string chatGptAccessTokenValue;
        std::string chatGptAccessTokenEnvironmentName;
        std::string chatGptAuthFileValue = config.ChatGptAuthFile;
        std::string reasoningEffortValue = config.ReasoningEffort;
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

        if (!TryReadFirstStringMember(parsed.Value, { "provider", "provider_kind", "providerKind", "kind" }, providerValue, error))
        {
            break;
        }

        if (!TryReadFirstStringMember(parsed.Value, { "endpoint", "url", "base_url", "baseUrl" }, endpointValue, error))
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

        if (!TryReadFirstStringMember(parsed.Value, { "access_token", "accessToken", "chatgpt_access_token", "chatGptAccessToken" }, chatGptAccessTokenValue, error))
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

        if (!TryReadFirstStringMember(parsed.Value, { "access_token_env", "accessTokenEnv", "chatgpt_access_token_env", "chatGptAccessTokenEnv" }, chatGptAccessTokenEnvironmentName, error))
        {
            break;
        }

        if (!TryReadFirstStringMember(parsed.Value, { "auth_file", "authFile", "chatgpt_auth_file", "chatGptAuthFile", "codex_auth_file", "codexAuthFile" }, chatGptAuthFileValue, error))
        {
            break;
        }

        if (!TryReadFirstStringMember(parsed.Value, { "reasoning_effort", "reasoningEffort" }, reasoningEffortValue, error))
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

        config.Provider = NormalizeProviderName(providerValue);

        if (!endpointValue.empty())
        {
            config.Endpoint = endpointValue;
        }

        if (!modelValue.empty())
        {
            config.Model = modelValue;
        }

        if (!apiKeyValue.empty() && !IsChatGptProvider(config))
        {
            config.ApiKey = apiKeyValue;
        }

        if (!chatGptAccessTokenValue.empty())
        {
            config.ApiKey = chatGptAccessTokenValue;
        }

        if (!chatGptAuthFileValue.empty())
        {
            config.ChatGptAuthFile = ExpandConfigPath(chatGptAuthFileValue);
        }

        if (!TryNormalizeReasoningEffort(reasoningEffortValue, config.ReasoningEffort, error))
        {
            break;
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

        if (config.ApiKey.empty() && !apiKeyEnvironmentName.empty() && !IsChatGptProvider(config))
        {
            config.ApiKey = ReadEnvironmentVariable(apiKeyEnvironmentName.c_str());
        }

        if (config.ApiKey.empty() && !chatGptAccessTokenEnvironmentName.empty())
        {
            config.ApiKey = ReadEnvironmentVariable(chatGptAccessTokenEnvironmentName.c_str());
        }

        success = true;
    }
    while (false);

    return success;
}

void ApplyEnvironmentOverrides(LlmClientConfig& config)
{
    const std::string provider = ReadFirstEnvironmentVariable({ "DECOMP_LLM_PROVIDER" });
    const std::string endpoint = ReadFirstEnvironmentVariable({ "DECOMP_LLM_ENDPOINT" });
    const std::string model = ReadFirstEnvironmentVariable({ "DECOMP_LLM_MODEL" });
    const std::string apiKey = ReadFirstEnvironmentVariable({ "DECOMP_LLM_API_KEY" });
    const std::string openAiApiKey = ReadFirstEnvironmentVariable({ "OPENAI_API_KEY" });
    const std::string chatGptAccessToken = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHATGPT_ACCESS_TOKEN", "DECOMP_LLM_CODEX_ACCESS_TOKEN", "KERNFORGE_CODEX_ACCESS_TOKEN" });
    const std::string chatGptAuthFile = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHATGPT_AUTH_FILE", "DECOMP_LLM_CODEX_AUTH_FILE", "KERNFORGE_CODEX_AUTH_FILE" });
    const std::string reasoningEffort = ReadFirstEnvironmentVariable({ "DECOMP_LLM_REASONING_EFFORT" });
    const std::string timeout = ReadFirstEnvironmentVariable({ "DECOMP_LLM_TIMEOUT_MS" });
    const std::string maxCompletionTokens = ReadFirstEnvironmentVariable({ "DECOMP_LLM_MAX_COMPLETION_TOKENS" });
    const std::string forceChunked = ReadFirstEnvironmentVariable({ "DECOMP_LLM_FORCE_CHUNKED" });
    const std::string chunkTriggerInstructions = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_TRIGGER_INSTRUCTIONS" });
    const std::string chunkTriggerBlocks = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_TRIGGER_BLOCKS" });
    const std::string chunkBlockLimit = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_BLOCK_LIMIT" });
    const std::string chunkCountLimit = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_COUNT_LIMIT" });
    const std::string chunkCompletionTokens = ReadFirstEnvironmentVariable({ "DECOMP_LLM_CHUNK_COMPLETION_TOKENS" });
    const std::string mergeCompletionTokens = ReadFirstEnvironmentVariable({ "DECOMP_LLM_MERGE_COMPLETION_TOKENS" });

    if (!provider.empty())
    {
        config.Provider = NormalizeProviderName(provider);
    }

    if (!endpoint.empty())
    {
        config.Endpoint = endpoint;
    }

    if (!model.empty())
    {
        config.Model = model;
    }

    if (!apiKey.empty() && !IsChatGptProvider(config))
    {
        config.ApiKey = apiKey;
    }

    if (config.ApiKey.empty() && !IsChatGptProvider(config) && !openAiApiKey.empty())
    {
        config.ApiKey = openAiApiKey;
    }

    if (!chatGptAccessToken.empty())
    {
        config.ApiKey = chatGptAccessToken;
    }

    if (!chatGptAuthFile.empty())
    {
        config.ChatGptAuthFile = ExpandConfigPath(chatGptAuthFile);
    }

    if (!reasoningEffort.empty())
    {
        config.ReasoningEffort = ToLowerAscii(TrimCopy(reasoningEffort));
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

void ApplyProviderDefaults(LlmClientConfig& config)
{
    config.Provider = NormalizeProviderName(config.Provider);

    if (!IsChatGptProvider(config))
    {
        return;
    }

    config.Provider = kChatGptProviderName;

    config.Endpoint = NormalizeChatGptResponsesEndpoint(config.Endpoint);

    if (TrimCopy(config.Model).empty() || config.Model == "local-model")
    {
        config.Model = kChatGptDefaultModel;
    }

    if (TrimCopy(config.ChatGptAuthFile).empty())
    {
        config.ChatGptAuthFile = BuildDefaultChatGptAuthFilePath();
    }
}

std::string BuildMockPseudoC(const AnalyzeRequest& request, std::vector<TypedNameConfidence>& params)
{
    params = BuildAnalyzerSkeletonParams(request);
    return BuildAnalyzerSkeletonPseudoC(request);
}

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
    const size_t totalBlocks = request.Facts.Blocks.size();
    std::vector<ChunkPlan> plans;

    if (totalBlocks == 0)
    {
        return plans;
    }

    const size_t maxBlocksPerChunk = (std::max)(static_cast<size_t>(4), static_cast<size_t>(config.ChunkBlockLimit));
    const size_t maxChunkCount = (std::max)(static_cast<size_t>(1), static_cast<size_t>(config.ChunkCountLimit));
    std::unordered_map<std::string, size_t> blockIndexById;
    std::vector<std::vector<size_t>> groups;
    std::set<size_t> assigned;

    for (size_t index = 0; index < request.Facts.Blocks.size(); ++index)
    {
        blockIndexById[request.Facts.Blocks[index].Id] = index;
    }

    auto addUniqueIndex = [](std::vector<size_t>& values, size_t index)
    {
        if (std::find(values.begin(), values.end(), index) == values.end())
        {
            values.push_back(index);
        }
    };

    auto findBlockContainingAddress = [&request](uint64_t address) -> size_t
    {
        for (size_t index = 0; index < request.Facts.Blocks.size(); ++index)
        {
            const BasicBlock& block = request.Facts.Blocks[index];

            if (address >= block.StartAddress && address < block.EndAddress)
            {
                return index;
            }
        }

        return static_cast<size_t>(-1);
    };

    auto addGroup = [&](std::vector<size_t> group)
    {
        if (group.empty())
        {
            return;
        }

        std::sort(group.begin(), group.end());
        group.erase(std::unique(group.begin(), group.end()), group.end());

        const size_t first = group.front();
        const size_t last = group.back();

        if (first > 0)
        {
            group.insert(group.begin(), first - 1U);
        }

        if (last + 1U < totalBlocks)
        {
            group.push_back(last + 1U);
        }

        std::sort(group.begin(), group.end());
        group.erase(std::unique(group.begin(), group.end()), group.end());

        groups.push_back(std::move(group));
    };

    for (const ControlFlowRegion& region : request.Facts.ControlFlow)
    {
        std::vector<size_t> group;
        const auto headerIt = blockIndexById.find(region.HeaderBlock);

        if (headerIt != blockIndexById.end())
        {
            addUniqueIndex(group, headerIt->second);
        }

        for (const std::string& blockId : region.BodyBlocks)
        {
            const auto it = blockIndexById.find(blockId);

            if (it != blockIndexById.end())
            {
                addUniqueIndex(group, it->second);
            }
        }

        for (const std::string& blockId : region.LatchBlocks)
        {
            const auto it = blockIndexById.find(blockId);

            if (it != blockIndexById.end())
            {
                addUniqueIndex(group, it->second);
            }
        }

        for (const std::string& blockId : region.ExitBlocks)
        {
            const auto it = blockIndexById.find(blockId);

            if (it != blockIndexById.end())
            {
                addUniqueIndex(group, it->second);
            }
        }

        addGroup(std::move(group));
    }

    for (const SwitchInfo& switchInfo : request.Facts.Switches)
    {
        std::vector<size_t> group;
        const size_t headerIndex = findBlockContainingAddress(switchInfo.Site);

        if (headerIndex != static_cast<size_t>(-1))
        {
            addUniqueIndex(group, headerIndex);
        }

        for (const uint64_t target : switchInfo.CaseTargets)
        {
            const size_t targetIndex = findBlockContainingAddress(target);

            if (targetIndex != static_cast<size_t>(-1))
            {
                addUniqueIndex(group, targetIndex);
            }
        }

        addGroup(std::move(group));
    }

    std::sort(
        groups.begin(),
        groups.end(),
        [](const std::vector<size_t>& left, const std::vector<size_t>& right)
        {
            return left.empty() ? false : right.empty() ? true : left.front() < right.front();
        });

    std::vector<std::vector<size_t>> mergedGroups;

    for (const std::vector<size_t>& group : groups)
    {
        if (group.empty())
        {
            continue;
        }

        if (!mergedGroups.empty())
        {
            std::vector<size_t>& previous = mergedGroups.back();
            const bool overlapsOrTouches = group.front() <= previous.back() + kChunkOverlapBlocks + 1U;

            if (overlapsOrTouches && previous.size() + group.size() <= maxBlocksPerChunk + (kChunkOverlapBlocks * 2U))
            {
                previous.insert(previous.end(), group.begin(), group.end());
                std::sort(previous.begin(), previous.end());
                previous.erase(std::unique(previous.begin(), previous.end()), previous.end());
                continue;
            }
        }

        mergedGroups.push_back(group);
    }

    for (const std::vector<size_t>& group : mergedGroups)
    {
        for (const size_t blockIndex : group)
        {
            assigned.insert(blockIndex);
        }
    }

    groups = mergedGroups;

    for (size_t blockIndex = 0; blockIndex < totalBlocks;)
    {
        if (assigned.find(blockIndex) != assigned.end())
        {
            ++blockIndex;
            continue;
        }

        std::vector<size_t> group;

        while (blockIndex < totalBlocks
            && assigned.find(blockIndex) == assigned.end()
            && group.size() < maxBlocksPerChunk)
        {
            group.push_back(blockIndex);
            assigned.insert(blockIndex);
            ++blockIndex;
        }

        addGroup(std::move(group));
    }

    std::sort(
        groups.begin(),
        groups.end(),
        [](const std::vector<size_t>& left, const std::vector<size_t>& right)
        {
            return left.empty() ? false : right.empty() ? true : left.front() < right.front();
        });

    if (groups.empty())
    {
        for (size_t start = 0; start < totalBlocks; start += maxBlocksPerChunk)
        {
            std::vector<size_t> group;
            const size_t end = (std::min)(totalBlocks, start + maxBlocksPerChunk);

            for (size_t index = start; index < end; ++index)
            {
                group.push_back(index);
            }

            groups.push_back(std::move(group));
        }
    }

    while (groups.size() > maxChunkCount && groups.size() > 1)
    {
        size_t bestIndex = 0;
        size_t bestSize = static_cast<size_t>(-1);

        for (size_t index = 0; index + 1U < groups.size(); ++index)
        {
            const size_t combinedSize = groups[index].size() + groups[index + 1U].size();

            if (combinedSize < bestSize)
            {
                bestSize = combinedSize;
                bestIndex = index;
            }
        }

        groups[bestIndex].insert(groups[bestIndex].end(), groups[bestIndex + 1U].begin(), groups[bestIndex + 1U].end());
        std::sort(groups[bestIndex].begin(), groups[bestIndex].end());
        groups[bestIndex].erase(std::unique(groups[bestIndex].begin(), groups[bestIndex].end()), groups[bestIndex].end());
        groups.erase(groups.begin() + static_cast<std::ptrdiff_t>(bestIndex + 1U));
    }

    std::set<std::string> seenKeys;

    for (size_t index = 0; index < groups.size(); ++index)
    {
        std::vector<size_t>& group = groups[index];

        std::sort(group.begin(), group.end());
        group.erase(std::unique(group.begin(), group.end()), group.end());

        if (group.empty())
        {
            continue;
        }

        std::string key;

        for (const size_t blockIndex : group)
        {
            key += std::to_string(blockIndex) + ",";
        }

        if (!seenKeys.insert(key).second)
        {
            continue;
        }

        ChunkPlan plan;
        plan.Id = "chunk_" + std::to_string(plans.size());
        plan.SlotIndex = plans.size();
        plan.BlockIndices = group;
        plans.push_back(std::move(plan));
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

void TrimTrailingCommaForJsonRepair(std::string& text)
{
    const size_t last = text.find_last_not_of(" \t\r\n");

    if (last != std::string::npos && text[last] == ',')
    {
        text.erase(last, 1U);
    }
}

bool TryRepairTruncatedChunkJson(
    const std::string& text,
    std::string& repaired,
    std::string& error)
{
    repaired = TrimCopy(text);

    if (repaired.empty())
    {
        error = "empty JSON text";
        return false;
    }

    const size_t objectStart = repaired.find('{');

    if (objectStart == std::string::npos)
    {
        error = "missing JSON object start";
        return false;
    }

    if (objectStart != 0)
    {
        repaired = repaired.substr(objectStart);
    }

    std::vector<char> closers;
    bool inString = false;
    bool escaped = false;

    for (const char ch : repaired)
    {
        if (inString)
        {
            if (escaped)
            {
                escaped = false;
            }
            else if (ch == '\\')
            {
                escaped = true;
            }
            else if (ch == '"')
            {
                inString = false;
            }

            continue;
        }

        if (ch == '"')
        {
            inString = true;
            continue;
        }

        if (ch == '{')
        {
            closers.push_back('}');
            continue;
        }

        if (ch == '[')
        {
            closers.push_back(']');
            continue;
        }

        if (ch == '}' || ch == ']')
        {
            if (closers.empty() || closers.back() != ch)
            {
                error = "mismatched JSON delimiter";
                return false;
            }

            closers.pop_back();
        }
    }

    if (!inString && closers.empty())
    {
        error = "no repairable truncation";
        return false;
    }

    if (inString)
    {
        if (escaped && !repaired.empty() && repaired.back() == '\\')
        {
            repaired.pop_back();
        }

        repaired.push_back('"');
    }

    while (!closers.empty())
    {
        TrimTrailingCommaForJsonRepair(repaired);
        repaired.push_back(closers.back());
        closers.pop_back();
    }

    return true;
}

bool ParseChunkAnalysisWithRepair(
    const std::string& text,
    ChunkAnalysis& analysis,
    std::string& error,
    bool& repaired)
{
    repaired = false;

    ChunkAnalysis parsedAnalysis;

    if (ParseChunkAnalysis(text, parsedAnalysis, error))
    {
        analysis = std::move(parsedAnalysis);
        return true;
    }

    const std::string originalError = error;
    std::string repairedJson;
    std::string repairError;

    if (!TryRepairTruncatedChunkJson(text, repairedJson, repairError))
    {
        error = originalError + "; JSON repair unavailable: " + repairError;
        return false;
    }

    ChunkAnalysis repairedAnalysis;
    std::string repairedParseError;

    if (!ParseChunkAnalysis(repairedJson, repairedAnalysis, repairedParseError))
    {
        error = originalError + "; repaired JSON parse failed: " + repairedParseError;
        return false;
    }

    repairedAnalysis.Uncertainties.push_back("chunk JSON was repaired after parse error: " + originalError);
    analysis = std::move(repairedAnalysis);
    repaired = true;
    return true;
}

std::string BuildChunkSystemPrompt(const AnalyzeRequest& request)
{
    return
        "You are a reverse-engineering assistant analyzing one high-coverage chunk of a larger x64 function. "
        "Return only a JSON object with these keys: chunk_id, summary_localized, pseudo_steps, state_updates, observed_calls, observed_memory, uncertainties, evidence, confidence. "
        "Write summary_localized and uncertainties in the configured display language: " + DescribePreferredNaturalLanguage(request) + ". "
        "Keep pseudo_steps, state_updates, observed_calls, observed_memory, identifiers, and API names in English or C-style. "
        "Do not invent external call targets that are not present in the input. "
        "Use selection, analyzer_skeleton, recovered_arguments, recovered_locals, call_arguments, stack_pointer, ir_values, block_value_states, normalized_conditions, control_flow, abi, session_policy, observed_behavior, obfuscation, semantic_control_flow, data_references, call_targets, type_hints, idioms, callee_summaries, evidence_graph, and pdb facts as high-signal semantic hints when present. "
        "Treat analyzer_skeleton as a chunk-local refinement scaffold, not as finished source. "
        "When semantic_control_flow exposes high-confidence non-dead edges, prefer those edges over raw dispatcher loop edges and keep unresolved state transitions uncertain. "
        "When reconstructing flattened state machines, assign state variables only to recovered state constants or explicitly uncertain state values; never use data reads such as bytes[index] as state values. "
        "Preserve helper call argument expressions from call_arguments and ir_values, including operands and operators. "
        "Use control_flow loop, branch, and switch region metadata as structure evidence without inventing unsupported regions. "
        "Use abi facts for Microsoft x64 stack home slots, tail-call, thunk, no-return, and frame-base hints. "
        "Use session_policy to distinguish live, dump, kernel, and trace-like analysis constraints. "
        "Use observed_behavior for concrete register samples, current-frame pointers, memory hotspots, and TTD query hints without treating them as static proof. "
        "Treat opaque_predicates as dead-edge proof only when present, and treat substitution_idioms as local expression simplifications rather than source-level intent. "
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
    prompt += "5. Use selection, analyzer_skeleton, recovered_arguments, recovered_locals, call_arguments, stack_pointer, ir_values, block_value_states, normalized_conditions, control_flow, abi, session_policy, observed_behavior, data_references, call_targets, type_hints, idioms, callee_summaries, and pdb facts when they improve naming, prompt-coverage-aware uncertainty, stack-frame context, reaching-value state, region structure, calling convention, session constraints, observed runtime state, expression simplification, or type/side-effect hints.\n";
    prompt += "6. If the chunk is partial, say what is missing, but still describe the concrete work visible in this chunk.\n";
    prompt += "7. evidence must be an array of objects shaped like {\\\"claim\\\": string, \\\"blocks\\\": [string, ...]}.\n";
    prompt += "8. evidence.blocks must reference only block ids present in this chunk.\n";
    prompt += "9. Use graph_summary to keep chunk-local control-flow claims aligned with function-level CFG evidence.\n";
    prompt += "10. Use chunk_boundary live_in_values, live_out_values, and crossing edges to preserve state that enters or leaves this chunk.\n";
    prompt += "11. For flattened state machines, assign state variables only to recovered state constants or explicitly uncertain state values; never replace a state transition with a data read such as bytes[index]. Preserve helper call argument expressions from call_arguments and ir_values without dropping operands or operators.\n";
    return prompt;
}

std::string BuildMergeSystemPrompt(const AnalyzeRequest& request)
{
    return
        "You are a reverse-engineering assistant combining multiple high-coverage chunk analyses for one x64 function. "
        "Return only a JSON object with these keys: status, pseudo_c, summary, params, locals, uncertainties, evidence, confidence. "
        "Write summary and uncertainties in the configured display language: " + DescribePreferredNaturalLanguage(request) + ". "
        "Keep pseudo_c, params, locals, evidence, identifiers, and API names in English or C-style. "
        "Use the chunk plans, coverage metadata, summary alignment, quality, evidence, risk metadata, per-chunk risk details, merge review plan, confidence policy, acceptance checks, output contract, traceability matrix, obfuscation policy, deobfuscation plan, deobfuscation output contract, and deobfuscation conflict policy, and summaries to produce a fuller function-level pseudocode than a single-pass summary. "
        "Use selection, blocks, direct_calls, indirect_calls, recovered_arguments, recovered_locals, call_arguments, stack_pointer, memory_accesses, ir_values, switches, normalized_conditions, data_references, call_targets, evidence_graph, block_value_states, value_merges, control_flow, type_hints, idioms, callee_summaries, abi, session_policy, observed_behavior, obfuscation, semantic_control_flow, and pdb facts to preserve semantic names, prompt coverage limits, block grounding, call-site grounding, stack-frame context, reaching-value state, memory side effects, switch dispatch intent, control-flow intent, debugger-session constraints, and observed runtime context. "
        "When semantic_control_flow exposes high-confidence non-dead edges, prefer those edges over raw dispatcher loop edges and keep unresolved state transitions uncertain. "
        "When reconstructing flattened state machines, assign state variables only to recovered state constants or explicitly uncertain state values; never use data reads such as bytes[index] as state values. "
        "Preserve helper call argument expressions from call_arguments and ir_values, including operands and operators. "
        "Treat opaque_predicates as dead-edge proof only when present, and treat substitution_idioms as local expression simplifications rather than source-level intent. "
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
    prompt += "5. Use selection, blocks, direct_calls, indirect_calls, recovered_arguments, recovered_locals, call_arguments, stack_pointer, memory_accesses, ir_values, switches, normalized_conditions, data_references, call_targets, evidence_graph, block_value_states, value_merges, type_hints, idioms, callee_summaries, abi, session_policy, observed_behavior, and pdb facts when they help produce more concrete block-grounded calls, prompt-coverage-aware uncertainty, names, reaching values, memory reads/writes, switch dispatches, conditions, stack-frame context, runtime context, or session-aware uncertainty.\n";
    prompt += "6. If chunks disagree or coverage remains partial, explain that in uncertainties, but still keep the visible operations explicit.\n";
    prompt += "7. evidence must be an array of objects shaped like {\\\"claim\\\": string, \\\"blocks\\\": [string, ...]}.\n";
    prompt += "8. evidence.blocks must reference block ids that appear in the chunk summaries.\n";
    prompt += "9. Use chunking.coverage_complete, chunking.uncovered_block_ids, chunking.chunk_plans, chunking.summary_alignment, chunking.summary_quality, chunking.summary_evidence, chunking.merge_risk, chunking.merge_risk_details, chunking.merge_review_plan, chunking.merge_confidence_policy, chunking.merge_acceptance_checks, chunking.merge_output_contract, chunking.merge_traceability_matrix, chunking.merge_obfuscation_policy, chunking.merge_deobfuscation_plan, chunking.merge_deobfuscation_output_contract, and chunking.merge_deobfuscation_conflict_policy to detect omitted, duplicated, orphaned, low-confidence, weak-evidence, ungrounded, obfuscated, conflicting, or risk-coded chunks before trusting a short chunk summary.\n";
    prompt += "10. Respect chunking.merge_confidence_policy.recommended_confidence_ceiling when setting confidence, and carry required uncertainty into uncertainties.\n";
    prompt += "11. Satisfy chunking.merge_acceptance_checks before reporting a clean merge; if blocking_issues is non-empty, reflect that in uncertainties and confidence.\n";
    prompt += "12. Follow chunking.merge_output_contract for required keys, evidence shape, grounding, language, and blocked-merge behavior.\n";
    prompt += "13. Use chunking.merge_traceability_matrix to map each output field back to source fact paths and chunk metadata before finalizing the JSON.\n";
    prompt += "14. Follow chunking.merge_obfuscation_policy when reconstructing flattened dispatch, opaque predicates, substitution idioms, and semantic-control-flow overlays.\n";
    prompt += "15. Follow chunking.merge_deobfuscation_plan for dispatcher recovery, opaque edge pruning, substitution simplification, semantic overlay review, and raw-CFG fallback uncertainty.\n";
    prompt += "16. Follow chunking.merge_deobfuscation_output_contract when reflecting deobfuscation decisions into pseudo_c, summary, uncertainties, evidence, and confidence.\n";
    prompt += "17. Follow chunking.merge_deobfuscation_conflict_policy when semantic overlay, recovered edges, raw CFG, and chunk claims disagree.\n";
    prompt += "18. Treat the analyzer skeleton and graph-derived facts as a draft to refine; do not invent unsupported loops, switches, or calls during merge.\n";
    prompt += "19. For flattened state machines, assign state variables only to recovered state constants or explicitly uncertain state values; never replace a state transition with a data read such as bytes[index]. Preserve helper call argument expressions from call_arguments and ir_values without dropping operands or operators.\n";
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
        "Use recovered_arguments, recovered_locals, call_arguments, normalized_conditions, data_references, call_targets, evidence_graph, block_value_states, value_merges, obfuscation, semantic_control_flow, type_hints, idioms, callee_summaries, graph_summary, session_policy, observed_behavior, and pdb facts as high-confidence semantic hints when available. "
        "When semantic_control_flow exposes high-confidence non-dead edges, prefer those edges over raw dispatcher loop edges and do not render the dispatcher as business logic unless recovery confidence is low. "
        "When reconstructing flattened state machines, assign state variables only to recovered state constants or explicitly uncertain state values; never use data reads such as bytes[index] as state values. "
        "Preserve helper call argument expressions from call_arguments and ir_values, including operands and operators. "
        "Treat opaque_predicates as dead-edge proof only when present, and treat substitution_idioms as local expression simplifications rather than source-level intent. "
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
    prompt += "8. Use recovered_arguments, recovered_locals, call_arguments, normalized_conditions, data_references, call_targets, evidence_graph, block_value_states, value_merges, obfuscation, semantic_control_flow, type_hints, idioms, callee_summaries, session_policy, observed_behavior, and pdb facts when they improve variable names, helper summaries, branch expressions, or observed behavior notes.\n";
    prompt += "9. Prefer concrete pseudocode statements over summary comments when a memory read, write, compare, or branch is explicitly visible in the facts.\n";
    prompt += "10. If control flow is incomplete, keep visible operations explicit and mark only the missing pieces as uncertain.\n";
    prompt += "11. If truncation flags are true, preserve that uncertainty instead of over-claiming.\n";
    prompt += "12. Refine analyzer_skeleton instead of writing from scratch; preserve its evidence-backed regions, calls, idioms, and uncertainties unless contradicted by stronger facts.\n";
    prompt += "13. Use graph_summary as the authoritative CFG/region outline; do not invent loops, switches, or branches that graph_summary and control_flow do not support.\n";
    prompt += "14. If semantic_control_flow contains high-confidence non-dead edges, reconstruct control flow from those edges before describing raw dispatcher blocks; keep missing state transitions uncertain.\n";
    prompt += "15. Use semantic_control_flow dead edges and obfuscation.opaque_predicates only to justify proven dead edges, and use obfuscation.substitution_idioms only as local simplification evidence.\n";
    prompt += "16. For flattened state machines, assign state variables only to recovered state constants or explicitly uncertain state values; never replace a state transition with a data read such as bytes[index]. Preserve helper call argument expressions from call_arguments and ir_values without dropping operands or operators.\n";
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

std::string SanitizeEndpointForLog(const std::string& endpoint)
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

bool HttpPostBody(
    const LlmClientConfig& config,
    const std::string& endpointOverride,
    const std::string& body,
    const std::string& contentType,
    const std::string& accept,
    const std::string& bearerToken,
    const std::vector<std::pair<std::string, std::string>>& extraHeaders,
    std::string& responseBody,
    std::string& error)
{
    bool success = false;
    const auto started = std::chrono::steady_clock::now();
    URL_COMPONENTSW components = {};
    std::wstring endpoint = Utf8ToWide(endpointOverride);
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
            "LLM HTTP prepare endpoint=" + SanitizeEndpointForLog(endpointOverride)
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

        std::wstring headers;

        if (!contentType.empty())
        {
            headers += L"Content-Type: ";
            headers += Utf8ToWide(contentType);
            headers += L"\r\n";
        }

        if (!accept.empty())
        {
            headers += L"Accept: ";
            headers += Utf8ToWide(accept);
            headers += L"\r\n";
        }

        if (!bearerToken.empty())
        {
            headers += L"Authorization: Bearer ";
            headers += Utf8ToWide(bearerToken);
            headers += L"\r\n";
        }

        for (const auto& header : extraHeaders)
        {
            if (header.first.empty())
            {
                continue;
            }

            headers += Utf8ToWide(header.first);
            headers += L": ";
            headers += Utf8ToWide(header.second);
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
    else
    {
        if (!error.empty())
        {
            LogVerbose(config, "LLM HTTP failed elapsed_ms=" + std::to_string(ElapsedMs(started)) + " error=" + BuildPreviewText(error));
        }
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

bool HttpPostJson(const LlmClientConfig& config, const std::string& body, std::string& responseBody, std::string& error)
{
    return HttpPostBody(
        config,
        config.Endpoint,
        body,
        "application/json",
        "application/json",
        config.ApiKey,
        {},
        responseBody,
        error);
}

struct ChatGptOAuthTokens
{
    std::string AccessToken;
    std::string RefreshToken;
    std::string IdToken;
    std::string AccountId;
};

std::string ReadObjectStringField(const JsonValue& value, const std::vector<const char*>& names)
{
    if (!value.IsObject())
    {
        return std::string();
    }

    for (const char* name : names)
    {
        const JsonValue* member = value.Find(name);

        if (member != nullptr && member->IsString())
        {
            const std::string text = TrimCopy(member->GetString());

            if (!text.empty())
            {
                return text;
            }
        }
    }

    return std::string();
}

std::string ReadNestedObjectStringField(const JsonValue& value, const char* objectName, const std::vector<const char*>& names)
{
    const JsonValue* object = value.Find(objectName);

    if (object == nullptr || !object->IsObject())
    {
        return std::string();
    }

    return ReadObjectStringField(*object, names);
}

bool ReadChatGptAuthTokens(
    const std::string& path,
    std::string& originalText,
    ChatGptOAuthTokens& tokens,
    std::string& error)
{
    bool success = false;

    do
    {
        if (!ReadTextFile(path, originalText, error))
        {
            error = "failed to read ChatGPT auth file: " + error;
            break;
        }

        const JsonParseResult parsed = ParseJson(originalText);

        if (!parsed.Success || !parsed.Value.IsObject())
        {
            error = parsed.Error.empty() ? "ChatGPT auth file is not a JSON object" : parsed.Error;
            break;
        }

        tokens.AccessToken = ReadNestedObjectStringField(parsed.Value, "tokens", { "access_token", "accessToken" });
        tokens.RefreshToken = ReadNestedObjectStringField(parsed.Value, "tokens", { "refresh_token", "refreshToken" });
        tokens.IdToken = ReadNestedObjectStringField(parsed.Value, "tokens", { "id_token", "idToken" });
        tokens.AccountId = ReadNestedObjectStringField(parsed.Value, "tokens", { "account_id", "accountId" });

        if (tokens.AccessToken.empty() && tokens.RefreshToken.empty())
        {
            error = "ChatGPT auth file does not contain tokens.access_token or tokens.refresh_token: " + path;
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

int DecodeBase64UrlCharacter(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        return ch - 'A';
    }

    if (ch >= 'a' && ch <= 'z')
    {
        return ch - 'a' + 26;
    }

    if (ch >= '0' && ch <= '9')
    {
        return ch - '0' + 52;
    }

    if (ch == '-' || ch == '+')
    {
        return 62;
    }

    if (ch == '_' || ch == '/')
    {
        return 63;
    }

    return -1;
}

bool DecodeBase64Url(const std::string& encoded, std::string& decoded)
{
    decoded.clear();
    int value = 0;
    int bits = -8;

    for (const char ch : encoded)
    {
        if (ch == '=' || ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t')
        {
            continue;
        }

        const int digit = DecodeBase64UrlCharacter(ch);

        if (digit < 0)
        {
            return false;
        }

        value = (value << 6) | digit;
        bits += 6;

        if (bits >= 0)
        {
            decoded.push_back(static_cast<char>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }

    return true;
}

bool TryReadJwtExpiration(const std::string& token, int64_t& expiresAt)
{
    bool success = false;
    expiresAt = 0;

    do
    {
        const size_t firstDot = token.find('.');

        if (firstDot == std::string::npos)
        {
            break;
        }

        const size_t secondDot = token.find('.', firstDot + 1);
        const std::string payload = token.substr(
            firstDot + 1,
            secondDot == std::string::npos ? std::string::npos : secondDot - firstDot - 1);
        std::string decoded;

        if (!DecodeBase64Url(payload, decoded))
        {
            break;
        }

        const JsonParseResult parsed = ParseJson(decoded);

        if (!parsed.Success || !parsed.Value.IsObject())
        {
            break;
        }

        const JsonValue* exp = parsed.Value.Find("exp");

        if (exp == nullptr || !exp->IsNumber())
        {
            break;
        }

        expiresAt = static_cast<int64_t>(exp->GetNumber());
        success = expiresAt > 0;
    }
    while (false);

    return success;
}

bool IsChatGptTokenUsable(const std::string& token)
{
    const std::string trimmed = TrimCopy(token);

    if (trimmed.empty())
    {
        return false;
    }

    int64_t expiresAt = 0;

    if (!TryReadJwtExpiration(trimmed, expiresAt))
    {
        return true;
    }

    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    return now + kChatGptTokenRefreshSkewSeconds < expiresAt;
}

std::string UrlEncodeFormValue(const std::string& value)
{
    std::ostringstream stream;
    stream << std::uppercase << std::hex;

    for (const unsigned char ch : value)
    {
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~')
        {
            stream << static_cast<char>(ch);
        }
        else
        {
            if (ch == ' ')
            {
                stream << '+';
            }
            else
            {
                stream << '%' << std::setw(2) << std::setfill('0') << static_cast<int>(ch);
            }
        }
    }

    return stream.str();
}

std::string BuildFormBody(const std::vector<std::pair<std::string, std::string>>& fields)
{
    std::string body;

    for (const auto& field : fields)
    {
        if (!body.empty())
        {
            body += "&";
        }

        body += UrlEncodeFormValue(field.first);
        body += "=";
        body += UrlEncodeFormValue(field.second);
    }

    return body;
}

bool WriteTextFile(const std::string& path, const std::string& text, std::string& error)
{
    bool success = false;
    const std::string tempPath = path + ".tmp." + MakeRequestId();
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        file = CreateFileA(
            tempPath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            error = DescribeWinHttpError("CreateFile", GetLastError()) + ": " + tempPath;
            break;
        }

        DWORD written = 0;

        if (!WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) || written != text.size())
        {
            error = DescribeWinHttpError("WriteFile", GetLastError()) + ": " + tempPath;
            break;
        }

        if (!FlushFileBuffers(file))
        {
            error = DescribeWinHttpError("FlushFileBuffers", GetLastError()) + ": " + tempPath;
            break;
        }

        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;

        if (!MoveFileExA(tempPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            error = DescribeWinHttpError("MoveFileEx", GetLastError()) + ": " + tempPath + " -> " + path;
            break;
        }

        success = true;
    }
    while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    if (!success && !tempPath.empty())
    {
        DeleteFileA(tempPath.c_str());
    }

    return success;
}

bool UpdateChatGptAuthFile(
    const std::string& path,
    const std::string& originalText,
    const ChatGptOAuthTokens& tokens,
    std::string& error)
{
    bool success = false;

    do
    {
        const JsonParseResult parsed = ParseJson(originalText);

        if (!parsed.Success || !parsed.Value.IsObject())
        {
            error = parsed.Error.empty() ? "ChatGPT auth file is not a JSON object" : parsed.Error;
            break;
        }

        JsonValue root = parsed.Value;
        JsonValue tokenObject = JsonValue::MakeObject();
        const JsonValue* existingTokens = root.Find("tokens");

        if (existingTokens != nullptr && existingTokens->IsObject())
        {
            tokenObject = *existingTokens;
        }

        if (!tokens.AccessToken.empty())
        {
            tokenObject.Set("access_token", JsonValue::MakeString(tokens.AccessToken));
        }

        if (!tokens.RefreshToken.empty())
        {
            tokenObject.Set("refresh_token", JsonValue::MakeString(tokens.RefreshToken));
        }

        if (!tokens.IdToken.empty())
        {
            tokenObject.Set("id_token", JsonValue::MakeString(tokens.IdToken));
        }

        if (!tokens.AccountId.empty())
        {
            tokenObject.Set("account_id", JsonValue::MakeString(tokens.AccountId));
        }

        root.Set("tokens", tokenObject);
        root.Set("auth_mode", JsonValue::MakeString("chatgpt"));

        std::string output = SerializeJson(root, true);
        output += "\n";

        if (!WriteTextFile(path, output, error))
        {
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

std::string ExtractJsonErrorMessage(const JsonValue& root)
{
    const JsonValue* errorObject = root.Find("error");

    if (errorObject == nullptr)
    {
        return std::string();
    }

    if (errorObject->IsString())
    {
        return errorObject->GetString();
    }

    if (!errorObject->IsObject())
    {
        return std::string();
    }

    std::string message = ReadObjectStringField(*errorObject, { "message", "detail", "error_description", "type", "code" });

    if (message.empty())
    {
        message = SerializeJson(*errorObject, false);
    }

    return message;
}

bool RefreshChatGptAccessToken(
    const LlmClientConfig& config,
    const std::string& refreshToken,
    ChatGptOAuthTokens& tokens,
    std::string& error)
{
    bool success = false;
    const std::string body = BuildFormBody({
        { "grant_type", "refresh_token" },
        { "refresh_token", refreshToken },
        { "client_id", kChatGptOAuthClientId }
    });
    std::string responseBody;

    do
    {
        if (!HttpPostBody(
                config,
                kChatGptOAuthTokenEndpoint,
                body,
                "application/x-www-form-urlencoded",
                "application/json",
                std::string(),
                { { "User-Agent", "WindbgLlmDecompExtension/openai-codex" } },
                responseBody,
                error))
        {
            break;
        }

        const JsonParseResult parsed = ParseJson(responseBody);

        if (!parsed.Success || !parsed.Value.IsObject())
        {
            error = parsed.Error.empty() ? "ChatGPT OAuth refresh returned invalid JSON" : parsed.Error;
            break;
        }

        const std::string providerError = ExtractJsonErrorMessage(parsed.Value);

        if (!providerError.empty())
        {
            error = "ChatGPT OAuth refresh failed: " + providerError;
            break;
        }

        tokens.AccessToken = ReadObjectStringField(parsed.Value, { "access_token", "accessToken" });
        tokens.RefreshToken = ReadObjectStringField(parsed.Value, { "refresh_token", "refreshToken" });
        tokens.IdToken = ReadObjectStringField(parsed.Value, { "id_token", "idToken" });
        tokens.AccountId = ReadObjectStringField(parsed.Value, { "account_id", "accountId" });

        if (tokens.AccessToken.empty())
        {
            error = "ChatGPT OAuth refresh returned no access token";
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

bool ResolveChatGptAccessToken(
    const LlmClientConfig& config,
    std::string& accessToken,
    std::string& error)
{
    bool success = false;

    do
    {
        accessToken = TrimCopy(config.ApiKey);

        if (!accessToken.empty())
        {
            success = true;
            break;
        }

        const std::string authPath = TrimCopy(config.ChatGptAuthFile).empty() ? BuildDefaultChatGptAuthFilePath() : config.ChatGptAuthFile;

        if (authPath.empty())
        {
            error = "ChatGPT auth file path is unavailable; set chatgpt_auth_file or DECOMP_LLM_CHATGPT_AUTH_FILE";
            AppendChatGptAuthBootstrapHint(config, error);
            break;
        }

        std::string originalText;
        ChatGptOAuthTokens tokens;

        if (!ReadChatGptAuthTokens(authPath, originalText, tokens, error))
        {
            AppendChatGptAuthBootstrapHint(config, error);
            break;
        }

        if (IsChatGptTokenUsable(tokens.AccessToken))
        {
            accessToken = tokens.AccessToken;
            success = true;
            break;
        }

        if (TrimCopy(tokens.RefreshToken).empty())
        {
            error = "ChatGPT access token is expired and no refresh token is available: " + authPath;
            AppendChatGptAuthBootstrapHint(config, error);
            break;
        }

        ChatGptOAuthTokens refreshed;

        LogProgress(config, "ChatGPT access token expired; refreshing OAuth token");

        if (!RefreshChatGptAccessToken(config, tokens.RefreshToken, refreshed, error))
        {
            if (IsLikelyChatGptInteractiveLoginRequired(error))
            {
                AppendChatGptAuthBootstrapHint(config, error);
            }

            break;
        }

        if (!UpdateChatGptAuthFile(authPath, originalText, refreshed, error))
        {
            error = "failed to update ChatGPT auth file after refresh: " + error;
            break;
        }

        accessToken = refreshed.AccessToken;
        success = true;
    }
    while (false);

    return success;
}

JsonValue BuildChatGptResponsesRequestBody(
    const LlmClientConfig& config,
    const std::string& systemPrompt,
    const std::string& userPrompt,
    uint32_t maxCompletionTokens)
{
    JsonValue content = JsonValue::MakeArray();
    JsonValue text = JsonValue::MakeObject();
    text.Set("type", JsonValue::MakeString("input_text"));
    text.Set("text", JsonValue::MakeString(userPrompt));
    content.PushBack(text);

    JsonValue inputItem = JsonValue::MakeObject();
    inputItem.Set("role", JsonValue::MakeString("user"));
    inputItem.Set("content", content);

    JsonValue input = JsonValue::MakeArray();
    input.PushBack(inputItem);

    JsonValue include = JsonValue::MakeArray();
    include.PushBack(JsonValue::MakeString("reasoning.encrypted_content"));

    JsonValue responseFormat = JsonValue::MakeObject();
    responseFormat.Set("type", JsonValue::MakeString("json_object"));

    JsonValue textFormat = JsonValue::MakeObject();
    textFormat.Set("format", responseFormat);

    JsonValue body = JsonValue::MakeObject();
    body.Set("model", JsonValue::MakeString(config.Model));
    body.Set("input", input);
    body.Set("instructions", JsonValue::MakeString(systemPrompt));
    body.Set("store", JsonValue::MakeBoolean(false));
    body.Set("stream", JsonValue::MakeBoolean(true));
    body.Set("include", include);
    body.Set("parallel_tool_calls", JsonValue::MakeBoolean(true));
    body.Set("max_output_tokens", JsonValue::MakeNumber(static_cast<double>(maxCompletionTokens)));
    body.Set("text", textFormat);

    if (!TrimCopy(config.ReasoningEffort).empty())
    {
        JsonValue reasoning = JsonValue::MakeObject();
        reasoning.Set("effort", JsonValue::MakeString(ToLowerAscii(TrimCopy(config.ReasoningEffort))));
        body.Set("reasoning", reasoning);
    }

    return body;
}

void AppendUniqueText(std::vector<std::string>& texts, const std::string& text)
{
    const std::string trimmed = TrimCopy(text);

    if (trimmed.empty())
    {
        return;
    }

    for (const std::string& existing : texts)
    {
        if (existing == trimmed)
        {
            return;
        }
    }

    texts.push_back(trimmed);
}

std::optional<std::string> ExtractResponsesContent(const JsonValue& root)
{
    std::vector<std::string> texts;
    const JsonValue* outputText = root.Find("output_text");

    if (outputText != nullptr && outputText->IsString())
    {
        AppendUniqueText(texts, outputText->GetString());
    }

    const JsonValue* output = root.Find("output");

    if (output != nullptr && output->IsArray())
    {
        for (const JsonValue& item : output->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            const JsonValue* content = item.Find("content");

            if (content == nullptr || !content->IsArray())
            {
                continue;
            }

            for (const JsonValue& contentItem : content->GetArray())
            {
                if (!contentItem.IsObject())
                {
                    continue;
                }

                const JsonValue* text = contentItem.Find("text");

                if (text != nullptr && text->IsString())
                {
                    AppendUniqueText(texts, text->GetString());
                }
            }
        }
    }

    if (texts.empty())
    {
        return std::nullopt;
    }

    return JoinStrings(texts, "\n");
}

std::string ExtractResponsesFinishReason(const JsonValue& root)
{
    const JsonValue* incompleteDetails = root.Find("incomplete_details");

    if (incompleteDetails != nullptr && incompleteDetails->IsObject())
    {
        const std::string reason = ReadObjectStringField(*incompleteDetails, { "reason", "type", "message" });

        if (!reason.empty())
        {
            return reason;
        }
    }

    return ReadObjectStringField(root, { "status", "finish_reason" });
}

bool IsChatGptLengthReason(const std::string& reason)
{
    const std::string lowered = ToLowerAscii(reason);

    return ContainsInsensitive(lowered, "length")
        || ContainsInsensitive(lowered, "token")
        || ContainsInsensitive(lowered, "max_output");
}

bool ParseChatGptResponseObject(
    const JsonValue& root,
    std::string& modelJson,
    std::string& error,
    bool& outputTruncated)
{
    outputTruncated = false;
    const std::string providerError = ExtractJsonErrorMessage(root);

    if (!providerError.empty())
    {
        error = providerError;
        return false;
    }

    const std::string finishReason = ExtractResponsesFinishReason(root);
    const std::optional<std::string> content = ExtractResponsesContent(root);
    outputTruncated = IsChatGptLengthReason(finishReason);

    if (!content.has_value())
    {
        if (outputTruncated)
        {
            error = "model output was truncated before content extraction";
        }
        else
        {
            error = "ChatGPT Responses output did not include message content";
        }

        return false;
    }

    modelJson = StripCodeFences(content.value());
    return true;
}

bool ParseChatGptResponsesStream(
    const std::string& responseBody,
    std::string& modelJson,
    std::string& error,
    bool& outputTruncated)
{
    bool success = false;
    bool sawStreamData = false;
    std::string streamText;
    std::string finishReason;
    std::optional<JsonValue> completedResponse;
    size_t offset = 0;

    outputTruncated = false;

    do
    {
        while (offset <= responseBody.size())
        {
            const size_t end = responseBody.find('\n', offset);
            std::string line = end == std::string::npos ? responseBody.substr(offset) : responseBody.substr(offset, end - offset);

            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }

            line = TrimCopy(line);

            if (end == std::string::npos)
            {
                offset = responseBody.size() + 1;
            }
            else
            {
                offset = end + 1;
            }

            if (line.empty() || line[0] == ':' || StartsWithInsensitive(line, "event:"))
            {
                continue;
            }

            if (!StartsWithInsensitive(line, "data:"))
            {
                continue;
            }

            sawStreamData = true;
            const std::string payload = TrimCopy(line.substr(5));

            if (payload.empty() || payload == "[DONE]")
            {
                continue;
            }

            const JsonParseResult parsed = ParseJson(payload);

            if (!parsed.Success || !parsed.Value.IsObject())
            {
                error = parsed.Error.empty() ? "ChatGPT Responses stream contained invalid JSON" : parsed.Error;
                break;
            }

            const std::string providerError = ExtractJsonErrorMessage(parsed.Value);

            if (!providerError.empty())
            {
                error = providerError;
                break;
            }

            const std::string eventType = ReadObjectStringField(parsed.Value, { "type" });

            if (eventType == "response.output_text.delta")
            {
                streamText += ReadObjectStringField(parsed.Value, { "delta" });
            }
            else
            {
                if (eventType == "response.output_text.done")
                {
                    if (streamText.empty())
                    {
                        streamText = ReadObjectStringField(parsed.Value, { "text" });
                    }
                }
                else
                {
                    if (eventType == "response.completed" || eventType == "response.incomplete" || eventType == "response.failed")
                    {
                        const JsonValue* response = parsed.Value.Find("response");

                        if (response != nullptr && response->IsObject())
                        {
                            completedResponse = *response;
                            finishReason = ExtractResponsesFinishReason(*response);
                        }

                        if (eventType == "response.incomplete" && finishReason.empty())
                        {
                            finishReason = "incomplete";
                        }

                        if (eventType == "response.failed")
                        {
                            if (completedResponse.has_value())
                            {
                                std::string ignoredText;
                                bool ignoredTruncated = false;

                                if (!ParseChatGptResponseObject(completedResponse.value(), ignoredText, error, ignoredTruncated))
                                {
                                    break;
                                }
                            }

                            error = "ChatGPT Responses stream failed";
                            break;
                        }
                    }
                }
            }

            if (offset > responseBody.size())
            {
                break;
            }
        }

        if (!error.empty())
        {
            break;
        }

        if (!sawStreamData)
        {
            const JsonParseResult parsed = ParseJson(responseBody);

            if (!parsed.Success || !parsed.Value.IsObject())
            {
                error = parsed.Error.empty() ? "ChatGPT provider returned invalid JSON" : parsed.Error;
                break;
            }

            success = ParseChatGptResponseObject(parsed.Value, modelJson, error, outputTruncated);
            break;
        }

        if (completedResponse.has_value())
        {
            std::string completedJson;
            bool completedTruncated = false;

            if (ParseChatGptResponseObject(completedResponse.value(), completedJson, error, completedTruncated))
            {
                modelJson = completedJson;
                outputTruncated = completedTruncated;
                success = true;
                break;
            }

            if (streamText.empty())
            {
                break;
            }

            error.clear();
            outputTruncated = completedTruncated;
        }

        if (streamText.empty())
        {
            error = "ChatGPT Responses stream did not include output text";
            break;
        }

        outputTruncated = outputTruncated || IsChatGptLengthReason(finishReason);
        modelJson = StripCodeFences(streamText);
        success = true;
    }
    while (false);

    return success;
}

bool SubmitChatGptJsonAttempt(
    const LlmClientConfig& config,
    const std::string& systemPrompt,
    const std::string& userPrompt,
    uint32_t maxCompletionTokens,
    std::string& modelJson,
    std::string& error,
    bool& outputTruncated)
{
    bool success = false;
    outputTruncated = false;
    const auto started = std::chrono::steady_clock::now();
    std::string accessToken;

    do
    {
        if (FailIfCancellationRequested(config, error))
        {
            break;
        }

        if (!ResolveChatGptAccessToken(config, accessToken, error))
        {
            break;
        }

        JsonValue body = BuildChatGptResponsesRequestBody(config, systemPrompt, userPrompt, maxCompletionTokens);
        const std::string requestBody = SerializeJson(body, false);
        std::string responseBody;
        const std::string requestId = MakeRequestId();

        LogVerbose(
            config,
            "ChatGPT Responses submit attempt model=" + config.Model
                + " max_output_tokens=" + std::to_string(maxCompletionTokens)
                + " reasoning_effort=" + (config.ReasoningEffort.empty() ? std::string("<default>") : config.ReasoningEffort)
                + " system_chars=" + std::to_string(systemPrompt.size())
                + " user_chars=" + std::to_string(userPrompt.size()));

        if (!HttpPostBody(
                config,
                config.Endpoint,
                requestBody,
                "application/json",
                "text/event-stream",
                accessToken,
                {
                    { "originator", "codex_cli_rs" },
                    { "User-Agent", "WindbgLlmDecompExtension/openai-codex" },
                    { "session_id", requestId },
                    { "x-client-request-id", requestId }
                },
                responseBody,
                error))
        {
            break;
        }

        if (!ParseChatGptResponsesStream(responseBody, modelJson, error, outputTruncated))
        {
            break;
        }

        LogVerbose(
            config,
            "ChatGPT Responses content extracted chars=" + std::to_string(modelJson.size())
                + " truncated=" + std::string(outputTruncated ? "true" : "false")
                + " preview=" + BuildPreviewText(modelJson));

        success = true;
    }
    while (false);

    if (!success)
    {
        LogVerbose(config, "ChatGPT Responses submit failed elapsed_ms=" + std::to_string(ElapsedMs(started)) + " error=" + BuildPreviewText(error));
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
        ApplyProviderDefaults(config);

        if (!TryNormalizeReasoningEffort(config.ReasoningEffort, config.ReasoningEffort, error))
        {
            break;
        }

        if (validateProviderSettings && !config.Endpoint.empty() && config.ApiKey.empty() && ContainsInsensitive(config.Endpoint, "api.openai.com"))
        {
            error = "api key is empty; set api_key or api_key_env in " + BuildDefaultConfigPath() + ", or set DECOMP_LLM_API_KEY/OPENAI_API_KEY";
            break;
        }

        if (validateProviderSettings && IsChatGptProvider(config) && config.ApiKey.empty() && !FileExists(config.ChatGptAuthFile))
        {
            error = "ChatGPT auth is not configured; set access_token/access_token_env or chatgpt_auth_file in " + BuildDefaultConfigPath();
            AppendChatGptAuthBootstrapHint(config, error);
            break;
        }

        success = true;
    }
    while (false);

    return success;
}

std::string BuildDefaultLlmConfigPath()
{
    return BuildDefaultConfigPath();
}

std::string BuildDefaultChatGptAuthFilePathForConfig()
{
    return BuildDefaultChatGptAuthFilePath();
}

bool PathExistsAsFile(const std::string& path)
{
    return FileExists(path);
}

bool IsChatGptProviderConfig(const LlmClientConfig& config)
{
    return IsChatGptProvider(config);
}

LlmChunkPlanSummary SummarizeLlmChunkPlan(
    const AnalyzeRequest& request,
    const LlmClientConfig& config)
{
    LlmChunkPlanSummary summary;
    summary.UseChunked = ShouldUseChunkedAnalysis(request, config);

    if (!summary.UseChunked)
    {
        summary.EstimatedChunks = 1;
        summary.Reason = "single-pass";
        return summary;
    }

    const std::vector<ChunkPlan> plans = BuildChunkPlans(request, config);
    summary.EstimatedChunks = (std::max)(static_cast<size_t>(1), plans.size());

    if (config.ForceChunked)
    {
        summary.Reason = "force_chunked";
    }
    else if (request.Facts.Instructions.size() >= config.ChunkTriggerInstructions)
    {
        summary.Reason = "instruction_threshold";
    }
    else if (request.Facts.Blocks.size() >= config.ChunkTriggerBlocks)
    {
        summary.Reason = "block_threshold";
    }
    else
    {
        summary.Reason = "planner";
    }

    return summary;
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

    if (IsChatGptProvider(config))
    {
        return SubmitChatGptJsonAttempt(
            config,
            systemPrompt,
            userPrompt,
            maxCompletionTokens,
            modelJson,
            error,
            outputTruncated);
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
    const MergeOutputPostPolicy* mergePolicy,
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
    if (mergePolicy != nullptr)
    {
        ApplyMergeOutputPostPolicy(*mergePolicy, response);
    }
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
    if (mergePolicy != nullptr)
    {
        ApplyMergeOutputPostPolicy(*mergePolicy, retryResponse);
    }
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
        nullptr,
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
        bool repairedChunkJson = false;

        if (!ParseChunkAnalysisWithRepair(chunkJson, chunkAnalysis, parseError, repairedChunkJson))
        {
            std::string retryJson;
            std::string retryError;
            ChunkAnalysis retryChunkAnalysis;
            bool repairedRetryChunkJson = false;
            const std::string retryUserPrompt = BuildChunkUserPrompt(request, plan)
                + "\n\nPrevious chunk JSON parse failed: "
                + parseError
                + "\nReturn exactly one complete JSON object matching the requested schema. "
                + "Close all strings, arrays, and objects. Do not include markdown or prose outside the JSON object.\n";

            LogVerbose(config, "chunk LLM parse failed id=" + plan.Id + " error=" + BuildPreviewText(parseError));
            LogProgress(
                config,
                "LLM chunk " + std::to_string(plan.SlotIndex + 1)
                    + "/" + std::to_string(plan.TotalChunks)
                    + " returned invalid JSON; retrying");

            if (SubmitChatJsonWithRetry(
                    config,
                    BuildChunkSystemPrompt(request),
                    retryUserPrompt,
                    config.ChunkCompletionTokens,
                    (std::max)(static_cast<uint32_t>(6000), config.ChunkCompletionTokens + 1200U),
                    retryJson,
                    retryError)
                && ParseChunkAnalysisWithRepair(retryJson, retryChunkAnalysis, retryError, repairedRetryChunkJson))
            {
                chunkJson = retryJson;
                chunkAnalysis = std::move(retryChunkAnalysis);
                repairedChunkJson = repairedRetryChunkJson;
                chunkAnalysis.Uncertainties.push_back("chunk JSON retry was used after parse error: " + parseError);
            }
            else
            {
                error = "failed to parse chunk JSON for " + plan.Id + ": " + parseError + "; preview: " + BuildPreviewText(chunkJson);
                LogVerbose(config, "chunk LLM parse failed id=" + plan.Id + " error=" + BuildPreviewText(error));
                return false;
            }
        }

        if (repairedChunkJson)
        {
            LogVerbose(config, "chunk LLM JSON repaired id=" + plan.Id + " preview=" + BuildPreviewText(chunkJson));
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
    const MergeOutputPostPolicy mergePolicy = BuildMergeOutputPostPolicy(request, chunkPlans, chunkAnalyses);
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
        &mergePolicy,
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

std::string BuildDebugFirstChunkPromptDump(
    const AnalyzeRequest& request,
    const LlmClientConfig& config)
{
    const std::vector<ChunkPlan> chunkPlans = BuildChunkPlans(request, config);

    if (chunkPlans.empty())
    {
        return std::string();
    }

    std::string dump;
    dump += "chunk_system_prompt:\n";
    dump += BuildChunkSystemPrompt(request);
    dump += "\n\nchunk_user_prompt:\n";
    dump += BuildChunkUserPrompt(request, chunkPlans.front());
    dump += "\n";
    return dump;
}

std::vector<ChunkAnalysis> BuildDebugMergeChunkAnalyses(const std::vector<ChunkPlan>& chunkPlans)
{
    std::vector<ChunkAnalysis> chunkAnalyses;
    chunkAnalyses.reserve(chunkPlans.size());

    for (const ChunkPlan& plan : chunkPlans)
    {
        ChunkAnalysis analysis;
        analysis.ChunkId = plan.Id;
        analysis.SummaryLocalized = "debug merge chunk summary";
        analysis.PseudoSteps.push_back("debug pseudo step");
        analysis.StateUpdates.push_back("debug state update");
        analysis.Confidence = 0.50;
        chunkAnalyses.push_back(std::move(analysis));
    }

    return chunkAnalyses;
}

std::string BuildDebugMergePromptDump(
    const AnalyzeRequest& request,
    const LlmClientConfig& config)
{
    const std::vector<ChunkPlan> chunkPlans = BuildChunkPlans(request, config);

    if (chunkPlans.empty())
    {
        return std::string();
    }

    const std::vector<ChunkAnalysis> chunkAnalyses = BuildDebugMergeChunkAnalyses(chunkPlans);
    std::string dump;
    dump += "merge_system_prompt:\n";
    dump += BuildMergeSystemPrompt(request);
    dump += "\n\nmerge_user_prompt:\n";
    dump += BuildMergeUserPrompt(request, chunkPlans, chunkAnalyses);
    dump += "\n\nmerge_facts_json:\n";
    dump += SerializeJson(BuildMergeFactsJson(request, chunkPlans, chunkAnalyses), true);
    dump += "\n";
    return dump;
}

std::string BuildDebugVerifierFeedbackPrompt(const VerifyReport& report)
{
    return BuildVerifierFeedbackPrompt(report);
}

bool DebugParseChunkAnalysisJson(
    const std::string& text,
    bool& repaired,
    size_t& uncertaintyCount,
    std::string& error)
{
    ChunkAnalysis analysis;

    if (!ParseChunkAnalysisWithRepair(text, analysis, error, repaired))
    {
        uncertaintyCount = 0;
        return false;
    }

    uncertaintyCount = analysis.Uncertainties.size();
    return true;
}

void ApplyDebugMergeOutputPolicy(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response)
{
    const std::vector<ChunkPlan> chunkPlans = BuildChunkPlans(request, config);

    if (chunkPlans.empty())
    {
        VerifyResponse(request, response);
        return;
    }

    const std::vector<ChunkAnalysis> chunkAnalyses = BuildDebugMergeChunkAnalyses(chunkPlans);
    const MergeOutputPostPolicy policy = BuildMergeOutputPostPolicy(request, chunkPlans, chunkAnalyses);
    VerifyResponse(request, response);
    ApplyMergeOutputPostPolicy(policy, response);
}
}
