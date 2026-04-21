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
#include <cctype>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "decomp/json.h"
#include "decomp/llm_client.h"
#include "decomp/protocol.h"
#include "decomp/string_utils.h"

namespace decomp
{
namespace
{
constexpr const char* kDefaultLlmConfigFileName = "decomp.llm.json";

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

std::string BuildMockPseudoC(const AnalyzeRequest& request, std::vector<TypedNameConfidence>& params)
{
    const std::vector<std::string> parameterNames = EstimateParameters(request);
    const std::string functionName = SanitizeIdentifier(request.Facts.QueryText);
    std::string text;

    for (size_t index = 0; index < parameterNames.size(); ++index)
    {
        TypedNameConfidence item;
        item.Name = parameterNames[index];
        item.Type = "UNKNOWN_TYPE";
        item.Confidence = 0.35;
        params.push_back(item);
    }

    text += "UNKNOWN_TYPE ";
    text += functionName;
    text += "(";

    for (size_t index = 0; index < params.size(); ++index)
    {
        if (index != 0)
        {
            text += ", ";
        }

        text += params[index].Type + " " + params[index].Name;
    }

    text += ")\n{\n";
    text += "    /* Generated by in-process mock provider. Configure decomp.llm.json beside decomp.dll for semantic lifting. */\n";
    text += "    /* Blocks: " + std::to_string(request.Facts.Blocks.size()) + ", direct calls: " + std::to_string(request.Facts.Calls.size()) + ", indirect calls: " + std::to_string(request.Facts.IndirectCalls.size()) + " */\n";

    if (!request.Facts.Calls.empty())
    {
        text += "    /* First call target: " + request.Facts.Calls.front().Target + " */\n";
    }

    text += "    return UNKNOWN_VALUE;\n";
    text += "}\n";
    return text;
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
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, access.Site);
        item.Set("instruction", JsonValue::MakeString(instruction != nullptr ? BuildInstructionPreview(*instruction) : std::string()));
        array.PushBack(item);
    }

    return array;
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
    counts.Set("facts_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Facts.size())));
    counts.Set("uncertainties_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.UncertainPoints.size())));
    return counts;
}

JsonValue BuildPromptFactsJson(const AnalyzeRequest& request)
{
    JsonValue root = JsonValue::MakeObject();
    JsonValue module = JsonValue::MakeObject();
    JsonValue stackFrame = JsonValue::MakeObject();
    JsonValue truncation = JsonValue::MakeObject();
    JsonValue selection = JsonValue::MakeObject();
    bool regionsTruncated = false;
    bool blocksTruncated = false;
    bool directCallsTruncated = false;
    bool indirectCallsTruncated = false;
    bool switchesTruncated = false;
    bool memoryAccessesTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("base", JsonValue::MakeString(HexU64(request.Facts.Module.Base)));
    module.Set("size", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.Size)));
    module.Set("symbol_type", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.SymbolType)));

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
    root.Set("calling_convention", JsonValue::MakeString(request.Facts.CallingConvention));
    root.Set("module", module);
    root.Set("regions", BuildRegionsJson(request, &regionsTruncated));
    root.Set("stack_frame", stackFrame);
    root.Set("counts", BuildCountsJson(request));
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
    std::string SummaryKo;
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

    const size_t blocksPerChunk = (std::max)(static_cast<size_t>(4), static_cast<size_t>(config.ChunkBlockLimit));
    const size_t maxChunkCount = (std::max)(static_cast<size_t>(1), static_cast<size_t>(config.ChunkCountLimit));
    const size_t slotCount = (totalBlocks + blocksPerChunk - 1) / blocksPerChunk;
    std::vector<size_t> selectedSlots;

    if (slotCount <= maxChunkCount)
    {
        for (size_t slot = 0; slot < slotCount; ++slot)
        {
            selectedSlots.push_back(slot);
        }
    }
    else
    {
        selectedSlots = SelectSpreadIndices(slotCount, maxChunkCount);
    }

    std::set<std::string> seenRanges;

    for (size_t localIndex = 0; localIndex < selectedSlots.size(); ++localIndex)
    {
        const size_t slot = selectedSlots[localIndex];
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
        plan.TotalChunks = selectedSlots.size();

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
        const DisassembledInstruction* instruction = FindInstructionByAddress(request, access.Site);
        item.Set("instruction", JsonValue::MakeString(instruction != nullptr ? BuildInstructionPreview(*instruction) : std::string()));
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

    stackFrame.Set("stack_alloc", JsonValue::MakeNumber(static_cast<double>(request.Facts.StackFrame.StackAlloc)));
    stackFrame.Set("saved_nonvolatile", BuildStringArray(request.Facts.StackFrame.SavedNonvolatile, 8, nullptr));
    stackFrame.Set("uses_cookie", JsonValue::MakeBoolean(request.Facts.StackFrame.UsesCookie));
    stackFrame.Set("frame_pointer", JsonValue::MakeBoolean(request.Facts.StackFrame.FramePointer));

    functionOverview.Set("query_text", JsonValue::MakeString(request.Facts.QueryText));
    functionOverview.Set("entry_address", JsonValue::MakeString(HexU64(request.Facts.EntryAddress)));
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
    root.Set("global_facts", BuildStringArray(request.Facts.Facts, kChunkPromptFactLimit, &factsTruncated));
    root.Set("global_uncertainties", BuildStringArray(request.Facts.UncertainPoints, kChunkPromptUncertaintyLimit, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));

    truncation.Set("direct_calls", JsonValue::MakeBoolean(directCallsTruncated));
    truncation.Set("indirect_calls", JsonValue::MakeBoolean(indirectCallsTruncated));
    truncation.Set("switches", JsonValue::MakeBoolean(switchesTruncated));
    truncation.Set("memory_accesses", JsonValue::MakeBoolean(memoryAccessesTruncated));
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

    if (!TryGetOptionalString(root, "summary_ko", analysis.SummaryKo))
    {
        error = "summary_ko must be a string";
        return false;
    }

    if (analysis.SummaryKo.empty() && !TryGetOptionalString(root, "summary", analysis.SummaryKo))
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

    if (analysis.SummaryKo.empty())
    {
        error = "chunk response is missing summary_ko";
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
        item.Set("summary_ko", JsonValue::MakeString(analysis.SummaryKo));
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
    JsonValue stackFrame = JsonValue::MakeObject();
    JsonValue chunking = JsonValue::MakeObject();
    bool regionsTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;
    const std::optional<size_t> middleInstructionIndex = FindMiddleInterestingInstructionIndex(request);
    std::set<size_t> coveredBlocks;

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("base", JsonValue::MakeString(HexU64(request.Facts.Module.Base)));
    module.Set("size", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.Size)));

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
    root.Set("calling_convention", JsonValue::MakeString(request.Facts.CallingConvention));
    root.Set("module", module);
    root.Set("stack_frame", stackFrame);
    root.Set("counts", BuildCountsJson(request));
    root.Set("regions", BuildRegionsJson(request, &regionsTruncated));
    root.Set("instruction_window_head", BuildInstructionWindowJson(request, false));
    root.Set("instruction_window_middle", middleInstructionIndex.has_value() ? BuildInstructionWindowJson(request, middleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("instruction_window_tail", BuildInstructionWindowJson(request, true));
    root.Set("global_facts", BuildStringArray(request.Facts.Facts, 24, &factsTruncated));
    root.Set("global_uncertainties", BuildStringArray(request.Facts.UncertainPoints, 12, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));
    root.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));
    root.Set("chunking", chunking);
    root.Set("chunk_summaries", BuildChunkSummariesJson(chunkAnalyses));

    JsonValue truncation = JsonValue::MakeObject();
    truncation.Set("regions", JsonValue::MakeBoolean(regionsTruncated));
    truncation.Set("facts", JsonValue::MakeBoolean(factsTruncated));
    truncation.Set("uncertainties", JsonValue::MakeBoolean(uncertaintiesTruncated));
    root.Set("truncation", truncation);

    return root;
}
std::string BuildChunkSystemPrompt()
{
    return
        "You are a reverse-engineering assistant analyzing one high-coverage chunk of a larger x64 function. "
        "Return only a JSON object with these keys: chunk_id, summary_ko, pseudo_steps, state_updates, observed_calls, observed_memory, uncertainties, evidence, confidence. "
        "Write summary_ko and uncertainties in Korean. "
        "Keep pseudo_steps, state_updates, observed_calls, observed_memory, identifiers, and API names in English or C-style. "
        "Do not invent external call targets that are not present in the input. "
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
    prompt += "2. Write summary_ko and uncertainties in Korean.\n";
    prompt += "3. Keep pseudo_steps and state_updates concrete and operation-focused.\n";
    prompt += "4. Preserve visible reads, writes, comparisons, and branches instead of replacing them with generic comments.\n";
    prompt += "5. If the chunk is partial, say what is missing, but still describe the concrete work visible in this chunk.\n";
    prompt += "6. evidence must be an array of objects shaped like {\\\"claim\\\": string, \\\"blocks\\\": [string, ...]}.\n";
    prompt += "7. evidence.blocks must reference only block ids present in this chunk.\n";
    return prompt;
}

std::string BuildMergeSystemPrompt()
{
    return
        "You are a reverse-engineering assistant combining multiple high-coverage chunk analyses for one x64 function. "
        "Return only a JSON object with these keys: status, pseudo_c, summary, params, locals, uncertainties, evidence, confidence. "
        "Write summary and uncertainties in Korean. "
        "Keep pseudo_c, params, locals, evidence, identifiers, and API names in English or C-style. "
        "Use the chunk summaries to produce a fuller function-level pseudocode than a single-pass summary. "
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
    prompt += "2. Write summary and uncertainties in Korean.\n";
    prompt += "3. Build a richer pseudo_c than a short high-level summary; use the chunk evidence to cover the main body.\n";
    prompt += "4. Preserve unknowns with UNKNOWN_TYPE instead of omitting entire regions of logic.\n";
    prompt += "5. If chunks disagree or coverage remains partial, explain that in uncertainties, but still keep the visible operations explicit.\n";
    prompt += "6. evidence must be an array of objects shaped like {\\\"claim\\\": string, \\\"blocks\\\": [string, ...]}.\n";
    prompt += "7. evidence.blocks must reference block ids that appear in the chunk summaries.\n";
    return prompt;
}


std::string BuildSystemPrompt()
{
    return
        "You are a reverse-engineering assistant. "
        "Return only a JSON object with these keys: status, pseudo_c, summary, params, locals, uncertainties, evidence, confidence. "
        "Do not invent external call targets that are not present in the input. "
        "Use UNKNOWN_TYPE for uncertain types. "
        "Write summary and uncertainties in Korean. "
        "Keep pseudo_c, params, locals, evidence, identifiers, and API names in English or C-style as appropriate. "
        "Use evidence.blocks values that reference only valid basic block ids from the input. "
        "Blocks are a representative selection, not necessarily the first contiguous blocks in the function. "
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
    prompt += "3. Write summary and uncertainties in Korean.\n";
    prompt += "4. Do not translate symbol names, API names, or code identifiers unless needed inside Korean prose.\n";
    prompt += "5. evidence.blocks must reference existing basic block ids.\n";
    prompt += "6. Treat blocks as representative high-signal samples, not as the only reachable blocks in order.\n";
    prompt += "7. Use instruction_window_head, instruction_window_middle, and instruction_window_tail to infer prologue, body, and late-path behavior.\n";
    prompt += "8. Prefer concrete pseudocode statements over summary comments when a memory read, write, compare, or branch is explicitly visible in the facts.\n";
    prompt += "9. If control flow is incomplete, keep visible operations explicit and mark only the missing pieces as uncertain.\n";
    prompt += "10. If truncation flags are true, preserve that uncertainty instead of over-claiming.\n";
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
    URL_COMPONENTSW components = {};
    std::wstring endpoint = Utf8ToWide(config.Endpoint);
    std::wstring host(256, L'\0');
    std::wstring path(2048, L'\0');
    HINTERNET session = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET request = nullptr;

    do
    {
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

        WinHttpSetTimeouts(session, config.TimeoutMs, config.TimeoutMs, config.TimeoutMs, config.TimeoutMs);
        connection = WinHttpConnect(session, host.c_str(), components.nPort, 0);

        if (connection == nullptr)
        {
            error = DescribeWinHttpError("WinHttpConnect", GetLastError());
            break;
        }

        const DWORD flags = (components.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        request = WinHttpOpenRequest(connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

        if (request == nullptr)
        {
            error = DescribeWinHttpError("WinHttpOpenRequest", GetLastError());
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

        if (!WinHttpReceiveResponse(request, nullptr))
        {
            error = DescribeWinHttpError("WinHttpReceiveResponse", GetLastError());
            break;
        }

        std::string response;

        for (;;)
        {
            DWORD available = 0;

            if (!WinHttpQueryDataAvailable(request, &available))
            {
                error = DescribeWinHttpError("WinHttpQueryDataAvailable", GetLastError());
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
                break;
            }

            chunk.resize(read);
            response += chunk;
        }

        responseBody = response;

        DWORD statusCode = 0;

        if (!TryQueryStatusCode(request, statusCode))
        {
            error = DescribeWinHttpError("WinHttpQueryHeaders", GetLastError());
            break;
        }

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

    response.RawModelJson = SerializeAnalyzeResponse(response, true);
    return response;
}
}

bool LoadLlmClientConfig(
    LlmClientConfig& config,
    std::string& error)
{
    bool success = false;

    do
    {
        if (!TryLoadConfigFile(config, error))
        {
            break;
        }

        ApplyEnvironmentOverrides(config);

        if (!config.Endpoint.empty() && config.ApiKey.empty() && ContainsInsensitive(config.Endpoint, "api.openai.com"))
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
        return false;
    }

    const JsonParseResult parsed = ParseJson(responseBody);

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        error = parsed.Error.empty() ? "provider returned invalid JSON" : parsed.Error;
        return false;
    }

    const auto finishReason = ExtractFinishReason(parsed.Value);
    const auto content = ExtractChatContent(parsed.Value);

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
    const bool firstSuccess = SubmitChatJsonAttempt(config, systemPrompt, userPrompt, initialBudget, firstJson, firstError, firstTruncated);

    if (firstSuccess && !firstTruncated)
    {
        modelJson = firstJson;
        return true;
    }

    const uint32_t retryBudget = GrowCompletionTokenBudget(initialBudget, retryFloor);

    if (retryBudget > initialBudget)
    {
        std::string retryJson;
        std::string retryError;
        bool retryTruncated = false;

        if (SubmitChatJsonAttempt(config, systemPrompt, userPrompt, retryBudget, retryJson, retryError, retryTruncated))
        {
            modelJson = retryJson;
            return true;
        }

        if (firstSuccess && !firstJson.empty())
        {
            modelJson = firstJson;
            return true;
        }

        error = retryError;
        return false;
    }

    if (firstSuccess && !firstJson.empty())
    {
        modelJson = firstJson;
        return true;
    }

    error = firstError;
    return false;
}

bool AnalyzeWithSinglePassLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error)
{
    std::string modelJson;

    if (!SubmitChatJsonWithRetry(
            config,
            BuildSystemPrompt(),
            BuildUserPrompt(request),
            config.MaxCompletionTokens,
            (std::max)(static_cast<uint32_t>(4000), config.MaxCompletionTokens),
            modelJson,
            error))
    {
        return false;
    }

    std::string parseError;

    if (!ParseAnalyzeResponse(modelJson, response, parseError))
    {
        error = "failed to parse model JSON: " + parseError + "; preview: " + BuildPreviewText(modelJson);
        return false;
    }

    response.Provider = "openai-compatible-direct";
    response.RawModelJson = modelJson;
    response.Status = response.Status.empty() ? "ok" : response.Status;
    return true;
}

bool AnalyzeWithChunkedLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error)
{
    const std::vector<ChunkPlan> chunkPlans = BuildChunkPlans(request, config);

    if (chunkPlans.empty())
    {
        return AnalyzeWithSinglePassLlm(request, config, response, error);
    }

    std::vector<ChunkAnalysis> chunkAnalyses;
    chunkAnalyses.reserve(chunkPlans.size());

    for (const ChunkPlan& plan : chunkPlans)
    {
        std::string chunkJson;
        std::string chunkError;

        if (!SubmitChatJsonWithRetry(
                config,
                BuildChunkSystemPrompt(),
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
            return false;
        }

        if (chunkAnalysis.ChunkId.empty())
        {
            chunkAnalysis.ChunkId = plan.Id;
        }

        chunkAnalyses.push_back(std::move(chunkAnalysis));
        Sleep(150);
    }

    std::string mergeJson;

    if (!SubmitChatJsonWithRetry(
            config,
            BuildMergeSystemPrompt(),
            BuildMergeUserPrompt(request, chunkPlans, chunkAnalyses),
            config.MergeCompletionTokens,
            (std::max)(static_cast<uint32_t>(9000), config.MergeCompletionTokens),
            mergeJson,
            error))
    {
        error = "merge analysis failed: " + error;
        return false;
    }

    std::string parseError;

    if (!ParseAnalyzeResponse(mergeJson, response, parseError))
    {
        error = "failed to parse merge JSON: " + parseError + "; preview: " + BuildPreviewText(mergeJson);
        return false;
    }

    response.Provider = "openai-compatible-direct-chunked";
    response.RawModelJson = mergeJson;
    response.Status = response.Status.empty() ? "ok" : response.Status;
    return true;
}

bool AnalyzeWithLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error)
{
    if (config.Endpoint.empty())
    {
        response = BuildMockResponse(request);
        return true;
    }

    if (ShouldUseChunkedAnalysis(request, config))
    {
        std::string chunkedError;

        if (AnalyzeWithChunkedLlm(request, config, response, chunkedError))
        {
            return true;
        }

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

    return AnalyzeWithSinglePassLlm(request, config, response, error);
}
}








