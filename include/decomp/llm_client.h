#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "decomp/types.h"

namespace decomp
{
struct PseudoCodeHighlightConfig
{
    std::string KeywordColor = "warnfg";
    std::string TypeColor = "emphfg";
    std::string FunctionNameColor = "srcid";
    std::string IdentifierColor = "wfg";
    std::string NumberColor = "changed";
    std::string StringColor = "srcstr";
    std::string CharColor = "srcchar";
    std::string CommentColor = "subfg";
    std::string PreprocessorColor = "verbfg";
    std::string OperatorColor = "srcannot";
    std::string PunctuationColor = "srcpair";
};

struct DisplayLanguageConfig
{
    std::string Mode = "auto";
    std::string Tag = "en-US";
    std::string Name = "English";
};

struct LlmClientConfig
{
    std::string Provider = "openai-compatible";
    std::string Endpoint;
    std::string Model = "local-model";
    std::string ApiKey;
    std::string ChatGptAuthFile;
    std::string ReasoningEffort;
    uint32_t TimeoutMs = 120000;
    uint32_t MaxCompletionTokens = 12000;
    bool ForceChunked = false;
    uint32_t ChunkTriggerInstructions = 900;
    uint32_t ChunkTriggerBlocks = 36;
    uint32_t ChunkBlockLimit = 24;
    uint32_t ChunkCountLimit = 16;
    uint32_t ChunkCompletionTokens = 6000;
    uint32_t MergeCompletionTokens = 12000;
    std::function<void(const std::string&)> ProgressLog;
    std::function<void(const std::string&)> VerboseLog;
    std::function<bool()> ShouldCancel;
    DisplayLanguageConfig DisplayLanguage;
    PseudoCodeHighlightConfig Highlight;
};

struct LlmChunkPlanSummary
{
    bool UseChunked = false;
    size_t EstimatedChunks = 1;
    std::string Reason;
};

bool LoadLlmClientConfig(
    LlmClientConfig& config,
    std::string& error,
    bool validateProviderSettings = true);

std::string BuildDefaultLlmConfigPath();
std::string BuildDefaultChatGptAuthFilePathForConfig();
bool PathExistsAsFile(const std::string& path);
bool IsChatGptProviderConfig(const LlmClientConfig& config);
LlmChunkPlanSummary SummarizeLlmChunkPlan(
    const AnalyzeRequest& request,
    const LlmClientConfig& config);

bool AnalyzeWithLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error);

std::string BuildDebugPromptDump(const AnalyzeRequest& request);
std::string BuildDebugFirstChunkPromptDump(
    const AnalyzeRequest& request,
    const LlmClientConfig& config);
std::string BuildDebugMergePromptDump(
    const AnalyzeRequest& request,
    const LlmClientConfig& config);
std::string BuildDebugVerifierFeedbackPrompt(const VerifyReport& report);
bool DebugParseChunkAnalysisJson(
    const std::string& text,
    bool& repaired,
    size_t& uncertaintyCount,
    std::string& error);
void ApplyDebugMergeOutputPolicy(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response);
}
