#pragma once

#include <cstdint>
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
    std::string Endpoint;
    std::string Model = "local-model";
    std::string ApiKey;
    uint32_t TimeoutMs = 5000;
    uint32_t MaxCompletionTokens = 4000;
    bool ForceChunked = false;
    uint32_t ChunkTriggerInstructions = 512;
    uint32_t ChunkTriggerBlocks = 24;
    uint32_t ChunkBlockLimit = 14;
    uint32_t ChunkCountLimit = 20;
    uint32_t ChunkCompletionTokens = 3500;
    uint32_t MergeCompletionTokens = 9000;
    DisplayLanguageConfig DisplayLanguage;
    PseudoCodeHighlightConfig Highlight;
};

bool LoadLlmClientConfig(
    LlmClientConfig& config,
    std::string& error,
    bool validateProviderSettings = true);

bool AnalyzeWithLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error);
}

