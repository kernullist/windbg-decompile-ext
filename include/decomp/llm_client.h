#pragma once

#include <cstdint>
#include <string>

#include "decomp/types.h"

namespace decomp
{
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
};

bool LoadLlmClientConfig(
    LlmClientConfig& config,
    std::string& error);

bool AnalyzeWithLlm(
    const AnalyzeRequest& request,
    const LlmClientConfig& config,
    AnalyzeResponse& response,
    std::string& error);
}

