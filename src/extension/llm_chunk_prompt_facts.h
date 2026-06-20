#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "decomp/json.h"
#include "decomp/types.h"

namespace decomp
{
inline constexpr size_t kChunkOverlapBlocks = 2;
inline constexpr size_t kChunkPromptFactLimit = 16;
inline constexpr size_t kChunkPromptUncertaintyLimit = 8;
inline constexpr size_t kMergeChunkUncoveredBlockIdLimit = 32;
inline constexpr size_t kMergeChunkEvidenceBlockIdLimit = 32;
inline constexpr size_t kMergeChunkRiskDetailLimit = 24;
inline constexpr size_t kMergeChunkRiskEvidenceBlockIdLimit = 8;
inline constexpr size_t kMergeChunkReviewPlanChunkLimit = 16;
inline constexpr double kMergeChunkLowConfidenceThreshold = 0.55;

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

struct MergeConfidencePolicy
{
    double RecommendedConfidenceCeiling = 0.90;
    std::vector<std::string> CeilingReasons;
};

struct MergeAcceptancePolicy
{
    std::vector<std::string> AcceptanceChecks;
    std::vector<std::string> BlockingIssues;
    bool RequiresCoverageStatement = false;
    bool RequiresEvidenceRewrite = false;
};

struct MergeOutputPostPolicy
{
    bool Active = false;
    MergeConfidencePolicy Confidence;
    MergeAcceptancePolicy Acceptance;
};

JsonValue BuildChunkFactsJson(
    const AnalyzeRequest& request,
    const ChunkPlan& plan);

JsonValue BuildMergeFactsJson(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses);

MergeOutputPostPolicy BuildMergeOutputPostPolicy(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses);

void ApplyMergeOutputPostPolicy(
    const MergeOutputPostPolicy& policy,
    AnalyzeResponse& response);
}
