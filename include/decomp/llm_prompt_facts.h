#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "decomp/json.h"
#include "decomp/types.h"

namespace decomp
{
inline constexpr size_t kPromptRegionLimit = 8;
inline constexpr size_t kPromptBlockLimit = 48;
inline constexpr size_t kPromptBlockInstructionLimit = 8;
inline constexpr size_t kPromptBlockCompactLimit = 32;
inline constexpr size_t kPromptBlockInstructionCompactLimit = 4;
inline constexpr size_t kPromptBlockInstructionCompactTailLimit = 2;
inline constexpr size_t kPromptDirectCallLimit = 32;
inline constexpr size_t kPromptIndirectCallLimit = 24;
inline constexpr size_t kPromptFactLimit = 32;
inline constexpr size_t kPromptUncertaintyLimit = 12;
inline constexpr size_t kPromptSwitchLimit = 10;
inline constexpr size_t kPromptMemoryAccessLimit = 32;
inline constexpr size_t kPromptMemoryAccessCompactLimit = 18;
inline constexpr size_t kPromptInstructionWindowLimit = 20;
inline constexpr size_t kPromptRecoveredArgumentLimit = 8;
inline constexpr size_t kPromptRecoveredLocalLimit = 24;
inline constexpr size_t kPromptStackPointerLimit = 32;
inline constexpr size_t kPromptCallArgumentLimit = 32;
inline constexpr size_t kPromptHelperCallContractLimit = 24;
inline constexpr size_t kPromptValueMergeLimit = 16;
inline constexpr size_t kPromptIrValueLimit = 32;
inline constexpr size_t kPromptIrValueCompactLimit = 24;
inline constexpr size_t kPromptBlockValueStateLimit = 24;
inline constexpr size_t kPromptBlockValueEntryLimit = 12;
inline constexpr size_t kPromptBlockValueStateCompactLimit = 16;
inline constexpr size_t kPromptBlockValueEntryCompactLimit = 6;
inline constexpr size_t kPromptObfuscationStateVariableLimit = 8;
inline constexpr size_t kPromptObfuscationDispatcherLimit = 8;
inline constexpr size_t kPromptObfuscationEdgeLimit = 24;
inline constexpr size_t kPromptObfuscationPredicateLimit = 12;
inline constexpr size_t kPromptObfuscationSubstitutionLimit = 12;
inline constexpr size_t kPromptObfuscationNoteLimit = 8;
inline constexpr size_t kPromptSemanticControlFlowEdgeLimit = 32;
inline constexpr size_t kPromptSemanticControlFlowNoteLimit = 8;
inline constexpr size_t kPromptControlFlowLimit = 24;
inline constexpr size_t kPromptGraphSummaryControlFlowCompactLimit = 12;
inline constexpr size_t kPromptGraphSummaryConditionCompactLimit = 16;
inline constexpr size_t kPromptGraphSummarySemanticEdgeCompactLimit = 20;
inline constexpr size_t kPromptGraphSummaryImportantBlockCompactLimit = 20;
inline constexpr size_t kPromptTypeHintLimit = 32;
inline constexpr size_t kPromptTypeHintCompactLimit = 24;
inline constexpr size_t kPromptIdiomLimit = 24;
inline constexpr size_t kPromptCalleeSummaryLimit = 32;
inline constexpr size_t kPromptDataReferenceLimit = 24;
inline constexpr size_t kPromptCallTargetLimit = 24;
inline constexpr size_t kPromptNormalizedConditionLimit = 24;
inline constexpr size_t kPromptPdbParamLimit = 12;
inline constexpr size_t kPromptPdbLocalLimit = 24;
inline constexpr size_t kPromptPdbFieldHintLimit = 24;
inline constexpr size_t kPromptPdbEnumHintLimit = 16;
inline constexpr size_t kPromptPdbSourceLocationLimit = 16;
inline constexpr size_t kPromptPdbConflictLimit = 12;
inline constexpr size_t kPromptObservedArgumentLimit = 8;
inline constexpr size_t kPromptObservedHotspotLimit = 12;
inline constexpr size_t kPromptTtdQueryLimit = 8;
inline constexpr size_t kPromptEvidenceNodeCompactLimit = 40;
inline constexpr size_t kPromptEvidenceEdgeCompactLimit = 48;
inline constexpr size_t kPromptEvidenceNodeLimit = 64;
inline constexpr size_t kPromptEvidenceEdgeLimit = 96;
inline constexpr size_t kPromptEvidenceNoteLimit = 8;

std::string SanitizeIdentifier(const std::string& value);
std::vector<TypedNameConfidence> BuildAnalyzerSkeletonParams(const AnalyzeRequest& request);
std::string BuildAnalyzerSkeletonPseudoC(const AnalyzeRequest& request);
std::string BuildInstructionPreview(const DisassembledInstruction& instruction);

bool IsPromptBlockSelected(const std::set<std::string>* blockIds, const std::string& blockId);
bool IsPromptSiteSelected(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    uint64_t site);
bool IsPromptDispatcherSelected(
    const std::set<std::string>* blockIds,
    const ObfuscationDispatcher& dispatcher);
bool IsPromptOpaquePredicateSelected(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    const OpaquePredicateFact& predicate);
bool IsPromptSubstitutionIdiomSelected(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    const SubstitutionIdiomFact& idiom);
bool IsPromptSemanticEdgeSelected(
    const std::set<std::string>* blockIds,
    const SemanticControlFlowEdge& edge);
bool IsPromptControlFlowRegionSelected(
    const std::set<std::string>* blockIds,
    const ControlFlowRegion& region);

JsonValue BuildStringArray(
    const std::vector<std::string>& values,
    size_t limit,
    bool* truncated);

JsonValue BuildChunkGlobalFactsJson(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    size_t limit,
    bool* truncated);
JsonValue BuildChunkGlobalUncertaintiesJson(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    size_t limit,
    bool* truncated);

JsonValue BuildRegionsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildInstructionWindowJson(const AnalyzeRequest& request, bool tail);
JsonValue BuildInstructionWindowJson(const AnalyzeRequest& request, size_t centerIndex);
std::optional<size_t> FindMiddleInterestingInstructionIndex(const AnalyzeRequest& request);
JsonValue BuildBlocksJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildCallsJson(
    const std::vector<CallSite>& calls,
    size_t limit,
    bool* truncated);
JsonValue BuildSwitchesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildMemoryAccessesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildRecoveredArgumentsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildRecoveredLocalsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildStackPointerJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildStackPointerJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildCallArgumentsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildHelperCallContractJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildHelperCallContractJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildValueMergesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildIrValuesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildIrValuesJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
JsonValue BuildBlockValueStatesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildBlockValueStatesJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
JsonValue BuildObfuscationJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildObfuscationJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
JsonValue BuildDeobfuscationReadinessJson(const AnalyzeRequest& request);
JsonValue BuildSemanticControlFlowJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildSemanticControlFlowJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
JsonValue BuildControlFlowJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildControlFlowJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
JsonValue BuildAbiJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildTypeHintsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildIdiomsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildCalleeSummariesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildDataReferencesJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildCallTargetsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildNormalizedConditionsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildPdbFactsJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildPdbFactsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildSessionPolicyJson(const AnalyzeRequest& request);
JsonValue BuildObservedBehaviorJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildEvidenceGraphJson(const AnalyzeRequest& request, bool* truncated);
JsonValue BuildEvidenceGraphJsonForScope(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildCountsJson(const AnalyzeRequest& request);
JsonValue BuildGraphSummaryJson(const AnalyzeRequest& request);
JsonValue BuildGraphSummaryJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds);
JsonValue BuildPromptFactsJson(const AnalyzeRequest& request);

JsonValue BuildBlocksJsonForIndices(
    const AnalyzeRequest& request,
    const std::vector<size_t>& indices);
JsonValue BuildCallsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::vector<CallSite>& calls,
    const std::set<uint64_t>& instructionAddresses,
    size_t limit,
    bool* truncated);
JsonValue BuildSwitchesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildMemoryAccessesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildDataReferencesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildTypeHintsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildIdiomsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildCalleeSummariesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildCallTargetsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildCallArgumentsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated);
JsonValue BuildNormalizedConditionsJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
JsonValue BuildValueMergesJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated);
}
