#include "llm_chunk_prompt_facts.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "decomp/llm_prompt_facts.h"
#include "decomp/string_utils.h"

namespace decomp
{
std::set<size_t> BuildMergeCoveredBlockIndexSet(const std::vector<ChunkPlan>& chunkPlans)
{
    std::set<size_t> coveredBlocks;

    for (const ChunkPlan& plan : chunkPlans)
    {
        for (const size_t blockIndex : plan.BlockIndices)
        {
            coveredBlocks.insert(blockIndex);
        }
    }

    return coveredBlocks;
}

size_t CountValidMergeCoveredBlocks(
    const std::set<size_t>& coveredBlocks,
    size_t totalBlockCount)
{
    size_t count = 0;

    for (const size_t blockIndex : coveredBlocks)
    {
        if (blockIndex < totalBlockCount)
        {
            ++count;
        }
    }

    return count;
}

size_t CountMergeUncoveredBlocks(
    const AnalyzeRequest& request,
    const std::set<size_t>& coveredBlocks)
{
    const size_t totalBlockCount = request.Facts.Blocks.size();
    const size_t coveredBlockCount = CountValidMergeCoveredBlocks(coveredBlocks, totalBlockCount);
    return totalBlockCount - coveredBlockCount;
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

std::string BuildChunkAnalyzerSkeletonPseudoC(
    const AnalyzeRequest& request,
    const ChunkPlan& plan,
    const std::set<std::string>& blockIds,
    const std::set<uint64_t>& instructionAddresses)
{
    const std::vector<TypedNameConfidence> params = BuildAnalyzerSkeletonParams(request);
    const std::string functionName = !request.Facts.Pdb.FunctionName.empty()
        ? SanitizeIdentifier(request.Facts.Pdb.FunctionName)
        : SanitizeIdentifier(request.Facts.QueryText);
    const std::string returnType = !request.Facts.Pdb.ReturnType.empty() ? request.Facts.Pdb.ReturnType : "UNKNOWN_TYPE";
    const std::set<std::string>* selectedBlocks = &blockIds;
    std::string text;

    text += returnType + " " + functionName + "_chunk(";

    for (size_t index = 0; index < params.size(); ++index)
    {
        if (index != 0)
        {
            text += ", ";
        }

        text += params[index].Type + " " + params[index].Name;
    }

    text += ")\n{\n";
    text += "    /* chunk analyzer skeleton: refine this chunk, preserve unresolved cross-chunk state */\n";
    text += "    /* chunk_id=" + plan.Id
        + ", slot=" + std::to_string(plan.SlotIndex + 1U)
        + "/" + std::to_string(plan.TotalChunks)
        + ", blocks=" + std::to_string(plan.BlockIndices.size())
        + ", instructions=" + std::to_string(instructionAddresses.size())
        + " */\n";

    size_t emitted = 0;

    for (const ObfuscationDispatcher& dispatcher : request.Facts.Obfuscation.Dispatchers)
    {
        if (emitted >= 3)
        {
            break;
        }

        if (dispatcher.Confidence < 0.75 || !IsPromptDispatcherSelected(selectedBlocks, dispatcher))
        {
            continue;
        }

        text += "    /* control-flow flattening dispatcher recovered: "
            + dispatcher.HeaderBlock
            + " state "
            + dispatcher.StateVariable
            + " */\n";
        ++emitted;
    }

    emitted = 0;

    for (const SemanticControlFlowEdge& edge : request.Facts.SemanticControlFlow.Edges)
    {
        if (emitted >= 8)
        {
            break;
        }

        if (edge.Confidence < 0.75 || !IsPromptSemanticEdgeSelected(selectedBlocks, edge))
        {
            continue;
        }

        if (edge.Dead)
        {
            text += "    /* semantic dead edge pruned: "
                + edge.SourceBlock
                + " -> "
                + edge.TargetBlock
                + " */\n";
        }
        else
        {
            text += "    /* semantic edge: "
                + edge.SourceBlock
                + " -> "
                + edge.TargetBlock;

            if (!edge.StateValue.empty())
            {
                text += " when state=" + edge.StateValue;
            }
            else if (!edge.Condition.empty())
            {
                text += " when " + edge.Condition;
            }

            text += " */\n";
        }

        ++emitted;
    }

    emitted = 0;

    for (const OpaquePredicateFact& predicate : request.Facts.Obfuscation.OpaquePredicates)
    {
        if (emitted >= 4)
        {
            break;
        }

        if (predicate.Confidence < 0.75 || !IsPromptOpaquePredicateSelected(request, selectedBlocks, predicate))
        {
            continue;
        }

        text += "    /* opaque predicate: block="
            + predicate.BlockId
            + " result="
            + predicate.ConstantResult;

        if (!predicate.LiveTargetBlock.empty() || !predicate.DeadTargetBlock.empty())
        {
            text += " live="
                + predicate.LiveTargetBlock
                + " dead="
                + predicate.DeadTargetBlock;
        }
        else
        {
            text += " constant_return=true";
        }

        text += " */\n";
        ++emitted;
    }

    emitted = 0;

    for (const SubstitutionIdiomFact& idiom : request.Facts.Obfuscation.SubstitutionIdioms)
    {
        if (emitted >= 4)
        {
            break;
        }

        if (idiom.Confidence < 0.75 || !IsPromptSubstitutionIdiomSelected(request, selectedBlocks, idiom))
        {
            continue;
        }

        text += "    /* substitution: " + idiom.OriginalExpression + " => " + idiom.SimplifiedExpression + " */\n";
        ++emitted;
    }

    emitted = 0;

    for (const ControlFlowRegion& region : request.Facts.ControlFlow)
    {
        if (emitted >= 6)
        {
            break;
        }

        if (!IsPromptControlFlowRegionSelected(selectedBlocks, region))
        {
            continue;
        }

        text += "    /* region " + region.Kind + " header=" + region.HeaderBlock;

        if (!region.Condition.empty())
        {
            text += " condition=" + region.Condition;
        }

        text += " */\n";
        ++emitted;
    }

    emitted = 0;

    for (const NormalizedCondition& condition : request.Facts.NormalizedConditions)
    {
        if (emitted >= 6)
        {
            break;
        }

        if (!IsPromptBlockSelected(selectedBlocks, condition.BlockId)
            && !IsPromptBlockSelected(selectedBlocks, condition.TrueTargetBlock)
            && !IsPromptBlockSelected(selectedBlocks, condition.FalseTargetBlock))
        {
            continue;
        }

        text += "    /* if (" + condition.Expression + ") goto " + condition.TrueTargetBlock
            + " else " + condition.FalseTargetBlock + " */\n";
        ++emitted;
    }

    emitted = 0;

    for (const IdiomPattern& idiom : request.Facts.Idioms)
    {
        if (emitted >= 4)
        {
            break;
        }

        if (!IsPromptSiteSelected(request, selectedBlocks, idiom.Site))
        {
            continue;
        }

        text += "    /* idiom " + idiom.Name + ": " + idiom.Replacement + " */\n";
        ++emitted;
    }

    emitted = 0;

    for (const CalleeSummary& summary : request.Facts.CalleeSummaries)
    {
        if (emitted >= 4)
        {
            break;
        }

        if (!IsPromptSiteSelected(request, selectedBlocks, summary.Site))
        {
            continue;
        }

        text += "    /* call " + summary.Callee + ": returns " + summary.ReturnType
            + ", effects=" + summary.SideEffects + " */\n";
        ++emitted;
    }

    text += "    return CHUNK_UNKNOWN_VALUE;\n";
    text += "}\n";
    return text;
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
std::set<std::string> BuildBlockIdSetForPlan(const AnalyzeRequest& request, const ChunkPlan& plan)
{
    std::set<std::string> blockIds;

    for (const size_t blockIndex : plan.BlockIndices)
    {
        if (blockIndex < request.Facts.Blocks.size())
        {
            blockIds.insert(request.Facts.Blocks[blockIndex].Id);
        }
    }

    return blockIds;
}

std::unordered_map<std::string, std::vector<std::string>> BuildPromptBlockPredecessors(const std::vector<BasicBlock>& blocks)
{
    std::unordered_map<std::string, std::vector<std::string>> predecessors;

    for (const BasicBlock& block : blocks)
    {
        for (const std::string& successor : block.Successors)
        {
            predecessors[successor].push_back(block.Id);
        }
    }

    return predecessors;
}

JsonValue BuildBoundaryValueItem(const IrValue& value)
{
    JsonValue item = JsonValue::MakeObject();
    item.Set("id", JsonValue::MakeString(value.Id));
    item.Set("block_id", JsonValue::MakeString(value.BlockId));
    item.Set("site", JsonValue::MakeString(HexU64(value.DefSite)));
    item.Set("target", JsonValue::MakeString(value.Target));
    item.Set("expression", JsonValue::MakeString(value.Expression));
    item.Set("kind", JsonValue::MakeString(value.Kind));
    item.Set("confidence", JsonValue::MakeNumber(value.Confidence));
    return item;
}

JsonValue BuildChunkBoundaryJson(const AnalyzeRequest& request, const ChunkPlan& plan)
{
    JsonValue boundary = JsonValue::MakeObject();
    JsonValue incomingEdges = JsonValue::MakeArray();
    JsonValue outgoingEdges = JsonValue::MakeArray();
    JsonValue liveInValues = JsonValue::MakeArray();
    JsonValue liveOutValues = JsonValue::MakeArray();
    JsonValue incomingConditions = JsonValue::MakeArray();
    JsonValue outgoingConditions = JsonValue::MakeArray();
    const std::set<std::string> chunkBlockIds = BuildBlockIdSetForPlan(request, plan);
    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildPromptBlockPredecessors(request.Facts.Blocks);
    std::unordered_map<std::string, const IrValue*> valueById;
    std::set<std::string> emittedLiveIn;
    std::set<std::string> emittedLiveOut;

    for (const IrValue& value : request.Facts.IrValues)
    {
        valueById[value.Id] = &value;
    }

    for (const BasicBlock& block : request.Facts.Blocks)
    {
        const bool blockInChunk = chunkBlockIds.find(block.Id) != chunkBlockIds.end();

        if (blockInChunk)
        {
            const auto predecessorIt = predecessors.find(block.Id);

            if (predecessorIt != predecessors.end())
            {
                for (const std::string& predecessor : predecessorIt->second)
                {
                    if (chunkBlockIds.find(predecessor) == chunkBlockIds.end())
                    {
                        JsonValue edge = JsonValue::MakeObject();
                        edge.Set("from", JsonValue::MakeString(predecessor));
                        edge.Set("to", JsonValue::MakeString(block.Id));
                        incomingEdges.PushBack(edge);
                    }
                }
            }

            for (const std::string& successor : block.Successors)
            {
                if (chunkBlockIds.find(successor) == chunkBlockIds.end())
                {
                    JsonValue edge = JsonValue::MakeObject();
                    edge.Set("from", JsonValue::MakeString(block.Id));
                    edge.Set("to", JsonValue::MakeString(successor));
                    outgoingEdges.PushBack(edge);
                }
            }
        }
    }

    for (const IrValue& value : request.Facts.IrValues)
    {
        const bool valueInChunk = chunkBlockIds.find(value.BlockId) != chunkBlockIds.end();

        for (const std::string& useId : value.Uses)
        {
            const auto usedIt = valueById.find(useId);

            if (usedIt == valueById.end() || usedIt->second == nullptr)
            {
                continue;
            }

            const IrValue& used = *usedIt->second;
            const bool usedInChunk = chunkBlockIds.find(used.BlockId) != chunkBlockIds.end();

            if (valueInChunk && !usedInChunk && emittedLiveIn.insert(used.Id).second && liveInValues.GetArray().size() < 24)
            {
                liveInValues.PushBack(BuildBoundaryValueItem(used));
            }

            if (!valueInChunk && usedInChunk && emittedLiveOut.insert(used.Id).second && liveOutValues.GetArray().size() < 24)
            {
                liveOutValues.PushBack(BuildBoundaryValueItem(used));
            }
        }
    }

    for (const NormalizedCondition& condition : request.Facts.NormalizedConditions)
    {
        const bool conditionInChunk = chunkBlockIds.find(condition.BlockId) != chunkBlockIds.end();
        const bool trueInChunk = chunkBlockIds.find(condition.TrueTargetBlock) != chunkBlockIds.end();
        const bool falseInChunk = chunkBlockIds.find(condition.FalseTargetBlock) != chunkBlockIds.end();

        if (!conditionInChunk && (trueInChunk || falseInChunk) && incomingConditions.GetArray().size() < 16)
        {
            JsonValue item = JsonValue::MakeObject();
            item.Set("block_id", JsonValue::MakeString(condition.BlockId));
            item.Set("expression", JsonValue::MakeString(condition.Expression));
            item.Set("true_target", JsonValue::MakeString(condition.TrueTargetBlock));
            item.Set("false_target", JsonValue::MakeString(condition.FalseTargetBlock));
            incomingConditions.PushBack(item);
        }

        if (conditionInChunk && (!trueInChunk || !falseInChunk) && outgoingConditions.GetArray().size() < 16)
        {
            JsonValue item = JsonValue::MakeObject();
            item.Set("block_id", JsonValue::MakeString(condition.BlockId));
            item.Set("expression", JsonValue::MakeString(condition.Expression));
            item.Set("true_target", JsonValue::MakeString(condition.TrueTargetBlock));
            item.Set("false_target", JsonValue::MakeString(condition.FalseTargetBlock));
            outgoingConditions.PushBack(item);
        }
    }

    boundary.Set("incoming_edges", incomingEdges);
    boundary.Set("outgoing_edges", outgoingEdges);
    boundary.Set("live_in_values", liveInValues);
    boundary.Set("live_out_values", liveOutValues);
    boundary.Set("incoming_conditions", incomingConditions);
    boundary.Set("outgoing_conditions", outgoingConditions);
    boundary.Set("note", JsonValue::MakeString("Use live_in/live_out and crossing edges to preserve state across adjacent chunks without inventing omitted blocks."));
    return boundary;
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
    JsonValue selection = JsonValue::MakeObject();
    std::set<uint64_t> instructionAddresses;
    std::set<std::string> blockIds;
    uint64_t startAddress = 0;
    uint64_t endAddress = 0;
    bool directCallsTruncated = false;
    bool indirectCallsTruncated = false;
    bool switchesTruncated = false;
    bool stackPointerTruncated = false;
    bool memoryAccessesTruncated = false;
    bool recoveredArgumentsTruncated = false;
    bool recoveredLocalsTruncated = false;
    bool callArgumentsTruncated = false;
    bool helperCallContractTruncated = false;
    bool valueMergesTruncated = false;
    bool irValuesTruncated = false;
    bool blockValueStatesTruncated = false;
    bool obfuscationTruncated = false;
    bool semanticControlFlowTruncated = false;
    bool controlFlowTruncated = false;
    bool abiTruncated = false;
    bool dataReferencesTruncated = false;
    bool callTargetsTruncated = false;
    bool typeHintsTruncated = false;
    bool idiomsTruncated = false;
    bool calleeSummariesTruncated = false;
    bool normalizedConditionsTruncated = false;
    bool pdbTruncated = false;
    bool evidenceGraphTruncated = false;
    bool observedBehaviorTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;

    CollectChunkAddressMetadata(request, plan, instructionAddresses, blockIds, startAddress, endAddress);
    const std::vector<const DisassembledInstruction*> chunkInstructions = CollectInstructionsForBlocks(request, plan.BlockIndices);
    const std::optional<size_t> middleInstructionIndex = FindMiddleInterestingInstructionIndex(chunkInstructions);
    const std::optional<size_t> globalMiddleInstructionIndex = FindMiddleInterestingInstructionIndex(request);

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("loaded_image_name", JsonValue::MakeString(request.Facts.Module.LoadedImageName));
    module.Set("base", JsonValue::MakeString(HexU64(request.Facts.Module.Base)));
    module.Set("size", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.Size)));
    module.Set("symbol_type", JsonValue::MakeNumber(static_cast<double>(request.Facts.Module.SymbolType)));

    naturalLanguage.Set("tag", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageTag));
    naturalLanguage.Set("name", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageName));

    stackFrame.Set("stack_alloc", JsonValue::MakeNumber(static_cast<double>(request.Facts.StackFrame.StackAlloc)));
    stackFrame.Set("saved_nonvolatile", BuildStringArray(request.Facts.StackFrame.SavedNonvolatile, 8, nullptr));
    stackFrame.Set("uses_cookie", JsonValue::MakeBoolean(request.Facts.StackFrame.UsesCookie));
    stackFrame.Set("frame_pointer", JsonValue::MakeBoolean(request.Facts.StackFrame.FramePointer));

    selection.Set("chunk_strategy", JsonValue::MakeString("chunk-local high-signal blocks + boundary context + spread sampling"));
    selection.Set("fact_strategy", JsonValue::MakeString("chunk-scoped facts + global fact carryover + spread sampling"));
    selection.Set("instruction_window_limit", JsonValue::MakeNumber(static_cast<double>(kPromptInstructionWindowLimit)));
    selection.Set("chunk_overlap_blocks", JsonValue::MakeNumber(static_cast<double>(kChunkOverlapBlocks)));
    selection.Set("global_fact_limit", JsonValue::MakeNumber(static_cast<double>(kChunkPromptFactLimit)));
    selection.Set("global_uncertainty_limit", JsonValue::MakeNumber(static_cast<double>(kChunkPromptUncertaintyLimit)));
    selection.Set("chunk_block_count", JsonValue::MakeNumber(static_cast<double>(plan.BlockIndices.size())));
    selection.Set("total_chunks", JsonValue::MakeNumber(static_cast<double>(plan.TotalChunks)));
    selection.Set("helper_call_contract_required", JsonValue::MakeBoolean(true));

    functionOverview.Set("query_text", JsonValue::MakeString(request.Facts.QueryText));
    functionOverview.Set("query_address", JsonValue::MakeString(HexU64(request.Facts.QueryAddress)));
    functionOverview.Set("entry_address", JsonValue::MakeString(HexU64(request.Facts.EntryAddress)));
    functionOverview.Set("rva", JsonValue::MakeString(HexU64(request.Facts.Rva)));
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

    root.Set("arch", JsonValue::MakeString(request.Facts.Arch));
    root.Set("mode", JsonValue::MakeString(request.Facts.Mode == AnalysisMode::LiveMemory ? "live" : "file"));
    root.Set("selection", selection);
    root.Set("function_overview", functionOverview);
    root.Set("chunk", chunk);
    root.Set("analyzer_skeleton", JsonValue::MakeString(BuildChunkAnalyzerSkeletonPseudoC(request, plan, blockIds, instructionAddresses)));
    root.Set("graph_summary", BuildGraphSummaryJsonForBlocks(request, blockIds));
    root.Set("global_instruction_window_head", BuildInstructionWindowJson(request, false));
    root.Set("global_instruction_window_middle", globalMiddleInstructionIndex.has_value() ? BuildInstructionWindowJson(request, globalMiddleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("global_instruction_window_tail", BuildInstructionWindowJson(request, true));
    root.Set("chunk_instruction_window_head", BuildInstructionWindowFromPointers(chunkInstructions, false));
    root.Set("chunk_instruction_window_middle", middleInstructionIndex.has_value() ? BuildInstructionWindowFromPointers(chunkInstructions, middleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("chunk_instruction_window_tail", BuildInstructionWindowFromPointers(chunkInstructions, true));
    root.Set("blocks", BuildBlocksJsonForIndices(request, plan.BlockIndices));
    root.Set("chunk_boundary", BuildChunkBoundaryJson(request, plan));
    root.Set("direct_calls", BuildCallsJsonForAddresses(request, request.Facts.Calls, instructionAddresses, 24, &directCallsTruncated));
    root.Set("indirect_calls", BuildCallsJsonForAddresses(request, request.Facts.IndirectCalls, instructionAddresses, 24, &indirectCallsTruncated));
    root.Set("switches", BuildSwitchesJsonForAddresses(request, instructionAddresses, &switchesTruncated));
    root.Set("stack_pointer", BuildStackPointerJsonForAddresses(request, instructionAddresses, &stackPointerTruncated));
    root.Set("memory_accesses", BuildMemoryAccessesJsonForAddresses(request, instructionAddresses, &memoryAccessesTruncated));
    root.Set("recovered_arguments", BuildRecoveredArgumentsJson(request, &recoveredArgumentsTruncated));
    root.Set("recovered_locals", BuildRecoveredLocalsJson(request, &recoveredLocalsTruncated));
    root.Set("call_arguments", BuildCallArgumentsJsonForAddresses(request, instructionAddresses, &callArgumentsTruncated));
    root.Set("helper_call_contract", BuildHelperCallContractJsonForAddresses(request, instructionAddresses, &helperCallContractTruncated));
    root.Set("value_merges", BuildValueMergesJsonForBlocks(request, blockIds, &valueMergesTruncated));
    root.Set("ir_values", BuildIrValuesJsonForBlocks(request, blockIds, &irValuesTruncated));
    root.Set("block_value_states", BuildBlockValueStatesJsonForBlocks(request, blockIds, &blockValueStatesTruncated));
    root.Set("obfuscation", BuildObfuscationJsonForBlocks(request, blockIds, &obfuscationTruncated));
    root.Set("deobfuscation_readiness", BuildDeobfuscationReadinessJson(request));
    root.Set("semantic_control_flow", BuildSemanticControlFlowJsonForBlocks(request, blockIds, &semanticControlFlowTruncated));
    root.Set("control_flow", BuildControlFlowJsonForBlocks(request, blockIds, &controlFlowTruncated));
    root.Set("abi", BuildAbiJson(request, &abiTruncated));
    root.Set("session_policy", BuildSessionPolicyJson(request));
    root.Set("data_references", BuildDataReferencesJsonForAddresses(request, instructionAddresses, &dataReferencesTruncated));
    root.Set("call_targets", BuildCallTargetsJsonForAddresses(request, instructionAddresses, &callTargetsTruncated));
    root.Set("type_hints", BuildTypeHintsJsonForAddresses(request, instructionAddresses, &typeHintsTruncated));
    root.Set("idioms", BuildIdiomsJsonForAddresses(request, instructionAddresses, &idiomsTruncated));
    root.Set("callee_summaries", BuildCalleeSummariesJsonForAddresses(request, instructionAddresses, &calleeSummariesTruncated));
    root.Set("normalized_conditions", BuildNormalizedConditionsJsonForBlocks(request, blockIds, &normalizedConditionsTruncated));
    root.Set("pdb", BuildPdbFactsJsonForAddresses(request, instructionAddresses, &pdbTruncated));
    root.Set("evidence_graph", BuildEvidenceGraphJsonForScope(request, blockIds, instructionAddresses, &evidenceGraphTruncated));
    root.Set("observed_behavior", BuildObservedBehaviorJson(request, &observedBehaviorTruncated));
    root.Set("global_facts", BuildChunkGlobalFactsJson(request, blockIds, kChunkPromptFactLimit, &factsTruncated));
    root.Set("global_uncertainties", BuildChunkGlobalUncertaintiesJson(request, blockIds, kChunkPromptUncertaintyLimit, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));

    truncation.Set("direct_calls", JsonValue::MakeBoolean(directCallsTruncated));
    truncation.Set("indirect_calls", JsonValue::MakeBoolean(indirectCallsTruncated));
    truncation.Set("switches", JsonValue::MakeBoolean(switchesTruncated));
    truncation.Set("stack_pointer", JsonValue::MakeBoolean(stackPointerTruncated));
    truncation.Set("memory_accesses", JsonValue::MakeBoolean(memoryAccessesTruncated));
    truncation.Set("recovered_arguments", JsonValue::MakeBoolean(recoveredArgumentsTruncated));
    truncation.Set("recovered_locals", JsonValue::MakeBoolean(recoveredLocalsTruncated));
    truncation.Set("call_arguments", JsonValue::MakeBoolean(callArgumentsTruncated));
    truncation.Set("helper_call_contract", JsonValue::MakeBoolean(helperCallContractTruncated));
    truncation.Set("value_merges", JsonValue::MakeBoolean(valueMergesTruncated));
    truncation.Set("ir_values", JsonValue::MakeBoolean(irValuesTruncated));
    truncation.Set("block_value_states", JsonValue::MakeBoolean(blockValueStatesTruncated));
    truncation.Set("obfuscation", JsonValue::MakeBoolean(obfuscationTruncated));
    truncation.Set("semantic_control_flow", JsonValue::MakeBoolean(semanticControlFlowTruncated));
    truncation.Set("control_flow", JsonValue::MakeBoolean(controlFlowTruncated));
    truncation.Set("abi", JsonValue::MakeBoolean(abiTruncated));
    truncation.Set("data_references", JsonValue::MakeBoolean(dataReferencesTruncated));
    truncation.Set("call_targets", JsonValue::MakeBoolean(callTargetsTruncated));
    truncation.Set("type_hints", JsonValue::MakeBoolean(typeHintsTruncated));
    truncation.Set("idioms", JsonValue::MakeBoolean(idiomsTruncated));
    truncation.Set("callee_summaries", JsonValue::MakeBoolean(calleeSummariesTruncated));
    truncation.Set("normalized_conditions", JsonValue::MakeBoolean(normalizedConditionsTruncated));
    truncation.Set("pdb", JsonValue::MakeBoolean(pdbTruncated));
    truncation.Set("evidence_graph", JsonValue::MakeBoolean(evidenceGraphTruncated));
    truncation.Set("observed_behavior", JsonValue::MakeBoolean(observedBehaviorTruncated));
    truncation.Set("facts", JsonValue::MakeBoolean(factsTruncated));
    truncation.Set("uncertainties", JsonValue::MakeBoolean(uncertaintiesTruncated));
    root.Set("truncation", truncation);

    return root;
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

JsonValue BuildMergeChunkPlansJson(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans)
{
    JsonValue array = JsonValue::MakeArray();

    for (const ChunkPlan& plan : chunkPlans)
    {
        JsonValue item = JsonValue::MakeObject();
        JsonValue blockIds = JsonValue::MakeArray();
        std::set<uint64_t> instructionAddresses;
        std::set<std::string> selectedBlockIds;
        uint64_t startAddress = 0;
        uint64_t endAddress = 0;

        CollectChunkAddressMetadata(request, plan, instructionAddresses, selectedBlockIds, startAddress, endAddress);

        for (const std::string& blockId : selectedBlockIds)
        {
            blockIds.PushBack(JsonValue::MakeString(blockId));
        }

        item.Set("chunk_id", JsonValue::MakeString(plan.Id));
        item.Set("slot_index", JsonValue::MakeNumber(static_cast<double>(plan.SlotIndex)));
        item.Set("total_chunks", JsonValue::MakeNumber(static_cast<double>(plan.TotalChunks)));
        item.Set("block_count", JsonValue::MakeNumber(static_cast<double>(plan.BlockIndices.size())));
        item.Set("start", JsonValue::MakeString(HexU64(startAddress)));
        item.Set("end", JsonValue::MakeString(HexU64(endAddress)));
        item.Set("block_ids", blockIds);

        if (!plan.BlockIndices.empty())
        {
            item.Set("first_block", JsonValue::MakeString(request.Facts.Blocks[plan.BlockIndices.front()].Id));
            item.Set("last_block", JsonValue::MakeString(request.Facts.Blocks[plan.BlockIndices.back()].Id));
        }

        array.PushBack(item);
    }

    return array;
}

JsonValue BuildMergeUncoveredBlockIdsJson(
    const AnalyzeRequest& request,
    const std::set<size_t>& coveredBlocks,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    size_t uncoveredCount = 0;

    for (size_t index = 0; index < request.Facts.Blocks.size(); ++index)
    {
        if (coveredBlocks.find(index) != coveredBlocks.end())
        {
            continue;
        }

        ++uncoveredCount;

        if (array.GetArray().size() < kMergeChunkUncoveredBlockIdLimit)
        {
            array.PushBack(JsonValue::MakeString(request.Facts.Blocks[index].Id));
        }
    }

    if (truncated != nullptr)
    {
        *truncated = uncoveredCount > kMergeChunkUncoveredBlockIdLimit;
    }

    return array;
}

struct MergeChunkAnalysisDiagnostic
{
    const ChunkAnalysis* Analysis = nullptr;
    std::string ChunkId;
    bool Planned = false;
    bool HasBlockEvidence = false;
    bool HasUngroundedEvidence = false;
    bool LowConfidence = false;
    bool HasUncertainties = false;
    bool EmptyEvidence = false;
};

struct MergeChunkDiagnostics
{
    size_t ChunkPlanCount = 0;
    size_t ChunkSummaryCount = 0;
    size_t UncoveredBlockCount = 0;
    size_t PlannedBlockCount = 0;
    size_t EvidenceBlockCount = 0;
    size_t GroundedEvidenceBlockCount = 0;
    size_t MissingSummaryCount = 0;
    size_t OrphanSummaryCount = 0;
    size_t DuplicateSummaryCount = 0;
    size_t LowConfidenceSummaryCount = 0;
    size_t UncertainSummaryCount = 0;
    size_t EmptyEvidenceSummaryCount = 0;
    size_t MissingBlockEvidenceSummaryCount = 0;
    size_t WeakEvidenceSummaryCount = 0;
    size_t UngroundedEvidenceSummaryCount = 0;
    double ConfidenceSum = 0.0;
    double MinConfidence = 0.0;
    double MaxConfidence = 0.0;
    bool HasConfidence = false;
    bool EvidenceBlocksOutsideChunkPlansTruncated = false;
    std::set<std::string> PlanIds;
    std::set<std::string> PlannedBlockIds;
    std::unordered_map<std::string, size_t> SummaryCountsByChunkId;
    std::vector<MergeChunkAnalysisDiagnostic> AnalysisDiagnostics;
    std::vector<std::string> MissingSummaryChunkIds;
    std::vector<std::string> OrphanSummaryChunkIds;
    std::vector<std::string> DuplicateSummaryChunkIds;
    std::vector<std::string> LowConfidenceChunkIds;
    std::vector<std::string> UncertaintyChunkIds;
    std::vector<std::string> EmptyEvidenceChunkIds;
    std::vector<std::string> ChunksWithoutBlockEvidence;
    std::vector<std::string> EvidenceBlocksOutsideChunkPlans;
    std::vector<std::string> RiskCodes;
};

MergeChunkDiagnostics BuildMergeChunkDiagnostics(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses,
    size_t uncoveredBlockCount)
{
    MergeChunkDiagnostics diagnostics;
    std::set<std::string> summaryIds;
    std::set<std::string> duplicateSummaryIds;
    std::set<std::string> evidenceBlockIds;
    std::set<std::string> outsideEvidenceBlockIds;

    diagnostics.ChunkPlanCount = chunkPlans.size();
    diagnostics.ChunkSummaryCount = chunkAnalyses.size();
    diagnostics.UncoveredBlockCount = uncoveredBlockCount;

    for (const ChunkPlan& plan : chunkPlans)
    {
        diagnostics.PlanIds.insert(plan.Id);

        for (const size_t blockIndex : plan.BlockIndices)
        {
            if (blockIndex < request.Facts.Blocks.size())
            {
                diagnostics.PlannedBlockIds.insert(request.Facts.Blocks[blockIndex].Id);
            }
        }
    }

    for (const ChunkAnalysis& analysis : chunkAnalyses)
    {
        MergeChunkAnalysisDiagnostic analysisDiagnostic;
        analysisDiagnostic.Analysis = &analysis;
        analysisDiagnostic.ChunkId = analysis.ChunkId;
        analysisDiagnostic.Planned = diagnostics.PlanIds.find(analysis.ChunkId) != diagnostics.PlanIds.end();
        analysisDiagnostic.LowConfidence = analysis.Confidence < kMergeChunkLowConfidenceThreshold;
        analysisDiagnostic.HasUncertainties = !analysis.Uncertainties.empty();
        analysisDiagnostic.EmptyEvidence = analysis.Evidence.empty();

        ++diagnostics.SummaryCountsByChunkId[analysis.ChunkId];
        diagnostics.ConfidenceSum += analysis.Confidence;

        if (!diagnostics.HasConfidence)
        {
            diagnostics.MinConfidence = analysis.Confidence;
            diagnostics.MaxConfidence = analysis.Confidence;
            diagnostics.HasConfidence = true;
        }
        else
        {
            diagnostics.MinConfidence = (std::min)(diagnostics.MinConfidence, analysis.Confidence);
            diagnostics.MaxConfidence = (std::max)(diagnostics.MaxConfidence, analysis.Confidence);
        }

        if (!summaryIds.insert(analysis.ChunkId).second && duplicateSummaryIds.insert(analysis.ChunkId).second)
        {
            diagnostics.DuplicateSummaryChunkIds.push_back(analysis.ChunkId);
        }

        if (!analysisDiagnostic.Planned)
        {
            ++diagnostics.OrphanSummaryCount;
            diagnostics.OrphanSummaryChunkIds.push_back(analysis.ChunkId);
        }

        if (analysisDiagnostic.LowConfidence)
        {
            ++diagnostics.LowConfidenceSummaryCount;
            diagnostics.LowConfidenceChunkIds.push_back(analysis.ChunkId);
        }

        if (analysisDiagnostic.HasUncertainties)
        {
            ++diagnostics.UncertainSummaryCount;
            diagnostics.UncertaintyChunkIds.push_back(analysis.ChunkId);
        }

        if (analysisDiagnostic.EmptyEvidence)
        {
            ++diagnostics.EmptyEvidenceSummaryCount;
            diagnostics.EmptyEvidenceChunkIds.push_back(analysis.ChunkId);
        }

        for (const EvidenceItem& evidence : analysis.Evidence)
        {
            for (const std::string& blockId : evidence.Blocks)
            {
                if (blockId.empty())
                {
                    continue;
                }

                analysisDiagnostic.HasBlockEvidence = true;
                evidenceBlockIds.insert(blockId);

                if (diagnostics.PlannedBlockIds.find(blockId) == diagnostics.PlannedBlockIds.end())
                {
                    analysisDiagnostic.HasUngroundedEvidence = true;
                    outsideEvidenceBlockIds.insert(blockId);
                }
            }
        }

        if (!analysisDiagnostic.HasBlockEvidence)
        {
            ++diagnostics.MissingBlockEvidenceSummaryCount;
            diagnostics.ChunksWithoutBlockEvidence.push_back(analysis.ChunkId);
        }

        if (analysisDiagnostic.EmptyEvidence || !analysisDiagnostic.HasBlockEvidence)
        {
            ++diagnostics.WeakEvidenceSummaryCount;
        }

        if (analysisDiagnostic.HasUngroundedEvidence)
        {
            ++diagnostics.UngroundedEvidenceSummaryCount;
        }

        diagnostics.AnalysisDiagnostics.push_back(analysisDiagnostic);
    }

    for (const ChunkPlan& plan : chunkPlans)
    {
        const auto summaryCountIt = diagnostics.SummaryCountsByChunkId.find(plan.Id);

        if (summaryCountIt == diagnostics.SummaryCountsByChunkId.end())
        {
            ++diagnostics.MissingSummaryCount;
            diagnostics.MissingSummaryChunkIds.push_back(plan.Id);
            continue;
        }

        if (summaryCountIt->second > 1)
        {
            diagnostics.DuplicateSummaryCount += summaryCountIt->second - 1;
        }
    }

    for (const std::string& blockId : evidenceBlockIds)
    {
        if (diagnostics.PlannedBlockIds.find(blockId) != diagnostics.PlannedBlockIds.end())
        {
            ++diagnostics.GroundedEvidenceBlockCount;
        }
    }

    for (const std::string& blockId : outsideEvidenceBlockIds)
    {
        if (diagnostics.EvidenceBlocksOutsideChunkPlans.size() >= kMergeChunkEvidenceBlockIdLimit)
        {
            break;
        }

        diagnostics.EvidenceBlocksOutsideChunkPlans.push_back(blockId);
    }

    diagnostics.PlannedBlockCount = diagnostics.PlannedBlockIds.size();
    diagnostics.EvidenceBlockCount = evidenceBlockIds.size();
    diagnostics.EvidenceBlocksOutsideChunkPlansTruncated = outsideEvidenceBlockIds.size() > kMergeChunkEvidenceBlockIdLimit;

    if (diagnostics.UncoveredBlockCount != 0)
    {
        diagnostics.RiskCodes.push_back("coverage_gap");
    }

    if (!diagnostics.MissingSummaryChunkIds.empty()
        || !diagnostics.OrphanSummaryChunkIds.empty()
        || !diagnostics.DuplicateSummaryChunkIds.empty())
    {
        diagnostics.RiskCodes.push_back("summary_alignment_issue");
    }

    if (!diagnostics.LowConfidenceChunkIds.empty())
    {
        diagnostics.RiskCodes.push_back("low_confidence_chunks");
    }

    if (!diagnostics.UncertaintyChunkIds.empty())
    {
        diagnostics.RiskCodes.push_back("uncertain_chunks");
    }

    if (!diagnostics.EmptyEvidenceChunkIds.empty())
    {
        diagnostics.RiskCodes.push_back("empty_evidence_chunks");
    }

    if (!diagnostics.ChunksWithoutBlockEvidence.empty())
    {
        diagnostics.RiskCodes.push_back("missing_block_evidence");
    }

    if (!outsideEvidenceBlockIds.empty())
    {
        diagnostics.RiskCodes.push_back("ungrounded_evidence_blocks");
    }

    return diagnostics;
}

JsonValue BuildMergeChunkSummaryAlignmentJson(
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();

    object.Set("alignment_complete", JsonValue::MakeBoolean(
        diagnostics.MissingSummaryChunkIds.empty()
        && diagnostics.OrphanSummaryChunkIds.empty()
        && diagnostics.DuplicateSummaryChunkIds.empty()));
    object.Set("missing_summary_chunk_ids", BuildStringArray(diagnostics.MissingSummaryChunkIds, 16, nullptr));
    object.Set("orphan_summary_chunk_ids", BuildStringArray(diagnostics.OrphanSummaryChunkIds, 16, nullptr));
    object.Set("duplicate_summary_chunk_ids", BuildStringArray(diagnostics.DuplicateSummaryChunkIds, 16, nullptr));
    return object;
}

JsonValue BuildMergeChunkSummaryQualityJson(
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();

    object.Set("summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.ChunkSummaryCount)));
    object.Set("average_confidence", JsonValue::MakeNumber(diagnostics.ChunkSummaryCount == 0 ? 0.0 : diagnostics.ConfidenceSum / static_cast<double>(diagnostics.ChunkSummaryCount)));
    object.Set("min_confidence", JsonValue::MakeNumber(diagnostics.HasConfidence ? diagnostics.MinConfidence : 0.0));
    object.Set("max_confidence", JsonValue::MakeNumber(diagnostics.HasConfidence ? diagnostics.MaxConfidence : 0.0));
    object.Set("low_confidence_threshold", JsonValue::MakeNumber(kMergeChunkLowConfidenceThreshold));
    object.Set("low_confidence_chunk_ids", BuildStringArray(diagnostics.LowConfidenceChunkIds, 16, nullptr));
    object.Set("uncertainty_chunk_ids", BuildStringArray(diagnostics.UncertaintyChunkIds, 16, nullptr));
    object.Set("empty_evidence_chunk_ids", BuildStringArray(diagnostics.EmptyEvidenceChunkIds, 16, nullptr));
    object.Set("all_summaries_have_evidence", JsonValue::MakeBoolean(diagnostics.EmptyEvidenceChunkIds.empty()));
    return object;
}

JsonValue BuildMergeChunkSummaryEvidenceJson(
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();

    object.Set("planned_block_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.PlannedBlockCount)));
    object.Set("evidence_block_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.EvidenceBlockCount)));
    object.Set("grounded_evidence_block_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.GroundedEvidenceBlockCount)));
    object.Set("evidence_block_coverage_ratio", JsonValue::MakeNumber(diagnostics.PlannedBlockCount == 0 ? 0.0 : static_cast<double>(diagnostics.GroundedEvidenceBlockCount) / static_cast<double>(diagnostics.PlannedBlockCount)));
    object.Set("chunks_without_block_evidence", BuildStringArray(diagnostics.ChunksWithoutBlockEvidence, 16, nullptr));
    object.Set("evidence_blocks_outside_chunk_plans", BuildStringArray(diagnostics.EvidenceBlocksOutsideChunkPlans, kMergeChunkEvidenceBlockIdLimit, nullptr));
    object.Set("evidence_blocks_outside_chunk_plans_truncated", JsonValue::MakeBoolean(diagnostics.EvidenceBlocksOutsideChunkPlansTruncated));
    object.Set("all_evidence_blocks_grounded", JsonValue::MakeBoolean(diagnostics.EvidenceBlocksOutsideChunkPlans.empty() && !diagnostics.EvidenceBlocksOutsideChunkPlansTruncated));
    return object;
}

JsonValue BuildMergeChunkRiskJson(
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();

    object.Set("risk_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.RiskCodes.size())));
    object.Set("risk_codes", BuildStringArray(diagnostics.RiskCodes, 16, nullptr));
    object.Set("has_coverage_gap", JsonValue::MakeBoolean(diagnostics.UncoveredBlockCount != 0));
    object.Set("has_summary_alignment_issue", JsonValue::MakeBoolean(
        !diagnostics.MissingSummaryChunkIds.empty()
        || !diagnostics.OrphanSummaryChunkIds.empty()
        || !diagnostics.DuplicateSummaryChunkIds.empty()));
    object.Set("has_low_confidence_chunks", JsonValue::MakeBoolean(!diagnostics.LowConfidenceChunkIds.empty()));
    object.Set("has_uncertain_chunks", JsonValue::MakeBoolean(!diagnostics.UncertaintyChunkIds.empty()));
    object.Set("has_empty_evidence_chunks", JsonValue::MakeBoolean(!diagnostics.EmptyEvidenceChunkIds.empty()));
    object.Set("has_chunks_without_block_evidence", JsonValue::MakeBoolean(!diagnostics.ChunksWithoutBlockEvidence.empty()));
    object.Set("has_ungrounded_evidence_blocks", JsonValue::MakeBoolean(!diagnostics.EvidenceBlocksOutsideChunkPlans.empty() || diagnostics.EvidenceBlocksOutsideChunkPlansTruncated));
    return object;
}

void AppendMergeChunkRiskDetail(
    JsonValue& riskedChunks,
    size_t& totalRiskedChunks,
    bool& truncated,
    const std::string& chunkId,
    bool planned,
    size_t blockCount,
    const std::set<std::string>& plannedBlockIds,
    const std::vector<const ChunkAnalysis*>& analyses)
{
    std::vector<std::string> riskCodes;
    std::vector<std::string> ungroundedEvidenceBlockIds;
    std::set<std::string> ungroundedEvidenceBlockSet;
    double confidenceSum = 0.0;
    double minConfidence = 0.0;
    double maxConfidence = 0.0;
    bool hasConfidence = false;
    bool hasLowConfidence = false;
    bool hasUncertainties = false;
    bool hasEvidence = false;
    bool hasBlockEvidence = false;

    for (const ChunkAnalysis* analysis : analyses)
    {
        if (analysis == nullptr)
        {
            continue;
        }

        confidenceSum += analysis->Confidence;

        if (!hasConfidence)
        {
            minConfidence = analysis->Confidence;
            maxConfidence = analysis->Confidence;
            hasConfidence = true;
        }
        else
        {
            minConfidence = (std::min)(minConfidence, analysis->Confidence);
            maxConfidence = (std::max)(maxConfidence, analysis->Confidence);
        }

        if (analysis->Confidence < kMergeChunkLowConfidenceThreshold)
        {
            hasLowConfidence = true;
        }

        if (!analysis->Uncertainties.empty())
        {
            hasUncertainties = true;
        }

        if (!analysis->Evidence.empty())
        {
            hasEvidence = true;
        }

        for (const EvidenceItem& evidence : analysis->Evidence)
        {
            for (const std::string& blockId : evidence.Blocks)
            {
                if (blockId.empty())
                {
                    continue;
                }

                hasBlockEvidence = true;

                if (plannedBlockIds.find(blockId) == plannedBlockIds.end())
                {
                    ungroundedEvidenceBlockSet.insert(blockId);
                }
            }
        }
    }

    if (!planned)
    {
        riskCodes.push_back("orphan_summary");
    }

    if (analyses.empty())
    {
        riskCodes.push_back("missing_summary");
    }

    if (analyses.size() > 1)
    {
        riskCodes.push_back("duplicate_summaries");
    }

    if (hasLowConfidence)
    {
        riskCodes.push_back("low_confidence");
    }

    if (hasUncertainties)
    {
        riskCodes.push_back("uncertain");
    }

    if (!hasEvidence)
    {
        riskCodes.push_back("empty_evidence");
    }

    if (!hasBlockEvidence)
    {
        riskCodes.push_back("missing_block_evidence");
    }

    if (!ungroundedEvidenceBlockSet.empty())
    {
        riskCodes.push_back("ungrounded_evidence_blocks");
    }

    if (riskCodes.empty())
    {
        return;
    }

    ++totalRiskedChunks;

    if (riskedChunks.GetArray().size() >= kMergeChunkRiskDetailLimit)
    {
        truncated = true;
        return;
    }

    for (const std::string& blockId : ungroundedEvidenceBlockSet)
    {
        if (ungroundedEvidenceBlockIds.size() >= kMergeChunkRiskEvidenceBlockIdLimit)
        {
            break;
        }

        ungroundedEvidenceBlockIds.push_back(blockId);
    }

    JsonValue item = JsonValue::MakeObject();
    item.Set("chunk_id", JsonValue::MakeString(chunkId));
    item.Set("planned", JsonValue::MakeBoolean(planned));
    item.Set("block_count", JsonValue::MakeNumber(static_cast<double>(blockCount)));
    item.Set("summary_count", JsonValue::MakeNumber(static_cast<double>(analyses.size())));
    item.Set("risk_codes", BuildStringArray(riskCodes, 16, nullptr));
    item.Set("confidence_average", JsonValue::MakeNumber(analyses.empty() ? 0.0 : confidenceSum / static_cast<double>(analyses.size())));
    item.Set("confidence_min", JsonValue::MakeNumber(hasConfidence ? minConfidence : 0.0));
    item.Set("confidence_max", JsonValue::MakeNumber(hasConfidence ? maxConfidence : 0.0));
    item.Set("has_missing_summary", JsonValue::MakeBoolean(analyses.empty()));
    item.Set("has_duplicate_summaries", JsonValue::MakeBoolean(analyses.size() > 1));
    item.Set("has_low_confidence", JsonValue::MakeBoolean(hasLowConfidence));
    item.Set("has_uncertainties", JsonValue::MakeBoolean(hasUncertainties));
    item.Set("has_evidence", JsonValue::MakeBoolean(hasEvidence));
    item.Set("has_block_evidence", JsonValue::MakeBoolean(hasBlockEvidence));
    item.Set("ungrounded_evidence_blocks", BuildStringArray(ungroundedEvidenceBlockIds, kMergeChunkRiskEvidenceBlockIdLimit, nullptr));
    item.Set("ungrounded_evidence_blocks_truncated", JsonValue::MakeBoolean(ungroundedEvidenceBlockSet.size() > kMergeChunkRiskEvidenceBlockIdLimit));
    riskedChunks.PushBack(item);
}

JsonValue BuildMergeChunkRiskDetailsJson(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue riskedChunks = JsonValue::MakeArray();
    std::unordered_map<std::string, std::vector<const ChunkAnalysis*>> analysesByChunkId;
    std::set<std::string> planIds;
    std::set<std::string> orphanChunkIds;
    size_t totalRiskedChunks = 0;
    bool truncated = false;

    for (const ChunkAnalysis& analysis : chunkAnalyses)
    {
        analysesByChunkId[analysis.ChunkId].push_back(&analysis);
    }

    for (const ChunkPlan& plan : chunkPlans)
    {
        planIds.insert(plan.Id);
    }

    for (const ChunkPlan& plan : chunkPlans)
    {
        std::set<std::string> plannedBlockIds;
        std::vector<const ChunkAnalysis*> emptyAnalyses;
        const auto analysisIt = analysesByChunkId.find(plan.Id);
        const std::vector<const ChunkAnalysis*>& analyses = analysisIt == analysesByChunkId.end() ? emptyAnalyses : analysisIt->second;

        for (const size_t blockIndex : plan.BlockIndices)
        {
            if (blockIndex < request.Facts.Blocks.size())
            {
                plannedBlockIds.insert(request.Facts.Blocks[blockIndex].Id);
            }
        }

        AppendMergeChunkRiskDetail(
            riskedChunks,
            totalRiskedChunks,
            truncated,
            plan.Id,
            true,
            plan.BlockIndices.size(),
            plannedBlockIds,
            analyses);
    }

    for (const ChunkAnalysis& analysis : chunkAnalyses)
    {
        if (planIds.find(analysis.ChunkId) == planIds.end())
        {
            orphanChunkIds.insert(analysis.ChunkId);
        }
    }

    for (const std::string& chunkId : orphanChunkIds)
    {
        std::set<std::string> plannedBlockIds;
        const auto analysisIt = analysesByChunkId.find(chunkId);

        if (analysisIt == analysesByChunkId.end())
        {
            continue;
        }

        AppendMergeChunkRiskDetail(
            riskedChunks,
            totalRiskedChunks,
            truncated,
            chunkId,
            false,
            0,
            plannedBlockIds,
            analysisIt->second);
    }

    object.Set("risked_chunk_count", JsonValue::MakeNumber(static_cast<double>(totalRiskedChunks)));
    object.Set("risked_chunks", riskedChunks);
    object.Set("risked_chunks_truncated", JsonValue::MakeBoolean(truncated));
    object.Set("risk_detail_limit", JsonValue::MakeNumber(static_cast<double>(kMergeChunkRiskDetailLimit)));
    return object;
}

void AppendMergeReviewAction(
    std::vector<std::string>& actions,
    const std::string& action)
{
    if (std::find(actions.begin(), actions.end(), action) == actions.end())
    {
        actions.push_back(action);
    }
}

void AppendMergeReviewChunkId(
    std::vector<std::string>& chunkIds,
    bool& truncated,
    const std::string& chunkId)
{
    if (chunkId.empty() || std::find(chunkIds.begin(), chunkIds.end(), chunkId) != chunkIds.end())
    {
        return;
    }

    if (chunkIds.size() >= kMergeChunkReviewPlanChunkLimit)
    {
        truncated = true;
        return;
    }

    chunkIds.push_back(chunkId);
}

JsonValue BuildMergeChunkReviewPlanJson(
    const std::vector<ChunkPlan>& chunkPlans,
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();
    std::vector<std::string> reviewActions;
    std::vector<std::string> priorityChunkIds;
    bool priorityChunkIdsTruncated = false;
    bool requiresCoverageReview = false;
    bool requiresSummaryReconciliation = false;
    bool requiresConfidenceReview = false;
    bool requiresEvidenceReview = false;

    if (diagnostics.UncoveredBlockCount != 0)
    {
        requiresCoverageReview = true;
        AppendMergeReviewAction(reviewActions, "verify_uncovered_blocks");
    }

    for (const ChunkPlan& plan : chunkPlans)
    {
        const auto summaryCountIt = diagnostics.SummaryCountsByChunkId.find(plan.Id);
        const size_t summaryCount = summaryCountIt == diagnostics.SummaryCountsByChunkId.end() ? 0 : summaryCountIt->second;

        if (summaryCount == 0)
        {
            requiresSummaryReconciliation = true;
            AppendMergeReviewAction(reviewActions, "recover_missing_chunk_summary");
            AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, plan.Id);
        }

        if (summaryCount > 1)
        {
            requiresSummaryReconciliation = true;
            AppendMergeReviewAction(reviewActions, "reconcile_duplicate_chunk_summaries");
            AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, plan.Id);
        }

        for (const MergeChunkAnalysisDiagnostic& analysisDiagnostic : diagnostics.AnalysisDiagnostics)
        {
            if (analysisDiagnostic.ChunkId != plan.Id)
            {
                continue;
            }

            if (analysisDiagnostic.LowConfidence)
            {
                requiresConfidenceReview = true;
                AppendMergeReviewAction(reviewActions, "recheck_low_confidence_chunks");
                AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, plan.Id);
            }

            if (analysisDiagnostic.HasUncertainties)
            {
                requiresConfidenceReview = true;
                AppendMergeReviewAction(reviewActions, "preserve_chunk_uncertainties");
                AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, plan.Id);
            }

            if (analysisDiagnostic.EmptyEvidence || !analysisDiagnostic.HasBlockEvidence)
            {
                requiresEvidenceReview = true;
                AppendMergeReviewAction(reviewActions, "require_chunk_block_evidence");
                AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, plan.Id);
            }

            if (analysisDiagnostic.HasUngroundedEvidence)
            {
                requiresEvidenceReview = true;
                AppendMergeReviewAction(reviewActions, "discard_ungrounded_chunk_evidence");
                AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, plan.Id);
            }
        }
    }

    for (const MergeChunkAnalysisDiagnostic& analysisDiagnostic : diagnostics.AnalysisDiagnostics)
    {
        if (analysisDiagnostic.Planned)
        {
            continue;
        }

        requiresSummaryReconciliation = true;
        AppendMergeReviewAction(reviewActions, "ignore_or_reconcile_orphan_summary");
        AppendMergeReviewChunkId(priorityChunkIds, priorityChunkIdsTruncated, analysisDiagnostic.ChunkId);
    }

    if (reviewActions.empty())
    {
        AppendMergeReviewAction(reviewActions, "synthesize_from_grounded_chunks");
    }

    object.Set("review_action_count", JsonValue::MakeNumber(static_cast<double>(reviewActions.size())));
    object.Set("review_actions", BuildStringArray(reviewActions, 16, nullptr));
    object.Set("priority_chunk_ids", BuildStringArray(priorityChunkIds, kMergeChunkReviewPlanChunkLimit, nullptr));
    object.Set("priority_chunk_ids_truncated", JsonValue::MakeBoolean(priorityChunkIdsTruncated));
    object.Set("priority_chunk_limit", JsonValue::MakeNumber(static_cast<double>(kMergeChunkReviewPlanChunkLimit)));
    object.Set("requires_coverage_review", JsonValue::MakeBoolean(requiresCoverageReview));
    object.Set("requires_summary_reconciliation", JsonValue::MakeBoolean(requiresSummaryReconciliation));
    object.Set("requires_confidence_review", JsonValue::MakeBoolean(requiresConfidenceReview));
    object.Set("requires_evidence_review", JsonValue::MakeBoolean(requiresEvidenceReview));
    object.Set("has_priority_chunks", JsonValue::MakeBoolean(!priorityChunkIds.empty()));
    return object;
}

void ApplyMergeConfidenceCeiling(
    double& confidenceCeiling,
    std::vector<std::string>& ceilingReasons,
    double candidateCeiling,
    const std::string& reason)
{
    confidenceCeiling = (std::min)(confidenceCeiling, candidateCeiling);

    if (std::find(ceilingReasons.begin(), ceilingReasons.end(), reason) == ceilingReasons.end())
    {
        ceilingReasons.push_back(reason);
    }
}

MergeConfidencePolicy BuildMergeConfidencePolicy(const MergeChunkDiagnostics& diagnostics)
{
    MergeConfidencePolicy policy;

    if (diagnostics.ChunkSummaryCount == 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.45, "no_chunk_summaries");
    }

    if (diagnostics.UncoveredBlockCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.65, "coverage_gap");
    }

    if (diagnostics.MissingSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.60, "missing_chunk_summary");
    }

    if (diagnostics.OrphanSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.65, "orphan_chunk_summary");
    }

    if (diagnostics.DuplicateSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.62, "duplicate_chunk_summary");
    }

    if (diagnostics.LowConfidenceSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.55, "low_confidence_chunk_summary");
    }

    if (diagnostics.UncertainSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.65, "uncertain_chunk_summary");
    }

    if (diagnostics.EmptyEvidenceSummaryCount != 0 || diagnostics.MissingBlockEvidenceSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.58, "weak_chunk_evidence");
    }

    if (diagnostics.UngroundedEvidenceSummaryCount != 0)
    {
        ApplyMergeConfidenceCeiling(policy.RecommendedConfidenceCeiling, policy.CeilingReasons, 0.55, "ungrounded_chunk_evidence");
    }

    return policy;
}

MergeAcceptancePolicy BuildMergeAcceptancePolicy(const MergeChunkDiagnostics& diagnostics)
{
    MergeAcceptancePolicy policy;

    AppendMergeReviewAction(policy.AcceptanceChecks, "preserve_visible_operations");
    AppendMergeReviewAction(policy.AcceptanceChecks, "ground_claims_to_chunk_blocks");
    AppendMergeReviewAction(policy.AcceptanceChecks, "respect_confidence_policy");

    if (diagnostics.UncoveredBlockCount != 0)
    {
        AppendMergeReviewAction(policy.AcceptanceChecks, "describe_uncovered_blocks");
        AppendMergeReviewAction(policy.BlockingIssues, "coverage_gap");
    }

    if (diagnostics.MissingSummaryCount != 0 || diagnostics.OrphanSummaryCount != 0 || diagnostics.DuplicateSummaryCount != 0)
    {
        AppendMergeReviewAction(policy.AcceptanceChecks, "reconcile_chunk_summary_alignment");
        AppendMergeReviewAction(policy.BlockingIssues, "summary_alignment_issue");
    }

    if (diagnostics.LowConfidenceSummaryCount != 0 || diagnostics.UncertainSummaryCount != 0)
    {
        AppendMergeReviewAction(policy.AcceptanceChecks, "carry_chunk_uncertainties");
        AppendMergeReviewAction(policy.BlockingIssues, "uncertain_or_low_confidence_summary");
    }

    if (diagnostics.WeakEvidenceSummaryCount != 0)
    {
        AppendMergeReviewAction(policy.AcceptanceChecks, "avoid_unsupported_evidence_claims");
        AppendMergeReviewAction(policy.BlockingIssues, "weak_chunk_evidence");
    }

    if (diagnostics.UngroundedEvidenceSummaryCount != 0)
    {
        AppendMergeReviewAction(policy.AcceptanceChecks, "discard_ungrounded_evidence");
        AppendMergeReviewAction(policy.BlockingIssues, "ungrounded_chunk_evidence");
    }

    policy.RequiresCoverageStatement = diagnostics.UncoveredBlockCount != 0;
    policy.RequiresEvidenceRewrite = diagnostics.WeakEvidenceSummaryCount != 0 || diagnostics.UngroundedEvidenceSummaryCount != 0;
    return policy;
}

JsonValue BuildMergeChunkConfidencePolicyJson(
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();
    const MergeConfidencePolicy policy = BuildMergeConfidencePolicy(diagnostics);

    object.Set("recommended_confidence_ceiling", JsonValue::MakeNumber(policy.RecommendedConfidenceCeiling));
    object.Set("ceiling_reasons", BuildStringArray(policy.CeilingReasons, 16, nullptr));
    object.Set("requires_uncertainty", JsonValue::MakeBoolean(!policy.CeilingReasons.empty()));
    object.Set("can_report_high_confidence", JsonValue::MakeBoolean(policy.CeilingReasons.empty()));
    object.Set("low_confidence_threshold", JsonValue::MakeNumber(kMergeChunkLowConfidenceThreshold));
    object.Set("chunk_plan_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.ChunkPlanCount)));
    object.Set("chunk_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.ChunkSummaryCount)));
    object.Set("missing_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.MissingSummaryCount)));
    object.Set("orphan_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.OrphanSummaryCount)));
    object.Set("duplicate_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.DuplicateSummaryCount)));
    object.Set("low_confidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.LowConfidenceSummaryCount)));
    object.Set("empty_evidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.EmptyEvidenceSummaryCount)));
    object.Set("missing_block_evidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.MissingBlockEvidenceSummaryCount)));
    object.Set("ungrounded_evidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.UngroundedEvidenceSummaryCount)));
    return object;
}

JsonValue BuildMergeChunkAcceptanceChecksJson(
    const MergeChunkDiagnostics& diagnostics)
{
    JsonValue object = JsonValue::MakeObject();
    const MergeAcceptancePolicy policy = BuildMergeAcceptancePolicy(diagnostics);

    object.Set("acceptance_check_count", JsonValue::MakeNumber(static_cast<double>(policy.AcceptanceChecks.size())));
    object.Set("acceptance_checks", BuildStringArray(policy.AcceptanceChecks, 16, nullptr));
    object.Set("blocking_issue_count", JsonValue::MakeNumber(static_cast<double>(policy.BlockingIssues.size())));
    object.Set("blocking_issues", BuildStringArray(policy.BlockingIssues, 16, nullptr));
    object.Set("must_emit_uncertainties", JsonValue::MakeBoolean(!policy.BlockingIssues.empty()));
    object.Set("must_bound_confidence", JsonValue::MakeBoolean(!policy.BlockingIssues.empty()));
    object.Set("requires_coverage_statement", JsonValue::MakeBoolean(policy.RequiresCoverageStatement));
    object.Set("requires_evidence_rewrite", JsonValue::MakeBoolean(policy.RequiresEvidenceRewrite));
    object.Set("ready_for_high_confidence_merge", JsonValue::MakeBoolean(policy.BlockingIssues.empty()));
    object.Set("missing_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.MissingSummaryCount)));
    object.Set("orphan_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.OrphanSummaryCount)));
    object.Set("duplicate_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.DuplicateSummaryCount)));
    object.Set("low_confidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.LowConfidenceSummaryCount)));
    object.Set("uncertain_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.UncertainSummaryCount)));
    object.Set("weak_evidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.WeakEvidenceSummaryCount)));
    object.Set("ungrounded_evidence_summary_count", JsonValue::MakeNumber(static_cast<double>(diagnostics.UngroundedEvidenceSummaryCount)));
    return object;
}

std::string FormatPolicyConfidence(double value)
{
    std::ostringstream stream;
    stream << std::fixed << std::setprecision(2) << Clamp01(value);
    return stream.str();
}

void AppendUniqueMergePolicyText(
    std::vector<std::string>& values,
    const std::string& value)
{
    if (value.empty())
    {
        return;
    }

    if (std::find(values.begin(), values.end(), value) == values.end())
    {
        values.push_back(value);
    }
}

void AddMergePolicyVerifierIssue(
    VerifyReport& report,
    const std::string& code,
    const std::string& severity,
    const std::string& message,
    const std::string& evidence)
{
    for (const VerificationIssue& issue : report.Issues)
    {
        if (issue.Code == code && issue.Evidence == evidence)
        {
            return;
        }
    }

    VerificationIssue issue;
    issue.Code = code;
    issue.Severity = severity;
    issue.Message = message;
    issue.Evidence = evidence;
    report.Issues.push_back(issue);
    report.Warnings.push_back(message);
}

std::string BuildMergePolicyUncertaintyText(const MergeOutputPostPolicy& policy)
{
    std::vector<std::string> details;

    if (!policy.Confidence.CeilingReasons.empty())
    {
        details.push_back("confidence_reasons=" + JoinStrings(policy.Confidence.CeilingReasons, ","));
    }

    if (!policy.Acceptance.BlockingIssues.empty())
    {
        details.push_back("blocking_issues=" + JoinStrings(policy.Acceptance.BlockingIssues, ","));
    }

    if (details.empty())
    {
        return std::string();
    }

    return "merge acceptance policy applied: " + JoinStrings(details, "; ");
}

MergeOutputPostPolicy BuildMergeOutputPostPolicy(
    const AnalyzeRequest& request,
    const std::vector<ChunkPlan>& chunkPlans,
    const std::vector<ChunkAnalysis>& chunkAnalyses)
{
    MergeOutputPostPolicy policy;

    if (chunkPlans.empty())
    {
        return policy;
    }

    const std::set<size_t> coveredBlocks = BuildMergeCoveredBlockIndexSet(chunkPlans);
    const size_t uncoveredBlockCount = CountMergeUncoveredBlocks(request, coveredBlocks);
    const MergeChunkDiagnostics diagnostics = BuildMergeChunkDiagnostics(request, chunkPlans, chunkAnalyses, uncoveredBlockCount);

    policy.Active = true;
    policy.Confidence = BuildMergeConfidencePolicy(diagnostics);
    policy.Acceptance = BuildMergeAcceptancePolicy(diagnostics);
    return policy;
}

void ApplyMergeOutputPostPolicy(
    const MergeOutputPostPolicy& policy,
    AnalyzeResponse& response)
{
    if (!policy.Active)
    {
        return;
    }

    const double originalConfidence = Clamp01(response.Confidence);
    const double ceiling = Clamp01(policy.Confidence.RecommendedConfidenceCeiling);
    const bool requiresUncertainty = !policy.Confidence.CeilingReasons.empty()
        || !policy.Acceptance.BlockingIssues.empty();
    const bool hadUncertainty = !response.Uncertainties.empty();

    if (originalConfidence > ceiling)
    {
        ++response.Verifier.FactConflicts;
        AddMergePolicyVerifierIssue(
            response.Verifier,
            "merge.confidence_ceiling_exceeded",
            "error",
            "merge response confidence exceeded the chunk confidence policy ceiling",
            "confidence=" + FormatPolicyConfidence(originalConfidence)
                + " ceiling=" + FormatPolicyConfidence(ceiling)
                + " reasons=" + JoinStrings(policy.Confidence.CeilingReasons, ","));
        response.Confidence = ceiling;
    }
    else
    {
        response.Confidence = originalConfidence;
    }

    if (requiresUncertainty)
    {
        const std::string uncertainty = BuildMergePolicyUncertaintyText(policy);
        AppendUniqueMergePolicyText(response.Uncertainties, uncertainty);

        if (!hadUncertainty)
        {
            ++response.Verifier.MissingEvidence;
            AddMergePolicyVerifierIssue(
                response.Verifier,
                "merge.acceptance_blockers_missing_uncertainty",
                "error",
                "merge response omitted uncertainty required by chunk acceptance blockers",
                JoinStrings(policy.Acceptance.BlockingIssues, ","));
        }
    }

    if (!policy.Acceptance.BlockingIssues.empty() && originalConfidence > ceiling)
    {
        AddMergePolicyVerifierIssue(
            response.Verifier,
            "merge.acceptance_blockers_high_confidence",
            "error",
            "merge response reported high confidence despite chunk acceptance blockers",
            JoinStrings(policy.Acceptance.BlockingIssues, ","));
    }

    response.Verifier.AdjustedConfidence = Clamp01((std::min)(response.Verifier.AdjustedConfidence, response.Confidence));
}

JsonValue BuildMergeChunkOutputContractJson()
{
    JsonValue object = JsonValue::MakeObject();
    std::vector<std::string> requiredTopLevelKeys;
    std::vector<std::string> requiredEvidenceKeys;
    std::vector<std::string> outputRules;
    std::vector<std::string> blockedMergeRules;

    requiredTopLevelKeys.push_back("status");
    requiredTopLevelKeys.push_back("pseudo_c");
    requiredTopLevelKeys.push_back("summary");
    requiredTopLevelKeys.push_back("params");
    requiredTopLevelKeys.push_back("locals");
    requiredTopLevelKeys.push_back("uncertainties");
    requiredTopLevelKeys.push_back("evidence");
    requiredTopLevelKeys.push_back("confidence");

    requiredEvidenceKeys.push_back("claim");
    requiredEvidenceKeys.push_back("blocks");

    outputRules.push_back("summary_uses_configured_language");
    outputRules.push_back("pseudo_c_uses_c_style_tokens");
    outputRules.push_back("evidence_blocks_reference_chunk_summaries");
    outputRules.push_back("confidence_respects_confidence_policy");
    outputRules.push_back("uncertainties_reflect_acceptance_blockers");

    blockedMergeRules.push_back("do_not_report_clean_merge");
    blockedMergeRules.push_back("emit_uncertainty_for_each_blocker");
    blockedMergeRules.push_back("cap_confidence_at_recommended_ceiling");
    blockedMergeRules.push_back("drop_or_rewrite_ungrounded_evidence");

    object.Set("required_top_level_keys", BuildStringArray(requiredTopLevelKeys, 16, nullptr));
    object.Set("required_evidence_keys", BuildStringArray(requiredEvidenceKeys, 8, nullptr));
    object.Set("output_rules", BuildStringArray(outputRules, 16, nullptr));
    object.Set("blocked_merge_rules", BuildStringArray(blockedMergeRules, 16, nullptr));
    object.Set("confidence_policy_path", JsonValue::MakeString("chunking.merge_confidence_policy.recommended_confidence_ceiling"));
    object.Set("acceptance_blockers_path", JsonValue::MakeString("chunking.merge_acceptance_checks.blocking_issues"));
    object.Set("review_plan_path", JsonValue::MakeString("chunking.merge_review_plan.review_actions"));
    object.Set("requires_json_object_only", JsonValue::MakeBoolean(true));
    object.Set("requires_evidence_array", JsonValue::MakeBoolean(true));
    object.Set("requires_block_grounding", JsonValue::MakeBoolean(true));
    object.Set("requires_configured_summary_language", JsonValue::MakeBoolean(true));
    return object;
}

void AppendMergeTraceabilityTarget(
    JsonValue& targets,
    const std::string& outputKey,
    const std::vector<std::string>& factPaths,
    const std::vector<std::string>& chunkPaths,
    const std::vector<std::string>& validationChecks)
{
    JsonValue item = JsonValue::MakeObject();
    item.Set("output_key", JsonValue::MakeString(outputKey));
    item.Set("fact_paths", BuildStringArray(factPaths, 16, nullptr));
    item.Set("chunk_paths", BuildStringArray(chunkPaths, 16, nullptr));
    item.Set("validation_checks", BuildStringArray(validationChecks, 16, nullptr));
    targets.PushBack(item);
}

JsonValue BuildMergeChunkTraceabilityMatrixJson()
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue targets = JsonValue::MakeArray();
    std::vector<std::string> factPaths;
    std::vector<std::string> chunkPaths;
    std::vector<std::string> validationChecks;

    factPaths.push_back("analyzer_skeleton");
    factPaths.push_back("blocks");
    factPaths.push_back("control_flow");
    factPaths.push_back("semantic_control_flow");
    factPaths.push_back("obfuscation");
    chunkPaths.push_back("chunk_summaries.pseudo_steps");
    chunkPaths.push_back("chunk_summaries.state_updates");
    chunkPaths.push_back("chunking.chunk_plans.block_ids");
    validationChecks.push_back("preserve_visible_operations");
    validationChecks.push_back("prefer_semantic_control_flow_when_grounded");
    validationChecks.push_back("do_not_invent_uncovered_operations");
    AppendMergeTraceabilityTarget(targets, "pseudo_c", factPaths, chunkPaths, validationChecks);

    factPaths.clear();
    chunkPaths.clear();
    validationChecks.clear();
    factPaths.push_back("natural_language");
    factPaths.push_back("global_facts");
    factPaths.push_back("observed_behavior");
    chunkPaths.push_back("chunk_summaries.summary_localized");
    chunkPaths.push_back("chunking.summary_alignment");
    validationChecks.push_back("use_configured_language");
    validationChecks.push_back("mention_partial_coverage_when_present");
    AppendMergeTraceabilityTarget(targets, "summary", factPaths, chunkPaths, validationChecks);

    factPaths.clear();
    chunkPaths.clear();
    validationChecks.clear();
    factPaths.push_back("recovered_arguments");
    factPaths.push_back("call_arguments");
    factPaths.push_back("pdb");
    factPaths.push_back("abi");
    chunkPaths.push_back("chunk_summaries.observed_calls");
    chunkPaths.push_back("chunking.merge_risk_details");
    validationChecks.push_back("prefer_named_pdb_or_recovered_arguments");
    validationChecks.push_back("carry_low_confidence_arguments_to_uncertainties");
    AppendMergeTraceabilityTarget(targets, "params", factPaths, chunkPaths, validationChecks);

    factPaths.clear();
    chunkPaths.clear();
    validationChecks.clear();
    factPaths.push_back("recovered_locals");
    factPaths.push_back("stack_pointer");
    factPaths.push_back("memory_accesses");
    factPaths.push_back("pdb");
    chunkPaths.push_back("chunk_summaries.observed_memory");
    chunkPaths.push_back("chunk_summaries.state_updates");
    validationChecks.push_back("preserve_stack_frame_context");
    validationChecks.push_back("avoid_unbacked_local_names");
    AppendMergeTraceabilityTarget(targets, "locals", factPaths, chunkPaths, validationChecks);

    factPaths.clear();
    chunkPaths.clear();
    validationChecks.clear();
    factPaths.push_back("global_uncertainties");
    factPaths.push_back("session_policy");
    factPaths.push_back("observed_behavior");
    chunkPaths.push_back("chunk_summaries.uncertainties");
    chunkPaths.push_back("chunking.merge_acceptance_checks.blocking_issues");
    chunkPaths.push_back("chunking.merge_confidence_policy.ceiling_reasons");
    validationChecks.push_back("emit_uncertainty_for_each_blocker");
    validationChecks.push_back("preserve_chunk_uncertainties");
    AppendMergeTraceabilityTarget(targets, "uncertainties", factPaths, chunkPaths, validationChecks);

    factPaths.clear();
    chunkPaths.clear();
    validationChecks.clear();
    factPaths.push_back("evidence_graph");
    factPaths.push_back("blocks");
    factPaths.push_back("semantic_control_flow");
    chunkPaths.push_back("chunk_summaries.evidence");
    chunkPaths.push_back("chunking.summary_evidence");
    chunkPaths.push_back("chunking.merge_risk_details");
    validationChecks.push_back("ground_claims_to_chunk_blocks");
    validationChecks.push_back("drop_or_rewrite_ungrounded_evidence");
    AppendMergeTraceabilityTarget(targets, "evidence", factPaths, chunkPaths, validationChecks);

    factPaths.clear();
    chunkPaths.clear();
    validationChecks.clear();
    factPaths.push_back("pre_llm_confidence");
    chunkPaths.push_back("chunking.merge_confidence_policy");
    chunkPaths.push_back("chunking.merge_acceptance_checks");
    chunkPaths.push_back("chunking.merge_risk");
    validationChecks.push_back("cap_confidence_at_recommended_ceiling");
    validationChecks.push_back("avoid_high_confidence_when_blocked");
    AppendMergeTraceabilityTarget(targets, "confidence", factPaths, chunkPaths, validationChecks);

    object.Set("target_count", JsonValue::MakeNumber(static_cast<double>(targets.GetArray().size())));
    object.Set("targets", targets);
    object.Set("requires_source_path_review", JsonValue::MakeBoolean(true));
    object.Set("requires_chunk_summary_linkage", JsonValue::MakeBoolean(true));
    object.Set("requires_evidence_graph_crosscheck", JsonValue::MakeBoolean(true));
    return object;
}

JsonValue BuildMergeChunkObfuscationPolicyJson(const AnalyzeRequest& request)
{
    JsonValue object = JsonValue::MakeObject();
    std::vector<std::string> rewriteRules;
    std::vector<std::string> uncertaintyRules;
    size_t highConfidenceSemanticEdgeCount = 0;
    size_t deadSemanticEdgeCount = 0;
    const bool deobfuscationEnabled = request.Facts.DeobfuscationReadiness.Enabled;

    for (const SemanticControlFlowEdge& edge : request.Facts.SemanticControlFlow.Edges)
    {
        if (edge.Confidence >= 0.75)
        {
            ++highConfidenceSemanticEdgeCount;
        }

        if (edge.Dead)
        {
            ++deadSemanticEdgeCount;
        }
    }

    if (deobfuscationEnabled)
    {
        rewriteRules.push_back("prefer_semantic_overlay_edges");
        rewriteRules.push_back("avoid_raw_dispatcher_loop_as_source_structure");
        rewriteRules.push_back("prune_only_proven_dead_edges");
        rewriteRules.push_back("simplify_substitution_idioms_locally");
        rewriteRules.push_back("fall_back_to_raw_blocks_when_semantic_overlay_is_missing");
        rewriteRules.push_back("assign_state_variables_only_to_recovered_state_values");
        rewriteRules.push_back("preserve_helper_call_argument_expressions");
    }
    else
    {
        rewriteRules.push_back("preserve_raw_obfuscated_structure");
    }

    uncertaintyRules.push_back("preserve_unresolved_state_transitions");
    uncertaintyRules.push_back("mark_low_confidence_recovered_edges_uncertain");
    uncertaintyRules.push_back("do_not_infer_dead_edges_without_opaque_predicate_facts");
    uncertaintyRules.push_back("do_not_promote_substitution_idioms_to_source_intent");
    uncertaintyRules.push_back("do_not_use_data_reads_as_state_values");
    uncertaintyRules.push_back("mark_missing_helper_argument_operands_uncertain");

    if (!deobfuscationEnabled)
    {
        uncertaintyRules.push_back("deobfuscation_disabled_by_option");
    }

    object.Set("enabled", JsonValue::MakeBoolean(deobfuscationEnabled));
    object.Set("mode", JsonValue::MakeString(deobfuscationEnabled ? "on" : "off"));
    object.Set("has_obfuscation_facts", JsonValue::MakeBoolean(
        !request.Facts.Obfuscation.Dispatchers.empty()
        || !request.Facts.Obfuscation.OpaquePredicates.empty()
        || !request.Facts.Obfuscation.SubstitutionIdioms.empty()));
    object.Set("has_flattening_dispatcher", JsonValue::MakeBoolean(!request.Facts.Obfuscation.Dispatchers.empty()));
    object.Set("has_opaque_predicates", JsonValue::MakeBoolean(!request.Facts.Obfuscation.OpaquePredicates.empty()));
    object.Set("has_substitution_idioms", JsonValue::MakeBoolean(!request.Facts.Obfuscation.SubstitutionIdioms.empty()));
    object.Set("has_semantic_overlay", JsonValue::MakeBoolean(!request.Facts.SemanticControlFlow.Edges.empty()));
    object.Set("can_prefer_semantic_cfg", JsonValue::MakeBoolean(deobfuscationEnabled && highConfidenceSemanticEdgeCount != 0));
    object.Set("dispatcher_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.Dispatchers.size())));
    object.Set("opaque_predicate_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.OpaquePredicates.size())));
    object.Set("substitution_idiom_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.SubstitutionIdioms.size())));
    object.Set("semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.SemanticControlFlow.Edges.size())));
    object.Set("high_confidence_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(highConfidenceSemanticEdgeCount)));
    object.Set("dead_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(deadSemanticEdgeCount)));
    object.Set("obfuscation_rewrite_rules", BuildStringArray(rewriteRules, 16, nullptr));
    object.Set("obfuscation_uncertainty_rules", BuildStringArray(uncertaintyRules, 16, nullptr));
    object.Set("semantic_overlay_confidence_threshold", JsonValue::MakeNumber(0.75));
    return object;
}

JsonValue BuildMergeChunkDeobfuscationPlanJson(const AnalyzeRequest& request)
{
    JsonValue object = JsonValue::MakeObject();
    std::vector<std::string> deobfuscationActions;
    std::vector<std::string> priorityFactPaths;
    std::vector<std::string> blockedAssumptions;
    size_t highConfidenceSemanticEdgeCount = 0;
    const bool hasDispatchers = !request.Facts.Obfuscation.Dispatchers.empty();
    const bool hasOpaquePredicates = !request.Facts.Obfuscation.OpaquePredicates.empty();
    const bool hasSubstitutionIdioms = !request.Facts.Obfuscation.SubstitutionIdioms.empty();
    const bool hasSemanticOverlay = !request.Facts.SemanticControlFlow.Edges.empty();
    const bool hasObfuscationFacts = hasDispatchers || hasOpaquePredicates || hasSubstitutionIdioms;
    const bool deobfuscationEnabled = request.Facts.DeobfuscationReadiness.Enabled;

    for (const SemanticControlFlowEdge& edge : request.Facts.SemanticControlFlow.Edges)
    {
        if (edge.Confidence >= 0.75)
        {
            ++highConfidenceSemanticEdgeCount;
        }
    }

    if (deobfuscationEnabled)
    {
        if (hasSemanticOverlay)
        {
            AppendMergeReviewAction(deobfuscationActions, "apply_semantic_control_flow_overlay");
            AppendMergeReviewAction(priorityFactPaths, "semantic_control_flow.edges");
        }

        if (hasDispatchers)
        {
            AppendMergeReviewAction(deobfuscationActions, "recover_dispatcher_edges");
            AppendMergeReviewAction(deobfuscationActions, "suppress_dispatcher_loop_shape");
            AppendMergeReviewAction(priorityFactPaths, "obfuscation.dispatchers.recovered_edges");
            AppendMergeReviewAction(priorityFactPaths, "obfuscation.dispatchers.state_variable");
        }

        if (hasOpaquePredicates)
        {
            AppendMergeReviewAction(deobfuscationActions, "prune_proven_opaque_dead_edges");
            AppendMergeReviewAction(priorityFactPaths, "obfuscation.opaque_predicates");
        }

        if (hasSubstitutionIdioms)
        {
            AppendMergeReviewAction(deobfuscationActions, "apply_local_substitution_simplifications");
            AppendMergeReviewAction(priorityFactPaths, "obfuscation.substitution_idioms");
        }

        if (hasObfuscationFacts && !hasSemanticOverlay)
        {
            AppendMergeReviewAction(deobfuscationActions, "preserve_raw_cfg_fallback_uncertainty");
            AppendMergeReviewAction(priorityFactPaths, "control_flow");
            AppendMergeReviewAction(priorityFactPaths, "blocks");
        }

        if (!hasObfuscationFacts)
        {
            AppendMergeReviewAction(deobfuscationActions, "no_deobfuscation_rewrite_required");
        }

        blockedAssumptions.push_back("raw_dispatcher_loop_is_source_loop");
        blockedAssumptions.push_back("opaque_branch_is_dead_without_fact");
        blockedAssumptions.push_back("substitution_idiom_is_source_intent");
        blockedAssumptions.push_back("low_confidence_semantic_edge_is_structural_truth");
    }
    else
    {
        if (hasObfuscationFacts)
        {
            AppendMergeReviewAction(deobfuscationActions, "preserve_raw_obfuscated_structure");
            AppendMergeReviewAction(priorityFactPaths, "obfuscation");
            AppendMergeReviewAction(priorityFactPaths, "control_flow");
            AppendMergeReviewAction(priorityFactPaths, "blocks");
        }
        else
        {
            AppendMergeReviewAction(deobfuscationActions, "no_deobfuscation_rewrite_required");
        }

        blockedAssumptions.push_back("deobfuscation_disabled_by_option");
    }

    object.Set("enabled", JsonValue::MakeBoolean(deobfuscationEnabled));
    object.Set("mode", JsonValue::MakeString(deobfuscationEnabled ? "on" : "off"));
    object.Set("deobfuscation_action_count", JsonValue::MakeNumber(static_cast<double>(deobfuscationActions.size())));
    object.Set("deobfuscation_actions", BuildStringArray(deobfuscationActions, 16, nullptr));
    object.Set("priority_fact_paths", BuildStringArray(priorityFactPaths, 16, nullptr));
    object.Set("blocked_assumptions", BuildStringArray(blockedAssumptions, 16, nullptr));
    object.Set("requires_dispatcher_edge_reconciliation", JsonValue::MakeBoolean(deobfuscationEnabled && hasDispatchers));
    object.Set("requires_opaque_dead_edge_pruning", JsonValue::MakeBoolean(deobfuscationEnabled && hasOpaquePredicates));
    object.Set("requires_substitution_simplification", JsonValue::MakeBoolean(deobfuscationEnabled && hasSubstitutionIdioms));
    object.Set("requires_semantic_overlay_review", JsonValue::MakeBoolean(deobfuscationEnabled && hasSemanticOverlay));
    object.Set("requires_raw_cfg_fallback_uncertainty", JsonValue::MakeBoolean(deobfuscationEnabled && hasObfuscationFacts && !hasSemanticOverlay));
    object.Set("safe_to_rewrite_obfuscated_cfg", JsonValue::MakeBoolean(deobfuscationEnabled && (!hasObfuscationFacts || highConfidenceSemanticEdgeCount != 0)));
    object.Set("high_confidence_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(highConfidenceSemanticEdgeCount)));
    object.Set("semantic_overlay_confidence_threshold", JsonValue::MakeNumber(0.75));
    return object;
}

void AppendMergeDeobfuscationOutputRule(
    JsonValue& rules,
    const std::string& outputKey,
    const std::vector<std::string>& requirements,
    const std::vector<std::string>& evidencePaths)
{
    JsonValue item = JsonValue::MakeObject();
    item.Set("output_key", JsonValue::MakeString(outputKey));
    item.Set("requirements", BuildStringArray(requirements, 16, nullptr));
    item.Set("evidence_paths", BuildStringArray(evidencePaths, 16, nullptr));
    rules.PushBack(item);
}

JsonValue BuildMergeChunkDeobfuscationOutputContractJson(const AnalyzeRequest& request)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue outputRules = JsonValue::MakeArray();
    std::vector<std::string> requirements;
    std::vector<std::string> evidencePaths;
    size_t highConfidenceSemanticEdgeCount = 0;
    const bool hasDispatchers = !request.Facts.Obfuscation.Dispatchers.empty();
    const bool hasOpaquePredicates = !request.Facts.Obfuscation.OpaquePredicates.empty();
    const bool hasSubstitutionIdioms = !request.Facts.Obfuscation.SubstitutionIdioms.empty();
    const bool hasSemanticOverlay = !request.Facts.SemanticControlFlow.Edges.empty();
    const bool hasObfuscationFacts = hasDispatchers || hasOpaquePredicates || hasSubstitutionIdioms;
    const bool deobfuscationEnabled = request.Facts.DeobfuscationReadiness.Enabled;

    for (const SemanticControlFlowEdge& edge : request.Facts.SemanticControlFlow.Edges)
    {
        if (edge.Confidence >= 0.75)
        {
            ++highConfidenceSemanticEdgeCount;
        }
    }

    const bool safeToRewriteObfuscatedCfg = deobfuscationEnabled && (!hasObfuscationFacts || highConfidenceSemanticEdgeCount != 0);

    if (deobfuscationEnabled)
    {
        requirements.push_back(hasSemanticOverlay ? "prefer_semantic_overlay_structure" : "preserve_raw_cfg_fallback_uncertainty");
        requirements.push_back(hasDispatchers ? "suppress_dispatcher_loop_shape" : "no_dispatcher_rewrite_required");
        requirements.push_back(hasOpaquePredicates ? "prune_only_proven_opaque_dead_edges" : "no_opaque_edge_pruning_required");
        requirements.push_back(hasSubstitutionIdioms ? "apply_local_substitution_simplifications" : "no_substitution_simplification_required");
        requirements.push_back("assign_state_variables_only_to_recovered_state_values");
        requirements.push_back("preserve_helper_call_argument_expressions");
    }
    else
    {
        requirements.push_back("preserve_raw_obfuscated_structure");
        requirements.push_back("do_not_emit_deobfuscated_rewrite");
        requirements.push_back("treat_obfuscation_facts_as_observations_only");
        requirements.push_back("validate_any_explicit_deobfuscated_state_claims");
    }

    evidencePaths.push_back("semantic_control_flow.edges");
    evidencePaths.push_back("obfuscation.dispatchers.recovered_edges");
    evidencePaths.push_back("obfuscation.opaque_predicates");
    evidencePaths.push_back("obfuscation.substitution_idioms");
    evidencePaths.push_back("call_arguments");
    evidencePaths.push_back("ir_values");
    AppendMergeDeobfuscationOutputRule(outputRules, "pseudo_c", requirements, evidencePaths);

    requirements.clear();
    evidencePaths.clear();
    if (deobfuscationEnabled)
    {
        requirements.push_back("summarize_deobfuscated_structure_when_applied");
        requirements.push_back("mention_raw_cfg_fallback_when_rewrite_is_unsafe");
    }
    else
    {
        requirements.push_back("summarize_raw_obfuscated_structure_when_relevant");
        requirements.push_back("mention_deobfuscation_disabled_when_obfuscation_facts_exist");
    }

    evidencePaths.push_back("chunking.merge_deobfuscation_plan.deobfuscation_actions");
    evidencePaths.push_back("chunking.merge_obfuscation_policy.obfuscation_rewrite_rules");
    AppendMergeDeobfuscationOutputRule(outputRules, "summary", requirements, evidencePaths);

    requirements.clear();
    evidencePaths.clear();
    requirements.push_back("carry_unresolved_state_transitions");
    requirements.push_back("carry_low_confidence_semantic_edges");
    requirements.push_back("carry_blocked_deobfuscation_assumptions");
    if (!deobfuscationEnabled)
    {
        requirements.push_back("carry_deobfuscation_disabled_policy");
    }

    evidencePaths.push_back("chunking.merge_deobfuscation_plan.blocked_assumptions");
    evidencePaths.push_back("chunking.merge_obfuscation_policy.obfuscation_uncertainty_rules");
    AppendMergeDeobfuscationOutputRule(outputRules, "uncertainties", requirements, evidencePaths);

    requirements.clear();
    evidencePaths.clear();
    if (deobfuscationEnabled)
    {
        requirements.push_back("cite_obfuscation_or_semantic_overlay_facts_for_rewrites");
        requirements.push_back("drop_evidence_for_blocked_assumptions");
    }
    else
    {
        requirements.push_back("cite_obfuscation_facts_as_observations_only");
        requirements.push_back("avoid_rewrite_evidence_claims");
    }

    evidencePaths.push_back("evidence_graph");
    evidencePaths.push_back("semantic_control_flow.edges");
    evidencePaths.push_back("obfuscation.dispatchers");
    evidencePaths.push_back("obfuscation.opaque_predicates");
    evidencePaths.push_back("obfuscation.substitution_idioms");
    AppendMergeDeobfuscationOutputRule(outputRules, "evidence", requirements, evidencePaths);

    requirements.clear();
    evidencePaths.clear();
    if (deobfuscationEnabled)
    {
        requirements.push_back("cap_confidence_when_deobfuscation_rewrite_is_unsafe");
        requirements.push_back("avoid_high_confidence_for_raw_cfg_fallback");
    }
    else
    {
        requirements.push_back("avoid_confidence_boost_from_deobfuscation");
        requirements.push_back("treat_raw_cfg_preservation_as_policy");
    }

    evidencePaths.push_back("chunking.merge_confidence_policy");
    evidencePaths.push_back("chunking.merge_deobfuscation_plan.safe_to_rewrite_obfuscated_cfg");
    AppendMergeDeobfuscationOutputRule(outputRules, "confidence", requirements, evidencePaths);

    object.Set("enabled", JsonValue::MakeBoolean(deobfuscationEnabled));
    object.Set("mode", JsonValue::MakeString(deobfuscationEnabled ? "on" : "off"));
    object.Set("output_rule_count", JsonValue::MakeNumber(static_cast<double>(outputRules.GetArray().size())));
    object.Set("output_rules", outputRules);
    object.Set("requires_pseudo_c_deobfuscation_review", JsonValue::MakeBoolean(deobfuscationEnabled && hasObfuscationFacts));
    object.Set("requires_deobfuscation_uncertainty", JsonValue::MakeBoolean(deobfuscationEnabled && hasObfuscationFacts && !safeToRewriteObfuscatedCfg));
    object.Set("requires_rewrite_evidence", JsonValue::MakeBoolean(deobfuscationEnabled && hasObfuscationFacts));
    object.Set("safe_to_emit_deobfuscated_structure", JsonValue::MakeBoolean(safeToRewriteObfuscatedCfg));
    object.Set("has_semantic_overlay_evidence", JsonValue::MakeBoolean(hasSemanticOverlay));
    object.Set("high_confidence_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(highConfidenceSemanticEdgeCount)));
    object.Set("semantic_overlay_confidence_threshold", JsonValue::MakeNumber(0.75));
    return object;
}

JsonValue BuildMergeChunkDeobfuscationConflictPolicyJson(const AnalyzeRequest& request)
{
    JsonValue object = JsonValue::MakeObject();
    std::vector<std::string> priorityOrder;
    std::vector<std::string> conflictChecks;
    std::vector<std::string> downgradeReasons;
    std::vector<std::string> requiredEvidencePaths;
    size_t highConfidenceSemanticEdgeCount = 0;
    size_t lowConfidenceSemanticEdgeCount = 0;
    size_t deadSemanticEdgeCount = 0;
    const bool hasDispatchers = !request.Facts.Obfuscation.Dispatchers.empty();
    const bool hasOpaquePredicates = !request.Facts.Obfuscation.OpaquePredicates.empty();
    const bool hasSubstitutionIdioms = !request.Facts.Obfuscation.SubstitutionIdioms.empty();
    const bool hasSemanticOverlay = !request.Facts.SemanticControlFlow.Edges.empty();
    const bool hasObfuscationFacts = hasDispatchers || hasOpaquePredicates || hasSubstitutionIdioms;
    const bool deobfuscationEnabled = request.Facts.DeobfuscationReadiness.Enabled;

    for (const SemanticControlFlowEdge& edge : request.Facts.SemanticControlFlow.Edges)
    {
        if (edge.Confidence >= 0.75)
        {
            ++highConfidenceSemanticEdgeCount;
        }
        else
        {
            ++lowConfidenceSemanticEdgeCount;
        }

        if (edge.Dead)
        {
            ++deadSemanticEdgeCount;
        }
    }

    if (deobfuscationEnabled)
    {
        priorityOrder.push_back("pdb_and_runtime_observations");
        priorityOrder.push_back("high_confidence_semantic_overlay");
        priorityOrder.push_back("obfuscation_recovered_edges");
        priorityOrder.push_back("grounded_chunk_summaries");
        priorityOrder.push_back("raw_control_flow_fallback");

        conflictChecks.push_back("semantic_overlay_vs_raw_successors");
        conflictChecks.push_back("dispatcher_recovered_edges_vs_dispatcher_loop");
        conflictChecks.push_back("opaque_dead_edges_vs_visible_branch_paths");
        conflictChecks.push_back("substitution_simplification_vs_original_expression");
        conflictChecks.push_back("chunk_summary_claims_vs_fact_paths");

        downgradeReasons.push_back("semantic_overlay_missing");
        downgradeReasons.push_back("semantic_overlay_low_confidence");
        downgradeReasons.push_back("dispatcher_edges_unresolved");
        downgradeReasons.push_back("opaque_dead_edge_unproven");
        downgradeReasons.push_back("chunk_summary_conflicts_with_facts");

        requiredEvidencePaths.push_back("semantic_control_flow.edges");
        requiredEvidencePaths.push_back("obfuscation.dispatchers.recovered_edges");
        requiredEvidencePaths.push_back("obfuscation.opaque_predicates");
        requiredEvidencePaths.push_back("obfuscation.substitution_idioms");
        requiredEvidencePaths.push_back("chunking.merge_traceability_matrix");
        requiredEvidencePaths.push_back("chunking.merge_deobfuscation_output_contract");
    }
    else
    {
        priorityOrder.push_back("raw_control_flow_fallback");
        priorityOrder.push_back("obfuscation_facts_as_observations");
        priorityOrder.push_back("grounded_chunk_summaries");

        conflictChecks.push_back("deobfuscation_disabled_policy");

        downgradeReasons.push_back("deobfuscation_disabled_by_option");

        requiredEvidencePaths.push_back("deobfuscation_readiness");
        requiredEvidencePaths.push_back("obfuscation");
        requiredEvidencePaths.push_back("control_flow");
    }

    object.Set("enabled", JsonValue::MakeBoolean(deobfuscationEnabled));
    object.Set("mode", JsonValue::MakeString(deobfuscationEnabled ? "on" : "off"));
    object.Set("requires_conflict_resolution", JsonValue::MakeBoolean(deobfuscationEnabled && (hasObfuscationFacts || hasSemanticOverlay)));
    object.Set("safe_to_prefer_semantic_overlay", JsonValue::MakeBoolean(deobfuscationEnabled && highConfidenceSemanticEdgeCount != 0));
    object.Set("requires_raw_cfg_fallback", JsonValue::MakeBoolean(deobfuscationEnabled && hasObfuscationFacts && highConfidenceSemanticEdgeCount == 0));
    object.Set("requires_uncertainty_on_conflict", JsonValue::MakeBoolean(deobfuscationEnabled && (hasObfuscationFacts || lowConfidenceSemanticEdgeCount != 0)));
    object.Set("priority_order", BuildStringArray(priorityOrder, 16, nullptr));
    object.Set("conflict_checks", BuildStringArray(conflictChecks, 16, nullptr));
    object.Set("confidence_downgrade_reasons", BuildStringArray(downgradeReasons, 16, nullptr));
    object.Set("required_evidence_paths", BuildStringArray(requiredEvidencePaths, 16, nullptr));
    object.Set("dispatcher_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.Dispatchers.size())));
    object.Set("opaque_predicate_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.OpaquePredicates.size())));
    object.Set("substitution_idiom_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.SubstitutionIdioms.size())));
    object.Set("semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(request.Facts.SemanticControlFlow.Edges.size())));
    object.Set("high_confidence_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(highConfidenceSemanticEdgeCount)));
    object.Set("low_confidence_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(lowConfidenceSemanticEdgeCount)));
    object.Set("dead_semantic_edge_count", JsonValue::MakeNumber(static_cast<double>(deadSemanticEdgeCount)));
    object.Set("semantic_overlay_confidence_threshold", JsonValue::MakeNumber(0.75));
    return object;
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
    JsonValue selection = JsonValue::MakeObject();
    bool regionsTruncated = false;
    bool blocksTruncated = false;
    bool directCallsTruncated = false;
    bool indirectCallsTruncated = false;
    bool switchesTruncated = false;
    bool stackPointerTruncated = false;
    bool memoryAccessesTruncated = false;
    bool recoveredArgumentsTruncated = false;
    bool recoveredLocalsTruncated = false;
    bool callArgumentsTruncated = false;
    bool helperCallContractTruncated = false;
    bool valueMergesTruncated = false;
    bool irValuesTruncated = false;
    bool blockValueStatesTruncated = false;
    bool obfuscationTruncated = false;
    bool semanticControlFlowTruncated = false;
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
    bool evidenceGraphTruncated = false;
    bool factsTruncated = false;
    bool uncertaintiesTruncated = false;
    bool uncoveredBlockIdsTruncated = false;
    const std::optional<size_t> middleInstructionIndex = FindMiddleInterestingInstructionIndex(request);
    const std::set<size_t> coveredBlocks = BuildMergeCoveredBlockIndexSet(chunkPlans);

    module.Set("module_name", JsonValue::MakeString(request.Facts.Module.ModuleName));
    module.Set("image_name", JsonValue::MakeString(request.Facts.Module.ImageName));
    module.Set("loaded_image_name", JsonValue::MakeString(request.Facts.Module.LoadedImageName));
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
    selection.Set("fact_strategy", JsonValue::MakeString("ranked high-signal facts + spread sampling"));
    selection.Set("prompt_profile", JsonValue::MakeString("merge_compact_with_helper_call_contract"));
    selection.Set("instruction_window_limit", JsonValue::MakeNumber(static_cast<double>(kPromptInstructionWindowLimit)));
    selection.Set("block_limit", JsonValue::MakeNumber(static_cast<double>(kPromptBlockCompactLimit)));
    selection.Set("helper_call_contract_required", JsonValue::MakeBoolean(true));

    const size_t totalBlockCount = request.Facts.Blocks.size();
    const size_t coveredBlockCount = CountValidMergeCoveredBlocks(coveredBlocks, totalBlockCount);
    const size_t uncoveredBlockCount = totalBlockCount - coveredBlockCount;
    const MergeChunkDiagnostics diagnostics = BuildMergeChunkDiagnostics(request, chunkPlans, chunkAnalyses, uncoveredBlockCount);
    chunking.Set("chunk_count", JsonValue::MakeNumber(static_cast<double>(chunkPlans.size())));
    chunking.Set("chunk_summaries_count", JsonValue::MakeNumber(static_cast<double>(chunkAnalyses.size())));
    chunking.Set("total_block_count", JsonValue::MakeNumber(static_cast<double>(totalBlockCount)));
    chunking.Set("covered_block_count", JsonValue::MakeNumber(static_cast<double>(coveredBlockCount)));
    chunking.Set("uncovered_block_count", JsonValue::MakeNumber(static_cast<double>(uncoveredBlockCount)));
    chunking.Set("coverage_complete", JsonValue::MakeBoolean(uncoveredBlockCount == 0));
    chunking.Set("coverage_ratio", JsonValue::MakeNumber(totalBlockCount == 0 ? 0.0 : static_cast<double>(coveredBlockCount) / static_cast<double>(totalBlockCount)));
    chunking.Set("uncovered_block_ids", BuildMergeUncoveredBlockIdsJson(request, coveredBlocks, &uncoveredBlockIdsTruncated));
    chunking.Set("uncovered_block_ids_truncated", JsonValue::MakeBoolean(uncoveredBlockIdsTruncated));
    chunking.Set("chunk_plans", BuildMergeChunkPlansJson(request, chunkPlans));
    chunking.Set("summary_alignment", BuildMergeChunkSummaryAlignmentJson(diagnostics));
    chunking.Set("summary_quality", BuildMergeChunkSummaryQualityJson(diagnostics));
    chunking.Set("summary_evidence", BuildMergeChunkSummaryEvidenceJson(diagnostics));
    chunking.Set("merge_risk", BuildMergeChunkRiskJson(diagnostics));
    chunking.Set("merge_risk_details", BuildMergeChunkRiskDetailsJson(request, chunkPlans, chunkAnalyses));
    chunking.Set("merge_review_plan", BuildMergeChunkReviewPlanJson(chunkPlans, diagnostics));
    chunking.Set("merge_confidence_policy", BuildMergeChunkConfidencePolicyJson(diagnostics));
    chunking.Set("merge_acceptance_checks", BuildMergeChunkAcceptanceChecksJson(diagnostics));
    chunking.Set("merge_output_contract", BuildMergeChunkOutputContractJson());
    chunking.Set("merge_traceability_matrix", BuildMergeChunkTraceabilityMatrixJson());
    chunking.Set("merge_obfuscation_policy", BuildMergeChunkObfuscationPolicyJson(request));
    chunking.Set("merge_deobfuscation_plan", BuildMergeChunkDeobfuscationPlanJson(request));
    chunking.Set("merge_deobfuscation_output_contract", BuildMergeChunkDeobfuscationOutputContractJson(request));
    chunking.Set("merge_deobfuscation_conflict_policy", BuildMergeChunkDeobfuscationConflictPolicyJson(request));

    root.Set("arch", JsonValue::MakeString(request.Facts.Arch));
    root.Set("mode", JsonValue::MakeString(request.Facts.Mode == AnalysisMode::LiveMemory ? "live" : "file"));
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
    root.Set("selection", selection);
    root.Set("regions", BuildRegionsJson(request, &regionsTruncated));
    root.Set("blocks", BuildBlocksJson(request, &blocksTruncated));
    root.Set("switches", BuildSwitchesJson(request, &switchesTruncated));
    root.Set("instruction_window_head", BuildInstructionWindowJson(request, false));
    root.Set("instruction_window_middle", middleInstructionIndex.has_value() ? BuildInstructionWindowJson(request, middleInstructionIndex.value()) : JsonValue::MakeArray());
    root.Set("instruction_window_tail", BuildInstructionWindowJson(request, true));
    root.Set("direct_calls", BuildCallsJson(request.Facts.Calls, kPromptDirectCallLimit, &directCallsTruncated));
    root.Set("indirect_calls", BuildCallsJson(request.Facts.IndirectCalls, kPromptIndirectCallLimit, &indirectCallsTruncated));
    root.Set("stack_pointer", BuildStackPointerJson(request, &stackPointerTruncated));
    root.Set("memory_accesses", BuildMemoryAccessesJson(request, &memoryAccessesTruncated));
    root.Set("recovered_arguments", BuildRecoveredArgumentsJson(request, &recoveredArgumentsTruncated));
    root.Set("recovered_locals", BuildRecoveredLocalsJson(request, &recoveredLocalsTruncated));
    root.Set("call_arguments", BuildCallArgumentsJson(request, &callArgumentsTruncated));
    root.Set("helper_call_contract", BuildHelperCallContractJson(request, &helperCallContractTruncated));
    root.Set("value_merges", BuildValueMergesJson(request, &valueMergesTruncated));
    root.Set("ir_values", BuildIrValuesJson(request, &irValuesTruncated));
    root.Set("block_value_states", BuildBlockValueStatesJson(request, &blockValueStatesTruncated));
    root.Set("obfuscation", BuildObfuscationJson(request, &obfuscationTruncated));
    root.Set("deobfuscation_readiness", BuildDeobfuscationReadinessJson(request));
    root.Set("semantic_control_flow", BuildSemanticControlFlowJson(request, &semanticControlFlowTruncated));
    root.Set("control_flow", BuildControlFlowJson(request, &controlFlowTruncated));
    root.Set("abi", BuildAbiJson(request, &abiTruncated));
    root.Set("session_policy", BuildSessionPolicyJson(request));
    root.Set("type_hints", BuildTypeHintsJson(request, &typeHintsTruncated));
    root.Set("idioms", BuildIdiomsJson(request, &idiomsTruncated));
    root.Set("callee_summaries", BuildCalleeSummariesJson(request, &calleeSummariesTruncated));
    root.Set("data_references", BuildDataReferencesJson(request, &dataReferencesTruncated));
    root.Set("call_targets", BuildCallTargetsJson(request, &callTargetsTruncated));
    root.Set("normalized_conditions", BuildNormalizedConditionsJson(request, &normalizedConditionsTruncated));
    root.Set("pdb", BuildPdbFactsJson(request, &pdbTruncated));
    root.Set("observed_behavior", BuildObservedBehaviorJson(request, &observedBehaviorTruncated));
    root.Set("evidence_graph", BuildEvidenceGraphJson(request, &evidenceGraphTruncated));
    root.Set("global_facts", BuildStringArray(request.Facts.Facts, 24, &factsTruncated));
    root.Set("global_uncertainties", BuildStringArray(request.Facts.UncertainPoints, 12, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));
    root.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));
    root.Set("chunking", chunking);
    root.Set("chunk_summaries", BuildChunkSummariesJson(chunkAnalyses));

    JsonValue truncation = JsonValue::MakeObject();
    truncation.Set("regions", JsonValue::MakeBoolean(regionsTruncated));
    truncation.Set("blocks", JsonValue::MakeBoolean(blocksTruncated));
    truncation.Set("direct_calls", JsonValue::MakeBoolean(directCallsTruncated));
    truncation.Set("indirect_calls", JsonValue::MakeBoolean(indirectCallsTruncated));
    truncation.Set("switches", JsonValue::MakeBoolean(switchesTruncated));
    truncation.Set("stack_pointer", JsonValue::MakeBoolean(stackPointerTruncated));
    truncation.Set("memory_accesses", JsonValue::MakeBoolean(memoryAccessesTruncated));
    truncation.Set("recovered_arguments", JsonValue::MakeBoolean(recoveredArgumentsTruncated));
    truncation.Set("recovered_locals", JsonValue::MakeBoolean(recoveredLocalsTruncated));
    truncation.Set("call_arguments", JsonValue::MakeBoolean(callArgumentsTruncated));
    truncation.Set("helper_call_contract", JsonValue::MakeBoolean(helperCallContractTruncated));
    truncation.Set("value_merges", JsonValue::MakeBoolean(valueMergesTruncated));
    truncation.Set("ir_values", JsonValue::MakeBoolean(irValuesTruncated));
    truncation.Set("block_value_states", JsonValue::MakeBoolean(blockValueStatesTruncated));
    truncation.Set("obfuscation", JsonValue::MakeBoolean(obfuscationTruncated));
    truncation.Set("semantic_control_flow", JsonValue::MakeBoolean(semanticControlFlowTruncated));
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
    truncation.Set("evidence_graph", JsonValue::MakeBoolean(evidenceGraphTruncated));
    truncation.Set("facts", JsonValue::MakeBoolean(factsTruncated));
    truncation.Set("uncertainties", JsonValue::MakeBoolean(uncertaintiesTruncated));
    root.Set("truncation", truncation);

    return root;
}
}
