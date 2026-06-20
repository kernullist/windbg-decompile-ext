#include "decomp/llm_prompt_facts.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "decomp/string_utils.h"

namespace decomp
{
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
    else if (!request.Facts.Pdb.PrototypeParameters.empty())
    {
        for (const PrototypeParameter& param : request.Facts.Pdb.PrototypeParameters)
        {
            if (param.Type == "..." || param.Name == "varargs")
            {
                continue;
            }

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

    for (size_t index = 0; index < request.Facts.Obfuscation.Dispatchers.size() && index < 4; ++index)
    {
        const ObfuscationDispatcher& dispatcher = request.Facts.Obfuscation.Dispatchers[index];

        if (dispatcher.Confidence < 0.75)
        {
            continue;
        }

        text += "    /* control-flow flattening dispatcher recovered: "
            + dispatcher.HeaderBlock
            + " state "
            + dispatcher.StateVariable
            + " */\n";
    }

    for (size_t index = 0; index < request.Facts.SemanticControlFlow.Edges.size() && index < 12; ++index)
    {
        const SemanticControlFlowEdge& edge = request.Facts.SemanticControlFlow.Edges[index];

        if (edge.Confidence < 0.75)
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
    }

    for (size_t index = 0; index < request.Facts.Obfuscation.OpaquePredicates.size() && index < 6; ++index)
    {
        const OpaquePredicateFact& predicate = request.Facts.Obfuscation.OpaquePredicates[index];

        if (predicate.Confidence < 0.75)
        {
            continue;
        }

        text += "    /* opaque predicate: block="
            + predicate.BlockId;

        if (!predicate.Predicate.empty())
        {
            text += " predicate=" + predicate.Predicate;
        }

        text += " result="
            + predicate.ConstantResult
            + " live="
            + predicate.LiveTargetBlock
            + " dead="
            + predicate.DeadTargetBlock
            + " */\n";
    }

    for (size_t index = 0; index < request.Facts.Obfuscation.SubstitutionIdioms.size() && index < 6; ++index)
    {
        const SubstitutionIdiomFact& idiom = request.Facts.Obfuscation.SubstitutionIdioms[index];

        if (idiom.Confidence >= 0.75)
        {
            text += "    /* substitution: " + idiom.OriginalExpression + " => " + idiom.SimplifiedExpression + " */\n";
        }
    }

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

using InstructionIndex = std::unordered_map<uint64_t, const DisassembledInstruction*>;

InstructionIndex BuildInstructionIndex(const AnalyzeRequest& request)
{
    InstructionIndex index;
    index.reserve(request.Facts.Instructions.size());

    for (const DisassembledInstruction& instruction : request.Facts.Instructions)
    {
        index[instruction.Address] = &instruction;
    }

    return index;
}

const DisassembledInstruction* FindInstructionByAddress(
    const InstructionIndex& index,
    uint64_t address)
{
    const auto found = index.find(address);
    return found == index.end() ? nullptr : found->second;
}

const DisassembledInstruction* FindInstructionByAddress(
    const AnalyzeRequest& request,
    uint64_t address)
{
    const InstructionIndex index = BuildInstructionIndex(request);
    return FindInstructionByAddress(index, address);
}

bool BlockContainsCallKind(
    const InstructionIndex& instructionIndex,
    const BasicBlock& block,
    bool indirectOnly)
{
    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructionIndex, address);

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
    const InstructionIndex& instructionIndex,
    const BasicBlock& block)
{
    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructionIndex, address);

        if (instruction != nullptr && instruction->IsReturn)
        {
            return true;
        }
    }

    return false;
}

bool BlockContainsConditionalBranch(
    const InstructionIndex& instructionIndex,
    const BasicBlock& block)
{
    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructionIndex, address);

        if (instruction != nullptr && instruction->IsConditionalBranch)
        {
            return true;
        }
    }

    return false;
}

size_t CountBlockMemoryAccesses(
    const InstructionIndex& instructionIndex,
    const BasicBlock& block)
{
    size_t count = 0;

    for (uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructionIndex, address);

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

    if (limit == 1)
    {
        indices.push_back(0);
        return indices;
    }

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

template<typename ScoreFn>
std::vector<size_t> SelectRankedSpreadIndices(size_t totalCount, size_t limit, ScoreFn scoreFn)
{
    struct ScoredIndex
    {
        size_t Index = 0;
        double Score = 0.0;
    };

    if (totalCount == 0 || limit == 0)
    {
        return {};
    }

    if (totalCount <= limit)
    {
        return SelectSpreadIndices(totalCount, limit);
    }

    std::vector<size_t> indices;
    std::set<size_t> selected;
    std::vector<ScoredIndex> scored;
    scored.reserve(totalCount);

    for (size_t index = 0; index < totalCount; ++index)
    {
        scored.push_back({ index, scoreFn(index) });
    }

    std::sort(
        scored.begin(),
        scored.end(),
        [](const ScoredIndex& left, const ScoredIndex& right)
        {
            if (left.Score != right.Score)
            {
                return left.Score > right.Score;
            }

            return left.Index < right.Index;
        });

    const size_t rankedBudget = (std::max<size_t>)(1U, limit / 2U);

    for (const ScoredIndex& candidate : scored)
    {
        if (indices.size() >= rankedBudget)
        {
            break;
        }

        if (selected.insert(candidate.Index).second)
        {
            indices.push_back(candidate.Index);
        }
    }

    const std::vector<size_t> spread = SelectSpreadIndices(totalCount, limit);

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

    for (const ScoredIndex& candidate : scored)
    {
        if (indices.size() >= limit)
        {
            break;
        }

        if (selected.insert(candidate.Index).second)
        {
            indices.push_back(candidate.Index);
        }
    }

    std::sort(indices.begin(), indices.end());
    return indices;
}

double ScorePromptCallTarget(const CallTargetInfo& call)
{
    double score = call.Confidence;
    score += call.TailCall ? 1.0 : 0.0;
    score += call.VirtualCall ? 0.9 : 0.0;
    score += call.Indirect ? 0.35 : 0.0;
    score += !call.Parameters.empty() ? 0.45 : 0.0;
    score += !call.TargetExpression.empty() ? 0.35 : 0.0;
    score += !call.MemoryEffects.empty() && call.MemoryEffects != "unknown" ? 0.30 : 0.0;
    score += !call.Prototype.empty() && call.Prototype.find("UNKNOWN_TYPE") == std::string::npos ? 0.25 : 0.0;
    return score;
}

double ScorePromptCalleeSummary(const CalleeSummary& summary)
{
    double score = summary.Confidence;
    score += summary.TailCall ? 0.8 : 0.0;
    score += !summary.Parameters.empty() ? 0.5 : 0.0;
    score += summary.Source == "known_api_model" ? 0.6 : 0.0;
    score += !summary.MemoryEffects.empty() && summary.MemoryEffects != "unknown" ? 0.3 : 0.0;
    score += !summary.Ownership.empty() && summary.Ownership != "unknown" ? 0.2 : 0.0;
    return score;
}

double ScorePromptIrValue(const IrValue& value)
{
    double score = value.Confidence;
    score += value.Kind == "conditional_select" ? 0.8 : 0.0;
    score += value.Kind == "call_result" ? 0.6 : 0.0;
    score += !value.Uses.empty() ? 0.3 : 0.0;
    score += value.IsDead ? -0.35 : 0.0;
    score += value.IsConstant ? -0.05 : 0.0;
    return score;
}

double ScorePromptTypeHint(const TypeRecoveryHint& hint)
{
    double score = hint.Confidence;
    score += hint.Source == "pdb" || hint.Source == "pdb_field" ? 0.8 : 0.0;
    score += hint.Kind.find("vtable") != std::string::npos ? 0.7 : 0.0;
    score += hint.PointerLike ? 0.3 : 0.0;
    score += hint.ArrayLike ? 0.3 : 0.0;
    score += hint.EnumLike || hint.BitflagLike ? 0.25 : 0.0;
    return score;
}

double ScorePromptSwitch(const SwitchInfo& info)
{
    double score = 0.0;
    score += info.CaseCount != 0 ? 0.4 : 0.0;
    score += !info.CaseTargets.empty() ? 0.7 : 0.0;
    score += info.RangeKnown ? 0.35 : 0.0;
    score += info.DefaultTarget != 0 ? 0.35 : 0.0;
    return score;
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
    const InstructionIndex instructionIndex = BuildInstructionIndex(request);
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

        if (BlockContainsCallKind(instructionIndex, block, false))
        {
            score += 280;
        }

        if (BlockContainsCallKind(instructionIndex, block, true))
        {
            score += 320;
        }

        if (block.Successors.size() >= 2)
        {
            score += 180;
        }

        if (BlockContainsConditionalBranch(instructionIndex, block))
        {
            score += 140;
        }

        if (BlockContainsReturn(instructionIndex, block))
        {
            score += 160;
        }

        const size_t memoryAccessCount = CountBlockMemoryAccesses(instructionIndex, block);
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

bool IsChunkScopedObfuscationFact(const std::string& fact)
{
    return StartsWithInsensitive(fact, "obfuscation dispatcher:")
        || StartsWithInsensitive(fact, "obfuscation recovered edge:")
        || StartsWithInsensitive(fact, "obfuscation opaque predicate:")
        || StartsWithInsensitive(fact, "obfuscation substitution:");
}

bool ChunkFactReferencesBlock(const std::string& fact, const std::string& blockId)
{
    if (blockId.empty())
    {
        return false;
    }

    const std::vector<std::string> fields = {
        "header",
        "source",
        "target",
        "dispatcher",
        "block",
        "live",
        "dead"
    };

    for (const std::string& field : fields)
    {
        const std::string marker = field + "=" + blockId;
        const size_t position = fact.find(marker);

        if (position == std::string::npos)
        {
            continue;
        }

        const size_t end = position + marker.size();

        if (end == fact.size() || fact[end] == ',')
        {
            return true;
        }
    }

    return false;
}

bool ChunkFactReferencesAnyBlock(const std::string& fact, const std::set<std::string>& blockIds)
{
    for (const std::string& blockId : blockIds)
    {
        if (ChunkFactReferencesBlock(fact, blockId))
        {
            return true;
        }
    }

    return false;
}

JsonValue BuildChunkScopedStringArrayJson(
    const std::vector<std::string>& values,
    const std::set<std::string>& blockIds,
    size_t limit,
    bool* truncated)
{
    std::vector<std::string> filteredValues;
    bool filteredOut = false;

    for (const std::string& value : values)
    {
        if (!IsChunkScopedObfuscationFact(value) || ChunkFactReferencesAnyBlock(value, blockIds))
        {
            filteredValues.push_back(value);
        }
        else
        {
            filteredOut = true;
        }
    }

    bool arrayTruncated = false;
    JsonValue array = BuildStringArray(filteredValues, limit, &arrayTruncated);

    if (truncated != nullptr)
    {
        *truncated = filteredOut || arrayTruncated;
    }

    return array;
}

JsonValue BuildChunkGlobalFactsJson(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    size_t limit,
    bool* truncated)
{
    return BuildChunkScopedStringArrayJson(request.Facts.Facts, blockIds, limit, truncated);
}

JsonValue BuildChunkGlobalUncertaintiesJson(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    size_t limit,
    bool* truncated)
{
    return BuildChunkScopedStringArrayJson(request.Facts.UncertainPoints, blockIds, limit, truncated);
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
    const InstructionIndex instructionByAddress = BuildInstructionIndex(request);
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

        for (size_t instructionOffset = 0; instructionOffset < headCount; ++instructionOffset)
        {
            const DisassembledInstruction* instruction = FindInstructionByAddress(instructionByAddress, block.InstructionAddresses[instructionOffset]);

            if (instruction != nullptr)
            {
                instructionHeadSample.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instruction)));
            }
        }

        if (block.InstructionAddresses.size() > tailCount)
        {
            for (size_t instructionOffset = block.InstructionAddresses.size() - tailCount; instructionOffset < block.InstructionAddresses.size(); ++instructionOffset)
            {
                const DisassembledInstruction* instruction = FindInstructionByAddress(instructionByAddress, block.InstructionAddresses[instructionOffset]);

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
        item.Set("memory_access_count", JsonValue::MakeNumber(static_cast<double>(CountBlockMemoryAccesses(instructionByAddress, block))));
        item.Set("has_direct_call", JsonValue::MakeBoolean(BlockContainsCallKind(instructionByAddress, block, false)));
        item.Set("has_indirect_call", JsonValue::MakeBoolean(BlockContainsCallKind(instructionByAddress, block, true)));
        item.Set("has_return", JsonValue::MakeBoolean(BlockContainsReturn(instructionByAddress, block)));
        item.Set("has_conditional_branch", JsonValue::MakeBoolean(BlockContainsConditionalBranch(instructionByAddress, block)));
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
    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        request.Facts.Switches.size(),
        kPromptSwitchLimit,
        [&request](size_t index)
        {
            return ScorePromptSwitch(request.Facts.Switches[index]);
        });

    if (truncated != nullptr)
    {
        *truncated = request.Facts.Switches.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const SwitchInfo& info = request.Facts.Switches[index];
        JsonValue item = JsonValue::MakeObject();
        JsonValue targets = JsonValue::MakeArray();

        for (size_t targetIndex = 0; targetIndex < info.CaseTargets.size() && targetIndex < 32; ++targetIndex)
        {
            targets.PushBack(JsonValue::MakeString(HexU64(info.CaseTargets[targetIndex])));
        }

        item.Set("site", JsonValue::MakeString(HexU64(info.Site)));
        item.Set("table_address", JsonValue::MakeString(HexU64(info.TableAddress)));
        item.Set("case_count", JsonValue::MakeNumber(static_cast<double>(info.CaseCount)));
        item.Set("default_target", JsonValue::MakeString(HexU64(info.DefaultTarget)));
        item.Set("range_min", JsonValue::MakeString(HexS64(info.RangeMin)));
        item.Set("range_max", JsonValue::MakeString(HexS64(info.RangeMax)));
        item.Set("range_known", JsonValue::MakeBoolean(info.RangeKnown));
        item.Set("signed_index", JsonValue::MakeBoolean(info.SignedIndex));
        item.Set("detail", JsonValue::MakeString(info.Detail));
        item.Set("index_expression", JsonValue::MakeString(info.IndexExpression));
        item.Set("case_targets", targets);
        item.Set("case_targets_truncated", JsonValue::MakeBoolean(info.CaseTargets.size() > 32));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildMemoryAccessesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const InstructionIndex instructionByAddress = BuildInstructionIndex(request);
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
        item.Set("implicit", JsonValue::MakeBoolean(access.Implicit));
        item.Set("semantic", JsonValue::MakeString(access.Semantic));
        item.Set("stack_frame_relative", JsonValue::MakeBoolean(access.StackFrameRelative));
        item.Set("frame_base", JsonValue::MakeString(access.FrameBase));
        item.Set("frame_offset", JsonValue::MakeString(HexS64(access.FrameOffset)));
        item.Set("stack_pointer_delta", JsonValue::MakeString(HexS64(access.StackPointerDelta)));
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructionByAddress, access.Site);
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
        item.Set("raw_base_register", JsonValue::MakeString(local.RawBaseRegister));
        item.Set("raw_offset", JsonValue::MakeString(HexS64(local.RawOffset)));
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

JsonValue BuildStackPointerJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.StackPointer.size(), kPromptStackPointerLimit);

    if (truncated != nullptr)
    {
        *truncated = request.Facts.StackPointer.size() > indices.size();
    }

    for (size_t index : indices)
    {
        const StackPointerFact& fact = request.Facts.StackPointer[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(fact.Site)));
        item.Set("delta_before", JsonValue::MakeString(HexS64(fact.DeltaBefore)));
        item.Set("delta_after", JsonValue::MakeString(HexS64(fact.DeltaAfter)));
        item.Set("frame_pointer_delta", JsonValue::MakeString(HexS64(fact.FramePointerDelta)));
        item.Set("known", JsonValue::MakeBoolean(fact.Known));
        item.Set("frame_pointer_known", JsonValue::MakeBoolean(fact.FramePointerKnown));
        item.Set("confidence", JsonValue::MakeNumber(fact.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildStackPointerJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.StackPointer.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.StackPointer[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    const std::vector<size_t> indices = SelectSpreadIndices(filteredIndices.size(), kPromptStackPointerLimit);

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > indices.size();
    }

    for (size_t relativeIndex : indices)
    {
        const size_t index = filteredIndices[relativeIndex];
        const StackPointerFact& fact = request.Facts.StackPointer[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(fact.Site)));
        item.Set("delta_before", JsonValue::MakeString(HexS64(fact.DeltaBefore)));
        item.Set("delta_after", JsonValue::MakeString(HexS64(fact.DeltaAfter)));
        item.Set("frame_pointer_delta", JsonValue::MakeString(HexS64(fact.FramePointerDelta)));
        item.Set("known", JsonValue::MakeBoolean(fact.Known));
        item.Set("frame_pointer_known", JsonValue::MakeBoolean(fact.FramePointerKnown));
        item.Set("confidence", JsonValue::MakeNumber(fact.Confidence));
        array.PushBack(item);
    }

    return array;
}

struct CallArgumentPromptGroup
{
    uint64_t Site = 0;
    std::vector<size_t> ArgumentIndices;
};

JsonValue BuildCallArgumentJsonItem(const CallArgumentFact& argument)
{
    JsonValue item = JsonValue::MakeObject();
    item.Set("ordinal", JsonValue::MakeNumber(static_cast<double>(argument.Ordinal)));
    item.Set("location", JsonValue::MakeString(argument.Location));
    item.Set("expression", JsonValue::MakeString(argument.Expression));
    item.Set("type_hint", JsonValue::MakeString(argument.TypeHint));
    item.Set("source", JsonValue::MakeString(argument.Source));
    item.Set("confidence", JsonValue::MakeNumber(argument.Confidence));
    return item;
}

JsonValue BuildPrototypeParametersJson(const std::vector<PrototypeParameter>& parameters, size_t limit, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const size_t count = (std::min)(parameters.size(), limit);

    if (truncated != nullptr)
    {
        *truncated = parameters.size() > count;
    }

    for (size_t index = 0; index < count; ++index)
    {
        const PrototypeParameter& parameter = parameters[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("ordinal", JsonValue::MakeNumber(static_cast<double>(parameter.Ordinal)));
        item.Set("name", JsonValue::MakeString(parameter.Name));
        item.Set("type", JsonValue::MakeString(parameter.Type));
        item.Set("location", JsonValue::MakeString(parameter.Location));
        item.Set("confidence", JsonValue::MakeNumber(parameter.Confidence));
        array.PushBack(item);
    }

    return array;
}

std::vector<CallArgumentPromptGroup> BuildCallArgumentPromptGroups(
    const AnalyzeRequest& request,
    const std::set<uint64_t>* instructionAddresses)
{
    std::vector<CallArgumentPromptGroup> groups;

    for (size_t index = 0; index < request.Facts.CallArguments.size(); ++index)
    {
        const CallArgumentFact& argument = request.Facts.CallArguments[index];

        if (instructionAddresses != nullptr && instructionAddresses->find(argument.Site) == instructionAddresses->end())
        {
            continue;
        }

        auto groupIt = std::find_if(
            groups.begin(),
            groups.end(),
            [&argument](const CallArgumentPromptGroup& group)
            {
                return group.Site == argument.Site;
            });

        if (groupIt == groups.end())
        {
            CallArgumentPromptGroup group;
            group.Site = argument.Site;
            groups.push_back(std::move(group));
            groupIt = groups.end() - 1;
        }

        groupIt->ArgumentIndices.push_back(index);
    }

    return groups;
}

JsonValue BuildCallArgumentGroupsJson(
    const AnalyzeRequest& request,
    const std::vector<CallArgumentPromptGroup>& groups,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(groups.size(), kPromptCallArgumentLimit);

    if (truncated != nullptr)
    {
        *truncated = groups.size() > sampled.size();
    }

    for (size_t relativeIndex : sampled)
    {
        const CallArgumentPromptGroup& group = groups[relativeIndex];
        JsonValue item = JsonValue::MakeObject();
        JsonValue arguments = JsonValue::MakeArray();

        item.Set("site", JsonValue::MakeString(HexU64(group.Site)));
        item.Set("argument_count", JsonValue::MakeNumber(static_cast<double>(group.ArgumentIndices.size())));

        for (const size_t argumentIndex : group.ArgumentIndices)
        {
            arguments.PushBack(BuildCallArgumentJsonItem(request.Facts.CallArguments[argumentIndex]));
        }

        item.Set("arguments", arguments);
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildCallArgumentsJson(const AnalyzeRequest& request, bool* truncated)
{
    return BuildCallArgumentGroupsJson(request, BuildCallArgumentPromptGroups(request, nullptr), truncated);
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
    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        request.Facts.IrValues.size(),
        kPromptIrValueLimit,
        [&request](size_t index)
        {
            return ScorePromptIrValue(request.Facts.IrValues[index]);
        });

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

JsonValue BuildIrValuesJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.IrValues.size(); ++index)
    {
        if (blockIds.find(request.Facts.IrValues[index].BlockId) != blockIds.end())
        {
            filteredIndices.push_back(index);
        }
    }

    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        filteredIndices.size(),
        kPromptIrValueLimit,
        [&request, &filteredIndices](size_t relativeIndex)
        {
            return ScorePromptIrValue(request.Facts.IrValues[filteredIndices[relativeIndex]]);
        });

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > indices.size();
    }

    for (size_t relativeIndex : indices)
    {
        const size_t index = filteredIndices[relativeIndex];
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

JsonValue BuildReachingValuesJson(const std::vector<ReachingValue>& values, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    const size_t count = values.size() < kPromptBlockValueEntryLimit ? values.size() : kPromptBlockValueEntryLimit;

    if (truncated != nullptr)
    {
        *truncated = values.size() > count;
    }

    for (size_t index = 0; index < count; ++index)
    {
        const ReachingValue& value = values[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(value.Name));
        item.Set("value_id", JsonValue::MakeString(value.ValueId));
        item.Set("canonical", JsonValue::MakeString(value.Canonical));
        item.Set("storage", JsonValue::MakeString(value.Storage));
        item.Set("confidence", JsonValue::MakeNumber(value.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildBlockValueStatesJson(const AnalyzeRequest& request, bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    bool anyTruncated = false;
    const std::vector<size_t> indices = SelectSpreadIndices(request.Facts.BlockValueStates.size(), kPromptBlockValueStateLimit);

    if (request.Facts.BlockValueStates.size() > indices.size())
    {
        anyTruncated = true;
    }

    for (size_t index : indices)
    {
        const BlockValueState& state = request.Facts.BlockValueStates[index];
        bool liveInTruncated = false;
        bool liveOutTruncated = false;
        JsonValue item = JsonValue::MakeObject();
        item.Set("block_id", JsonValue::MakeString(state.BlockId));
        item.Set("live_in", BuildReachingValuesJson(state.LiveIn, &liveInTruncated));
        item.Set("live_out", BuildReachingValuesJson(state.LiveOut, &liveOutTruncated));
        item.Set("converged", JsonValue::MakeBoolean(state.Converged));
        item.Set("confidence", JsonValue::MakeNumber(state.Confidence));
        array.PushBack(item);
        anyTruncated = anyTruncated || liveInTruncated || liveOutTruncated;
    }

    if (truncated != nullptr)
    {
        *truncated = anyTruncated;
    }

    return array;
}

JsonValue BuildBlockValueStatesJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    std::vector<size_t> filteredIndices;
    bool anyTruncated = false;

    for (size_t index = 0; index < request.Facts.BlockValueStates.size(); ++index)
    {
        if (blockIds.find(request.Facts.BlockValueStates[index].BlockId) != blockIds.end())
        {
            filteredIndices.push_back(index);
        }
    }

    const std::vector<size_t> indices = SelectSpreadIndices(filteredIndices.size(), kPromptBlockValueStateLimit);

    if (filteredIndices.size() > indices.size())
    {
        anyTruncated = true;
    }

    for (size_t relativeIndex : indices)
    {
        const size_t index = filteredIndices[relativeIndex];
        const BlockValueState& state = request.Facts.BlockValueStates[index];
        bool liveInTruncated = false;
        bool liveOutTruncated = false;
        JsonValue item = JsonValue::MakeObject();
        item.Set("block_id", JsonValue::MakeString(state.BlockId));
        item.Set("live_in", BuildReachingValuesJson(state.LiveIn, &liveInTruncated));
        item.Set("live_out", BuildReachingValuesJson(state.LiveOut, &liveOutTruncated));
        item.Set("converged", JsonValue::MakeBoolean(state.Converged));
        item.Set("confidence", JsonValue::MakeNumber(state.Confidence));
        array.PushBack(item);
        anyTruncated = anyTruncated || liveInTruncated || liveOutTruncated;
    }

    if (truncated != nullptr)
    {
        *truncated = anyTruncated;
    }

    return array;
}

bool IsPromptBlockSelected(const std::set<std::string>* blockIds, const std::string& blockId)
{
    return blockIds == nullptr
        || (!blockId.empty() && blockIds->find(blockId) != blockIds->end());
}

bool IsPromptAnyBlockSelected(const std::set<std::string>* blockIds, const std::vector<std::string>& values)
{
    if (blockIds == nullptr)
    {
        return true;
    }

    for (const std::string& blockId : values)
    {
        if (IsPromptBlockSelected(blockIds, blockId))
        {
            return true;
        }
    }

    return false;
}

std::string FindPromptBlockIdContainingAddress(const AnalyzeRequest& request, uint64_t address)
{
    for (const BasicBlock& block : request.Facts.Blocks)
    {
        if (address >= block.StartAddress && address < block.EndAddress)
        {
            return block.Id;
        }
    }

    return std::string();
}

bool IsPromptSiteSelected(const AnalyzeRequest& request, const std::set<std::string>* blockIds, uint64_t site)
{
    if (blockIds == nullptr)
    {
        return true;
    }

    if (site == 0)
    {
        return false;
    }

    return IsPromptBlockSelected(blockIds, FindPromptBlockIdContainingAddress(request, site));
}

bool IsPromptRecoveredEdgeSelected(const std::set<std::string>* blockIds, const RecoveredControlFlowEdge& edge)
{
    return IsPromptBlockSelected(blockIds, edge.SourceBlock)
        || IsPromptBlockSelected(blockIds, edge.TargetBlock);
}

bool IsPromptDispatcherSelected(const std::set<std::string>* blockIds, const ObfuscationDispatcher& dispatcher)
{
    if (blockIds == nullptr)
    {
        return true;
    }

    if (IsPromptBlockSelected(blockIds, dispatcher.HeaderBlock)
        || IsPromptAnyBlockSelected(blockIds, dispatcher.DispatcherBlocks)
        || IsPromptAnyBlockSelected(blockIds, dispatcher.OriginalBlockCandidates))
    {
        return true;
    }

    for (const RecoveredControlFlowEdge& edge : dispatcher.RecoveredEdges)
    {
        if (IsPromptRecoveredEdgeSelected(blockIds, edge))
        {
            return true;
        }
    }

    return false;
}

bool IsPromptOpaquePredicateSelected(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    const OpaquePredicateFact& predicate)
{
    return IsPromptBlockSelected(blockIds, predicate.BlockId)
        || IsPromptBlockSelected(blockIds, predicate.LiveTargetBlock)
        || IsPromptBlockSelected(blockIds, predicate.DeadTargetBlock)
        || IsPromptSiteSelected(request, blockIds, predicate.Site);
}

bool IsPromptSubstitutionIdiomSelected(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    const SubstitutionIdiomFact& idiom)
{
    return IsPromptBlockSelected(blockIds, idiom.BlockId)
        || IsPromptSiteSelected(request, blockIds, idiom.Site);
}

bool IsPromptSemanticEdgeSelected(const std::set<std::string>* blockIds, const SemanticControlFlowEdge& edge)
{
    return IsPromptBlockSelected(blockIds, edge.SourceBlock)
        || IsPromptBlockSelected(blockIds, edge.TargetBlock);
}

bool IsPromptControlFlowRegionSelected(const std::set<std::string>* blockIds, const ControlFlowRegion& region)
{
    return IsPromptBlockSelected(blockIds, region.HeaderBlock)
        || IsPromptAnyBlockSelected(blockIds, region.BodyBlocks)
        || IsPromptAnyBlockSelected(blockIds, region.LatchBlocks)
        || IsPromptAnyBlockSelected(blockIds, region.ExitBlocks);
}

JsonValue BuildObfuscationJson(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue stateVariables = JsonValue::MakeArray();
    JsonValue dispatchers = JsonValue::MakeArray();
    JsonValue opaquePredicates = JsonValue::MakeArray();
    JsonValue substitutionIdioms = JsonValue::MakeArray();
    bool anyTruncated = false;
    std::vector<size_t> filteredDispatcherIndices;
    std::set<std::string> selectedStateVariables;

    for (size_t index = 0; index < request.Facts.Obfuscation.Dispatchers.size(); ++index)
    {
        const ObfuscationDispatcher& dispatcher = request.Facts.Obfuscation.Dispatchers[index];

        if (IsPromptDispatcherSelected(blockIds, dispatcher))
        {
            filteredDispatcherIndices.push_back(index);

            if (!dispatcher.StateVariable.empty())
            {
                selectedStateVariables.insert(dispatcher.StateVariable);
            }
        }
    }

    std::vector<size_t> filteredStateVariableIndices;

    for (size_t index = 0; index < request.Facts.Obfuscation.StateVariables.size(); ++index)
    {
        const ObfuscationStateVariable& variable = request.Facts.Obfuscation.StateVariables[index];

        if (blockIds == nullptr
            || selectedStateVariables.find(variable.Name) != selectedStateVariables.end()
            || IsPromptSiteSelected(request, blockIds, variable.FirstSite))
        {
            filteredStateVariableIndices.push_back(index);
        }
    }

    const std::vector<size_t> stateVariableIndices = SelectSpreadIndices(
        filteredStateVariableIndices.size(),
        kPromptObfuscationStateVariableLimit);

    if (filteredStateVariableIndices.size() > stateVariableIndices.size())
    {
        anyTruncated = true;
    }

    for (size_t relativeIndex : stateVariableIndices)
    {
        const size_t index = filteredStateVariableIndices[relativeIndex];
        const ObfuscationStateVariable& variable = request.Facts.Obfuscation.StateVariables[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("name", JsonValue::MakeString(variable.Name));
        item.Set("storage", JsonValue::MakeString(variable.Storage));
        item.Set("first_site", JsonValue::MakeString(HexU64(variable.FirstSite)));
        item.Set("read_count", JsonValue::MakeNumber(static_cast<double>(variable.ReadCount)));
        item.Set("write_count", JsonValue::MakeNumber(static_cast<double>(variable.WriteCount)));
        item.Set("confidence", JsonValue::MakeNumber(variable.Confidence));
        stateVariables.PushBack(item);
    }

    const std::vector<size_t> dispatcherIndices = SelectRankedSpreadIndices(
        filteredDispatcherIndices.size(),
        kPromptObfuscationDispatcherLimit,
        [&request, &filteredDispatcherIndices](size_t relativeIndex)
        {
            const size_t index = filteredDispatcherIndices[relativeIndex];
            return request.Facts.Obfuscation.Dispatchers[index].Confidence;
        });

    if (filteredDispatcherIndices.size() > dispatcherIndices.size())
    {
        anyTruncated = true;
    }

    for (size_t relativeIndex : dispatcherIndices)
    {
        const size_t index = filteredDispatcherIndices[relativeIndex];
        const ObfuscationDispatcher& dispatcher = request.Facts.Obfuscation.Dispatchers[index];
        JsonValue item = JsonValue::MakeObject();
        JsonValue recoveredEdges = JsonValue::MakeArray();
        bool edgesTruncated = false;
        std::vector<size_t> filteredEdgeIndices;

        for (size_t edgeIndex = 0; edgeIndex < dispatcher.RecoveredEdges.size(); ++edgeIndex)
        {
            if (IsPromptRecoveredEdgeSelected(blockIds, dispatcher.RecoveredEdges[edgeIndex]))
            {
                filteredEdgeIndices.push_back(edgeIndex);
            }
        }

        const std::vector<size_t> edgeIndices = SelectSpreadIndices(
            filteredEdgeIndices.size(),
            kPromptObfuscationEdgeLimit);

        if (filteredEdgeIndices.size() > edgeIndices.size())
        {
            edgesTruncated = true;
            anyTruncated = true;
        }

        for (size_t relativeEdgeIndex : edgeIndices)
        {
            const size_t edgeIndex = filteredEdgeIndices[relativeEdgeIndex];
            const RecoveredControlFlowEdge& edge = dispatcher.RecoveredEdges[edgeIndex];
            JsonValue edgeItem = JsonValue::MakeObject();
            edgeItem.Set("source_block", JsonValue::MakeString(edge.SourceBlock));
            edgeItem.Set("target_block", JsonValue::MakeString(edge.TargetBlock));
            edgeItem.Set("condition", JsonValue::MakeString(edge.Condition));
            edgeItem.Set("state_value", JsonValue::MakeString(edge.StateValue));
            edgeItem.Set("evidence", JsonValue::MakeString(edge.Evidence));
            edgeItem.Set("conditional", JsonValue::MakeBoolean(edge.Conditional));
            edgeItem.Set("confidence", JsonValue::MakeNumber(edge.Confidence));
            recoveredEdges.PushBack(edgeItem);
        }

        item.Set("header_block", JsonValue::MakeString(dispatcher.HeaderBlock));
        item.Set("kind", JsonValue::MakeString(dispatcher.Kind));
        item.Set("state_variable", JsonValue::MakeString(dispatcher.StateVariable));
        item.Set("dispatcher_blocks", BuildStringArray(dispatcher.DispatcherBlocks, 12, nullptr));
        item.Set("original_block_candidates", BuildStringArray(dispatcher.OriginalBlockCandidates, 24, nullptr));
        item.Set("recovered_edges", recoveredEdges);
        item.Set("recovered_edges_truncated", JsonValue::MakeBoolean(edgesTruncated));
        item.Set("evidence", JsonValue::MakeString(dispatcher.Evidence));
        item.Set("confidence", JsonValue::MakeNumber(dispatcher.Confidence));
        dispatchers.PushBack(item);
    }

    std::vector<size_t> filteredPredicateIndices;

    for (size_t index = 0; index < request.Facts.Obfuscation.OpaquePredicates.size(); ++index)
    {
        if (IsPromptOpaquePredicateSelected(request, blockIds, request.Facts.Obfuscation.OpaquePredicates[index]))
        {
            filteredPredicateIndices.push_back(index);
        }
    }

    const std::vector<size_t> predicateIndices = SelectRankedSpreadIndices(
        filteredPredicateIndices.size(),
        kPromptObfuscationPredicateLimit,
        [&request, &filteredPredicateIndices](size_t relativeIndex)
        {
            const size_t index = filteredPredicateIndices[relativeIndex];
            return request.Facts.Obfuscation.OpaquePredicates[index].Confidence;
        });

    if (filteredPredicateIndices.size() > predicateIndices.size())
    {
        anyTruncated = true;
    }

    for (size_t relativeIndex : predicateIndices)
    {
        const size_t index = filteredPredicateIndices[relativeIndex];
        const OpaquePredicateFact& predicate = request.Facts.Obfuscation.OpaquePredicates[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(predicate.Site)));
        item.Set("block_id", JsonValue::MakeString(predicate.BlockId));
        item.Set("predicate", JsonValue::MakeString(predicate.Predicate));
        item.Set("constant_result", JsonValue::MakeString(predicate.ConstantResult));
        item.Set("dead_target_block", JsonValue::MakeString(predicate.DeadTargetBlock));
        item.Set("live_target_block", JsonValue::MakeString(predicate.LiveTargetBlock));
        item.Set("evidence", JsonValue::MakeString(predicate.Evidence));
        item.Set("confidence", JsonValue::MakeNumber(predicate.Confidence));
        opaquePredicates.PushBack(item);
    }

    std::vector<size_t> filteredSubstitutionIndices;

    for (size_t index = 0; index < request.Facts.Obfuscation.SubstitutionIdioms.size(); ++index)
    {
        if (IsPromptSubstitutionIdiomSelected(request, blockIds, request.Facts.Obfuscation.SubstitutionIdioms[index]))
        {
            filteredSubstitutionIndices.push_back(index);
        }
    }

    const std::vector<size_t> substitutionIndices = SelectRankedSpreadIndices(
        filteredSubstitutionIndices.size(),
        kPromptObfuscationSubstitutionLimit,
        [&request, &filteredSubstitutionIndices](size_t relativeIndex)
        {
            const size_t index = filteredSubstitutionIndices[relativeIndex];
            return request.Facts.Obfuscation.SubstitutionIdioms[index].Confidence;
        });

    if (filteredSubstitutionIndices.size() > substitutionIndices.size())
    {
        anyTruncated = true;
    }

    for (size_t relativeIndex : substitutionIndices)
    {
        const size_t index = filteredSubstitutionIndices[relativeIndex];
        const SubstitutionIdiomFact& idiom = request.Facts.Obfuscation.SubstitutionIdioms[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(idiom.Site)));
        item.Set("block_id", JsonValue::MakeString(idiom.BlockId));
        item.Set("original_expression", JsonValue::MakeString(idiom.OriginalExpression));
        item.Set("simplified_expression", JsonValue::MakeString(idiom.SimplifiedExpression));
        item.Set("pattern", JsonValue::MakeString(idiom.Pattern));
        item.Set("evidence", JsonValue::MakeString(idiom.Evidence));
        item.Set("confidence", JsonValue::MakeNumber(idiom.Confidence));
        substitutionIdioms.PushBack(item);
    }

    bool notesTruncated = false;
    object.Set("state_variables", stateVariables);
    object.Set("dispatchers", dispatchers);
    object.Set("opaque_predicates", opaquePredicates);
    object.Set("substitution_idioms", substitutionIdioms);
    object.Set("notes", BuildStringArray(request.Facts.Obfuscation.Notes, kPromptObfuscationNoteLimit, &notesTruncated));
    object.Set("confidence", JsonValue::MakeNumber(request.Facts.Obfuscation.Confidence));
    object.Set("scope", JsonValue::MakeString(blockIds == nullptr ? "function" : "chunk"));
    object.Set(
        "usage_guidance",
        JsonValue::MakeString("Prefer high-confidence recovered_edges over raw dispatcher loop edges; use opaque_predicates only for proven dead edges; use substitution_idioms only as local simplification evidence; preserve uncertainty for unresolved state transitions."));

    if (truncated != nullptr)
    {
        *truncated = anyTruncated || notesTruncated;
    }

    return object;
}

JsonValue BuildObfuscationJson(const AnalyzeRequest& request, bool* truncated)
{
    return BuildObfuscationJson(request, nullptr, truncated);
}

JsonValue BuildObfuscationJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    return BuildObfuscationJson(request, &blockIds, truncated);
}

JsonValue BuildDeobfuscationReadinessJson(const AnalyzeRequest& request)
{
    const DeobfuscationReadiness& readiness = request.Facts.DeobfuscationReadiness;
    JsonValue object = JsonValue::MakeObject();
    object.Set("enabled", JsonValue::MakeBoolean(readiness.Enabled));
    object.Set("mode", JsonValue::MakeString(readiness.Enabled ? "on" : "off"));
    object.Set("has_obfuscation_facts", JsonValue::MakeBoolean(readiness.HasObfuscationFacts));
    object.Set("has_flattening_dispatcher", JsonValue::MakeBoolean(readiness.HasFlatteningDispatcher));
    object.Set("has_high_confidence_dispatcher_edges", JsonValue::MakeBoolean(readiness.HasHighConfidenceDispatcherEdges));
    object.Set("has_opaque_dead_edges", JsonValue::MakeBoolean(readiness.HasOpaqueDeadEdges));
    object.Set("has_substitution_idioms", JsonValue::MakeBoolean(readiness.HasSubstitutionIdioms));
    object.Set("safe_to_rewrite_control_flow", JsonValue::MakeBoolean(readiness.SafeToRewriteControlFlow));
    object.Set("requires_raw_cfg_fallback_uncertainty", JsonValue::MakeBoolean(readiness.RequiresRawCfgFallbackUncertainty));
    object.Set("dispatcher_count", JsonValue::MakeNumber(static_cast<double>(readiness.DispatcherCount)));
    object.Set("recovered_edge_count", JsonValue::MakeNumber(static_cast<double>(readiness.RecoveredEdgeCount)));
    object.Set("opaque_dead_edge_count", JsonValue::MakeNumber(static_cast<double>(readiness.OpaqueDeadEdgeCount)));
    object.Set("substitution_idiom_count", JsonValue::MakeNumber(static_cast<double>(readiness.SubstitutionIdiomCount)));
    object.Set("safe_actions", BuildStringArray(readiness.SafeActions, 16, nullptr));
    object.Set("blocked_assumptions", BuildStringArray(readiness.BlockedAssumptions, 16, nullptr));
    object.Set("priority_fact_paths", BuildStringArray(readiness.PriorityFactPaths, 16, nullptr));
    object.Set("confidence", JsonValue::MakeNumber(readiness.Confidence));
    if (readiness.Enabled)
    {
        object.Set(
            "usage_guidance",
            JsonValue::MakeString("Use safe_actions only when the corresponding priority_fact_paths are present; keep blocked_assumptions as uncertainty instead of inventing deobfuscated control flow."));
    }
    else
    {
        object.Set(
            "usage_guidance",
            JsonValue::MakeString("Deobfuscation is disabled by command option; keep obfuscation facts as evidence, preserve raw CFG shape, and do not apply safe_actions as rewrites."));
    }

    return object;
}

JsonValue BuildSemanticControlFlowJson(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue edges = JsonValue::MakeArray();
    bool notesTruncated = false;
    std::vector<size_t> filteredEdgeIndices;

    for (size_t index = 0; index < request.Facts.SemanticControlFlow.Edges.size(); ++index)
    {
        if (IsPromptSemanticEdgeSelected(blockIds, request.Facts.SemanticControlFlow.Edges[index]))
        {
            filteredEdgeIndices.push_back(index);
        }
    }

    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        filteredEdgeIndices.size(),
        kPromptSemanticControlFlowEdgeLimit,
        [&request, &filteredEdgeIndices](size_t relativeIndex)
        {
            const size_t index = filteredEdgeIndices[relativeIndex];
            return request.Facts.SemanticControlFlow.Edges[index].Confidence;
        });

    if (truncated != nullptr)
    {
        *truncated = filteredEdgeIndices.size() > indices.size();
    }

    for (size_t relativeIndex : indices)
    {
        const size_t index = filteredEdgeIndices[relativeIndex];
        const SemanticControlFlowEdge& edge = request.Facts.SemanticControlFlow.Edges[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("source_block", JsonValue::MakeString(edge.SourceBlock));
        item.Set("target_block", JsonValue::MakeString(edge.TargetBlock));
        item.Set("condition", JsonValue::MakeString(edge.Condition));
        item.Set("state_value", JsonValue::MakeString(edge.StateValue));
        item.Set("evidence", JsonValue::MakeString(edge.Evidence));
        item.Set("source", JsonValue::MakeString(edge.Source));
        item.Set("conditional", JsonValue::MakeBoolean(edge.Conditional));
        item.Set("dead", JsonValue::MakeBoolean(edge.Dead));
        item.Set("confidence", JsonValue::MakeNumber(edge.Confidence));
        edges.PushBack(item);
    }

    object.Set("edges", edges);
    object.Set("notes", BuildStringArray(request.Facts.SemanticControlFlow.Notes, kPromptSemanticControlFlowNoteLimit, &notesTruncated));
    object.Set("confidence", JsonValue::MakeNumber(request.Facts.SemanticControlFlow.Confidence));
    object.Set("scope", JsonValue::MakeString(blockIds == nullptr ? "function" : "chunk"));
    object.Set(
        "usage_guidance",
        JsonValue::MakeString("Use high-confidence non-dead edges as the semantic CFG overlay for recovered structure; use dead edges only to prune proven opaque-predicate targets; fall back to raw blocks where this overlay has no edge."));

    if (truncated != nullptr)
    {
        *truncated = *truncated || notesTruncated;
    }

    return object;
}

JsonValue BuildSemanticControlFlowJson(const AnalyzeRequest& request, bool* truncated)
{
    return BuildSemanticControlFlowJson(request, nullptr, truncated);
}

JsonValue BuildSemanticControlFlowJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    return BuildSemanticControlFlowJson(request, &blockIds, truncated);
}

JsonValue BuildControlFlowJson(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    bool* truncated)
{
    JsonValue array = JsonValue::MakeArray();
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.ControlFlow.size(); ++index)
    {
        if (IsPromptControlFlowRegionSelected(blockIds, request.Facts.ControlFlow[index]))
        {
            filteredIndices.push_back(index);
        }
    }

    const std::vector<size_t> indices = SelectSpreadIndices(filteredIndices.size(), kPromptControlFlowLimit);

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > indices.size();
    }

    for (size_t relativeIndex : indices)
    {
        const size_t index = filteredIndices[relativeIndex];
        const ControlFlowRegion& region = request.Facts.ControlFlow[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("kind", JsonValue::MakeString(region.Kind));
        item.Set("header_block", JsonValue::MakeString(region.HeaderBlock));
        item.Set("body_blocks", BuildStringArray(region.BodyBlocks, 16, nullptr));
        item.Set("latch_blocks", BuildStringArray(region.LatchBlocks, 8, nullptr));
        item.Set("exit_blocks", BuildStringArray(region.ExitBlocks, 8, nullptr));
        item.Set("condition", JsonValue::MakeString(region.Condition));
        item.Set("evidence", JsonValue::MakeString(region.Evidence));
        item.Set("induction_variable", JsonValue::MakeString(region.InductionVariable));
        item.Set("initial_value", JsonValue::MakeString(region.InitialValue));
        item.Set("step", JsonValue::MakeString(region.Step));
        item.Set("bound", JsonValue::MakeString(region.Bound));
        item.Set("direction", JsonValue::MakeString(region.Direction));
        item.Set("confidence", JsonValue::MakeNumber(region.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildControlFlowJson(const AnalyzeRequest& request, bool* truncated)
{
    return BuildControlFlowJson(request, nullptr, truncated);
}

JsonValue BuildControlFlowJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    bool* truncated)
{
    return BuildControlFlowJson(request, &blockIds, truncated);
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
    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        request.Facts.TypeHints.size(),
        kPromptTypeHintLimit,
        [&request](size_t index)
        {
            return ScorePromptTypeHint(request.Facts.TypeHints[index]);
        });

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
    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        request.Facts.CalleeSummaries.size(),
        kPromptCalleeSummaryLimit,
        [&request](size_t index)
        {
            return ScorePromptCalleeSummary(request.Facts.CalleeSummaries[index]);
        });

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
        item.Set("parameters", BuildPrototypeParametersJson(summary.Parameters, 16, nullptr));
        item.Set("tail_call", JsonValue::MakeBoolean(summary.TailCall));
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
    const std::vector<size_t> indices = SelectRankedSpreadIndices(
        request.Facts.CallTargets.size(),
        kPromptCallTargetLimit,
        [&request](size_t index)
        {
            return ScorePromptCallTarget(request.Facts.CallTargets[index]);
        });

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
        item.Set("memory_effects", JsonValue::MakeString(call.MemoryEffects));
        item.Set("ownership", JsonValue::MakeString(call.Ownership));
        item.Set("target_expression", JsonValue::MakeString(call.TargetExpression));
        item.Set("vtable_offset", JsonValue::MakeNumber(static_cast<double>(call.VtableOffset)));
        item.Set("indirect", JsonValue::MakeBoolean(call.Indirect));
        item.Set("tail_call", JsonValue::MakeBoolean(call.TailCall));
        item.Set("virtual_call", JsonValue::MakeBoolean(call.VirtualCall));
        item.Set("parameters", BuildPrototypeParametersJson(call.Parameters, 16, nullptr));
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

bool IsPromptAddressSelected(const std::set<uint64_t>* instructionAddresses, uint64_t site)
{
    return instructionAddresses == nullptr
        || site == 0
        || instructionAddresses->find(site) != instructionAddresses->end();
}

JsonValue BuildPdbFactsJson(
    const AnalyzeRequest& request,
    const std::set<uint64_t>* instructionAddresses,
    bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue params = JsonValue::MakeArray();
    JsonValue locals = JsonValue::MakeArray();
    JsonValue fieldHints = JsonValue::MakeArray();
    JsonValue enumHints = JsonValue::MakeArray();
    JsonValue sourceLocations = JsonValue::MakeArray();
    JsonValue conflicts = JsonValue::MakeArray();
    bool anyTruncated = false;
    std::vector<size_t> filteredLocalIndices;
    std::vector<size_t> filteredFieldIndices;
    std::vector<size_t> filteredEnumIndices;
    std::vector<size_t> filteredSourceIndices;

    for (size_t index = 0; index < request.Facts.Pdb.Locals.size(); ++index)
    {
        if (IsPromptAddressSelected(instructionAddresses, request.Facts.Pdb.Locals[index].Site))
        {
            filteredLocalIndices.push_back(index);
        }
    }

    for (size_t index = 0; index < request.Facts.Pdb.FieldHints.size(); ++index)
    {
        if (IsPromptAddressSelected(instructionAddresses, request.Facts.Pdb.FieldHints[index].Site))
        {
            filteredFieldIndices.push_back(index);
        }
    }

    for (size_t index = 0; index < request.Facts.Pdb.EnumHints.size(); ++index)
    {
        if (IsPromptAddressSelected(instructionAddresses, request.Facts.Pdb.EnumHints[index].Site))
        {
            filteredEnumIndices.push_back(index);
        }
    }

    for (size_t index = 0; index < request.Facts.Pdb.SourceLocations.size(); ++index)
    {
        if (IsPromptAddressSelected(instructionAddresses, request.Facts.Pdb.SourceLocations[index].Site))
        {
            filteredSourceIndices.push_back(index);
        }
    }

    const std::vector<size_t> paramIndices = SelectSpreadIndices(request.Facts.Pdb.Params.size(), kPromptPdbParamLimit);
    const std::vector<size_t> localIndices = SelectSpreadIndices(filteredLocalIndices.size(), kPromptPdbLocalLimit);
    const std::vector<size_t> fieldIndices = SelectSpreadIndices(filteredFieldIndices.size(), kPromptPdbFieldHintLimit);
    const std::vector<size_t> enumIndices = SelectSpreadIndices(filteredEnumIndices.size(), kPromptPdbEnumHintLimit);
    const std::vector<size_t> sourceIndices = SelectSpreadIndices(filteredSourceIndices.size(), kPromptPdbSourceLocationLimit);
    const std::vector<size_t> conflictIndices = SelectSpreadIndices(request.Facts.Pdb.Conflicts.size(), kPromptPdbConflictLimit);

    anyTruncated = anyTruncated
        || request.Facts.Pdb.PrototypeParameters.size() > 16
        || request.Facts.Pdb.Params.size() > paramIndices.size()
        || filteredLocalIndices.size() > localIndices.size()
        || filteredFieldIndices.size() > fieldIndices.size()
        || filteredEnumIndices.size() > enumIndices.size()
        || filteredSourceIndices.size() > sourceIndices.size()
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

    for (size_t relativeIndex : localIndices)
    {
        const size_t index = filteredLocalIndices[relativeIndex];
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

    for (size_t relativeIndex : fieldIndices)
    {
        const size_t index = filteredFieldIndices[relativeIndex];
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

    for (size_t relativeIndex : enumIndices)
    {
        const size_t index = filteredEnumIndices[relativeIndex];
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

    for (size_t relativeIndex : sourceIndices)
    {
        const size_t index = filteredSourceIndices[relativeIndex];
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
    object.Set("prototype_parameters", BuildPrototypeParametersJson(request.Facts.Pdb.PrototypeParameters, 16, nullptr));
    object.Set("params", params);
    object.Set("locals", locals);
    object.Set("field_hints", fieldHints);
    object.Set("enum_hints", enumHints);
    object.Set("source_locations", sourceLocations);
    object.Set("conflicts", conflicts);
    object.Set("confidence", JsonValue::MakeNumber(request.Facts.Pdb.Confidence));
    object.Set("scope", JsonValue::MakeString(instructionAddresses == nullptr ? "function" : "chunk"));

    if (truncated != nullptr)
    {
        *truncated = anyTruncated;
    }

    return object;
}

JsonValue BuildPdbFactsJson(const AnalyzeRequest& request, bool* truncated)
{
    return BuildPdbFactsJson(request, nullptr, truncated);
}

JsonValue BuildPdbFactsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    return BuildPdbFactsJson(request, &instructionAddresses, truncated);
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

double ScorePromptEvidenceNode(const EvidenceNode& node)
{
    double score = node.Confidence;

    if (node.Kind == "control_flow_region" || node.Kind == "normalized_condition")
    {
        score += 0.90;
    }
    else if (node.Kind == "call_target" || node.Kind == "callee_summary")
    {
        score += 0.75;
    }
    else if (node.Kind == "type_hint" || node.Kind == "pdb_field" || node.Kind == "pdb_enum")
    {
        score += 0.65;
    }
    else if (node.Kind == "ir_value" || node.Kind == "value_merge")
    {
        score += 0.55;
    }
    else if (node.Kind == "memory_access" || node.Kind == "data_reference")
    {
        score += 0.40;
    }

    score += node.Site != 0 ? 0.20 : 0.0;
    score += !node.BlockId.empty() ? 0.20 : 0.0;
    return score;
}

bool IsPromptEvidenceNodeSelected(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    const std::set<uint64_t>* instructionAddresses,
    const EvidenceNode& node)
{
    if (blockIds == nullptr && instructionAddresses == nullptr)
    {
        return true;
    }

    if (blockIds != nullptr && IsPromptBlockSelected(blockIds, node.BlockId))
    {
        return true;
    }

    if (node.Site != 0 && instructionAddresses != nullptr)
    {
        return instructionAddresses->find(node.Site) != instructionAddresses->end();
    }

    if (node.Site != 0)
    {
        return IsPromptSiteSelected(request, blockIds, node.Site);
    }

    return false;
}

JsonValue BuildEvidenceGraphJson(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds,
    const std::set<uint64_t>* instructionAddresses,
    bool* truncated)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue nodes = JsonValue::MakeArray();
    JsonValue edges = JsonValue::MakeArray();
    bool notesTruncated = false;
    std::set<std::string> selectedNodeIds;
    const EvidenceGraphFacts& graph = request.Facts.EvidenceGraph;
    std::vector<size_t> filteredNodeIndices;

    for (size_t index = 0; index < graph.Nodes.size(); ++index)
    {
        if (IsPromptEvidenceNodeSelected(request, blockIds, instructionAddresses, graph.Nodes[index]))
        {
            filteredNodeIndices.push_back(index);
        }
    }

    const std::vector<size_t> nodeIndices = SelectRankedSpreadIndices(
        filteredNodeIndices.size(),
        kPromptEvidenceNodeLimit,
        [&graph, &filteredNodeIndices](size_t relativeIndex)
        {
            return ScorePromptEvidenceNode(graph.Nodes[filteredNodeIndices[relativeIndex]]);
        });

    for (size_t relativeIndex : nodeIndices)
    {
        const size_t index = filteredNodeIndices[relativeIndex];
        const EvidenceNode& node = graph.Nodes[index];
        JsonValue item = JsonValue::MakeObject();
        item.Set("id", JsonValue::MakeString(node.Id));
        item.Set("kind", JsonValue::MakeString(node.Kind));
        item.Set("label", JsonValue::MakeString(node.Label));
        item.Set("site", JsonValue::MakeString(HexU64(node.Site)));
        item.Set("block_id", JsonValue::MakeString(node.BlockId));
        item.Set("confidence", JsonValue::MakeNumber(node.Confidence));
        nodes.PushBack(item);
        selectedNodeIds.insert(node.Id);
    }

    for (const EvidenceEdge& edge : graph.Edges)
    {
        if (edges.GetArray().size() >= kPromptEvidenceEdgeLimit)
        {
            break;
        }

        if (selectedNodeIds.find(edge.SourceId) == selectedNodeIds.end()
            || selectedNodeIds.find(edge.TargetId) == selectedNodeIds.end())
        {
            continue;
        }

        JsonValue item = JsonValue::MakeObject();
        item.Set("source_id", JsonValue::MakeString(edge.SourceId));
        item.Set("target_id", JsonValue::MakeString(edge.TargetId));
        item.Set("relation", JsonValue::MakeString(edge.Relation));
        item.Set("confidence", JsonValue::MakeNumber(edge.Confidence));
        edges.PushBack(item);
    }

    object.Set("nodes", nodes);
    object.Set("edges", edges);
    object.Set("notes", BuildStringArray(graph.Notes, kPromptEvidenceNoteLimit, &notesTruncated));
    object.Set("coverage", JsonValue::MakeNumber(graph.Coverage));
    object.Set("scope", JsonValue::MakeString(blockIds == nullptr && instructionAddresses == nullptr ? "function" : "chunk"));

    if (truncated != nullptr)
    {
        *truncated = filteredNodeIndices.size() > nodeIndices.size()
            || graph.Edges.size() > edges.GetArray().size()
            || notesTruncated;
    }

    return object;
}

JsonValue BuildEvidenceGraphJson(const AnalyzeRequest& request, bool* truncated)
{
    return BuildEvidenceGraphJson(request, nullptr, nullptr, truncated);
}

JsonValue BuildEvidenceGraphJsonForScope(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    return BuildEvidenceGraphJson(request, &blockIds, &instructionAddresses, truncated);
}

JsonValue BuildCountsJson(const AnalyzeRequest& request)
{
    JsonValue counts = JsonValue::MakeObject();
    counts.Set("instructions_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Instructions.size())));
    counts.Set("blocks_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Blocks.size())));
    counts.Set("direct_calls_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Calls.size())));
    counts.Set("indirect_calls_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.IndirectCalls.size())));
    counts.Set("switches_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Switches.size())));
    counts.Set("stack_pointer_facts_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.StackPointer.size())));
    counts.Set("memory_accesses_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.MemoryAccesses.size())));
    counts.Set("recovered_arguments_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.RecoveredArguments.size())));
    counts.Set("recovered_locals_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.RecoveredLocals.size())));
    counts.Set("call_arguments_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.CallArguments.size())));
    counts.Set("value_merges_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.ValueMerges.size())));
    counts.Set("ir_values_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.IrValues.size())));
    counts.Set("block_value_states_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.BlockValueStates.size())));
    counts.Set("obfuscation_state_variables_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.StateVariables.size())));
    counts.Set("obfuscation_dispatchers_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.Dispatchers.size())));
    counts.Set("obfuscation_opaque_predicates_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.OpaquePredicates.size())));
    counts.Set("obfuscation_substitution_idioms_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Obfuscation.SubstitutionIdioms.size())));
    counts.Set("semantic_control_flow_edges_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.SemanticControlFlow.Edges.size())));
    counts.Set("control_flow_regions_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.ControlFlow.size())));
    counts.Set("type_hints_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.TypeHints.size())));
    counts.Set("idioms_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Idioms.size())));
    counts.Set("callee_summaries_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.CalleeSummaries.size())));
    counts.Set("data_references_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.DataReferences.size())));
    counts.Set("call_targets_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.CallTargets.size())));
    counts.Set("normalized_conditions_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.NormalizedConditions.size())));
    counts.Set("pdb_prototype_params_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.PrototypeParameters.size())));
    counts.Set("pdb_params_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.Params.size())));
    counts.Set("pdb_locals_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.Locals.size())));
    counts.Set("pdb_field_hints_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.FieldHints.size())));
    counts.Set("pdb_enum_hints_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.EnumHints.size())));
    counts.Set("pdb_source_locations_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Pdb.SourceLocations.size())));
    counts.Set("evidence_graph_nodes_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.EvidenceGraph.Nodes.size())));
    counts.Set("evidence_graph_edges_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.EvidenceGraph.Edges.size())));
    counts.Set("facts_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.Facts.size())));
    counts.Set("uncertainties_total", JsonValue::MakeNumber(static_cast<double>(request.Facts.UncertainPoints.size())));
    return counts;
}

JsonValue BuildGraphSummaryJson(
    const AnalyzeRequest& request,
    const std::set<std::string>* blockIds)
{
    JsonValue graph = JsonValue::MakeObject();
    JsonValue entry = JsonValue::MakeObject();
    JsonValue regions = JsonValue::MakeArray();
    JsonValue conditions = JsonValue::MakeArray();
    JsonValue semanticEdges = JsonValue::MakeArray();
    JsonValue importantBlocks = JsonValue::MakeArray();

    if (!request.Facts.Blocks.empty())
    {
        const BasicBlock& first = request.Facts.Blocks.front();
        entry.Set("id", JsonValue::MakeString(first.Id));
        entry.Set("start", JsonValue::MakeString(HexU64(first.StartAddress)));
        entry.Set("successors", BuildStringArray(first.Successors, 8, nullptr));
    }

    for (size_t index = 0;
        index < request.Facts.ControlFlow.size()
        && regions.GetArray().size() < kPromptControlFlowLimit;
        ++index)
    {
        const ControlFlowRegion& region = request.Facts.ControlFlow[index];

        if (!IsPromptControlFlowRegionSelected(blockIds, region))
        {
            continue;
        }

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

    for (size_t index = 0;
        index < request.Facts.NormalizedConditions.size()
        && conditions.GetArray().size() < kPromptNormalizedConditionLimit;
        ++index)
    {
        const NormalizedCondition& condition = request.Facts.NormalizedConditions[index];

        if (blockIds != nullptr
            && !IsPromptBlockSelected(blockIds, condition.BlockId)
            && !IsPromptBlockSelected(blockIds, condition.TrueTargetBlock)
            && !IsPromptBlockSelected(blockIds, condition.FalseTargetBlock))
        {
            continue;
        }

        JsonValue item = JsonValue::MakeObject();
        item.Set("block", JsonValue::MakeString(condition.BlockId));
        item.Set("expression", JsonValue::MakeString(condition.Expression));
        item.Set("true_target", JsonValue::MakeString(condition.TrueTargetBlock));
        item.Set("false_target", JsonValue::MakeString(condition.FalseTargetBlock));
        item.Set("confidence", JsonValue::MakeNumber(condition.Confidence));
        conditions.PushBack(item);
    }

    for (size_t index = 0;
        index < request.Facts.SemanticControlFlow.Edges.size()
        && semanticEdges.GetArray().size() < kPromptSemanticControlFlowEdgeLimit;
        ++index)
    {
        const SemanticControlFlowEdge& edge = request.Facts.SemanticControlFlow.Edges[index];

        if (!IsPromptSemanticEdgeSelected(blockIds, edge))
        {
            continue;
        }

        JsonValue item = JsonValue::MakeObject();
        item.Set("source", JsonValue::MakeString(edge.SourceBlock));
        item.Set("target", JsonValue::MakeString(edge.TargetBlock));
        item.Set("state_value", JsonValue::MakeString(edge.StateValue));
        item.Set("condition", JsonValue::MakeString(edge.Condition));
        item.Set("dead", JsonValue::MakeBoolean(edge.Dead));
        item.Set("confidence", JsonValue::MakeNumber(edge.Confidence));
        semanticEdges.PushBack(item);
    }

    const InstructionIndex instructionByAddress = BuildInstructionIndex(request);
    const std::vector<size_t> blockIndices = SelectRepresentativeBlockIndices(request);

    for (size_t selectedIndex : blockIndices)
    {
        const BasicBlock& block = request.Facts.Blocks[selectedIndex];

        if (!IsPromptBlockSelected(blockIds, block.Id))
        {
            continue;
        }

        JsonValue item = JsonValue::MakeObject();
        item.Set("id", JsonValue::MakeString(block.Id));
        item.Set("succ", BuildStringArray(block.Successors, 8, nullptr));
        item.Set("instruction_count", JsonValue::MakeNumber(static_cast<double>(block.InstructionAddresses.size())));
        item.Set("has_direct_call", JsonValue::MakeBoolean(BlockContainsCallKind(instructionByAddress, block, false)));
        item.Set("has_indirect_call", JsonValue::MakeBoolean(BlockContainsCallKind(instructionByAddress, block, true)));
        item.Set("has_conditional_branch", JsonValue::MakeBoolean(BlockContainsConditionalBranch(instructionByAddress, block)));
        item.Set("has_return", JsonValue::MakeBoolean(BlockContainsReturn(instructionByAddress, block)));
        importantBlocks.PushBack(item);
    }

    graph.Set("entry", entry);
    graph.Set("scope", JsonValue::MakeString(blockIds == nullptr ? "function" : "chunk"));
    graph.Set("regions", regions);
    graph.Set("conditions", conditions);
    graph.Set("semantic_edges", semanticEdges);
    graph.Set("important_blocks", importantBlocks);
    graph.Set("truncated_policy", JsonValue::MakeString("When any truncation flag is true, keep the omitted graph portions uncertain unless supported by listed evidence."));
    return graph;
}

JsonValue BuildGraphSummaryJson(const AnalyzeRequest& request)
{
    return BuildGraphSummaryJson(request, nullptr);
}

JsonValue BuildGraphSummaryJsonForBlocks(
    const AnalyzeRequest& request,
    const std::set<std::string>& blockIds)
{
    return BuildGraphSummaryJson(request, &blockIds);
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
    bool stackPointerTruncated = false;
    bool memoryAccessesTruncated = false;
    bool recoveredArgumentsTruncated = false;
    bool recoveredLocalsTruncated = false;
    bool callArgumentsTruncated = false;
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
    root.Set("stack_pointer", BuildStackPointerJson(request, &stackPointerTruncated));
    root.Set("memory_accesses", BuildMemoryAccessesJson(request, &memoryAccessesTruncated));
    root.Set("recovered_arguments", BuildRecoveredArgumentsJson(request, &recoveredArgumentsTruncated));
    root.Set("recovered_locals", BuildRecoveredLocalsJson(request, &recoveredLocalsTruncated));
    root.Set("call_arguments", BuildCallArgumentsJson(request, &callArgumentsTruncated));
    root.Set("value_merges", BuildValueMergesJson(request, &valueMergesTruncated));
    root.Set("ir_values", BuildIrValuesJson(request, &irValuesTruncated));
    root.Set("block_value_states", BuildBlockValueStatesJson(request, &blockValueStatesTruncated));
    root.Set("obfuscation", BuildObfuscationJson(request, &obfuscationTruncated));
    root.Set("deobfuscation_readiness", BuildDeobfuscationReadinessJson(request));
    root.Set("semantic_control_flow", BuildSemanticControlFlowJson(request, &semanticControlFlowTruncated));
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
    root.Set("evidence_graph", BuildEvidenceGraphJson(request, &evidenceGraphTruncated));
    root.Set("facts", BuildStringArray(request.Facts.Facts, kPromptFactLimit, &factsTruncated));
    root.Set("uncertainties", BuildStringArray(request.Facts.UncertainPoints, kPromptUncertaintyLimit, &uncertaintiesTruncated));
    root.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));
    root.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));

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

JsonValue BuildBlocksJsonForIndices(
    const AnalyzeRequest& request,
    const std::vector<size_t>& indices)
{
    JsonValue blocks = JsonValue::MakeArray();
    const InstructionIndex instructionByAddress = BuildInstructionIndex(request);

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

        for (size_t instructionOffset = 0; instructionOffset < headCount; ++instructionOffset)
        {
            const DisassembledInstruction* instruction = FindInstructionByAddress(instructionByAddress, block.InstructionAddresses[instructionOffset]);

            if (instruction != nullptr)
            {
                instructionHeadSample.PushBack(JsonValue::MakeString(BuildInstructionPreview(*instruction)));
            }
        }

        if (block.InstructionAddresses.size() > tailCount)
        {
            for (size_t instructionOffset = block.InstructionAddresses.size() - tailCount; instructionOffset < block.InstructionAddresses.size(); ++instructionOffset)
            {
                const DisassembledInstruction* instruction = FindInstructionByAddress(instructionByAddress, block.InstructionAddresses[instructionOffset]);

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
        item.Set("memory_access_count", JsonValue::MakeNumber(static_cast<double>(CountBlockMemoryAccesses(instructionByAddress, block))));
        item.Set("has_direct_call", JsonValue::MakeBoolean(BlockContainsCallKind(instructionByAddress, block, false)));
        item.Set("has_indirect_call", JsonValue::MakeBoolean(BlockContainsCallKind(instructionByAddress, block, true)));
        item.Set("has_return", JsonValue::MakeBoolean(BlockContainsReturn(instructionByAddress, block)));
        item.Set("has_conditional_branch", JsonValue::MakeBoolean(BlockContainsConditionalBranch(instructionByAddress, block)));
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
        bool include = instructionAddresses.find(request.Facts.Switches[index].Site) != instructionAddresses.end();

        for (const uint64_t target : request.Facts.Switches[index].CaseTargets)
        {
            include = include || instructionAddresses.find(target) != instructionAddresses.end();
        }

        if (include)
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptSwitchLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectRankedSpreadIndices(
        filteredIndices.size(),
        kPromptSwitchLimit,
        [&request, &filteredIndices](size_t relativeIndex)
        {
            return ScorePromptSwitch(request.Facts.Switches[filteredIndices[relativeIndex]]);
        });

    for (size_t relativeIndex : sampled)
    {
        const SwitchInfo& info = request.Facts.Switches[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        JsonValue targets = JsonValue::MakeArray();

        for (size_t targetIndex = 0; targetIndex < info.CaseTargets.size() && targetIndex < 32; ++targetIndex)
        {
            targets.PushBack(JsonValue::MakeString(HexU64(info.CaseTargets[targetIndex])));
        }

        item.Set("site", JsonValue::MakeString(HexU64(info.Site)));
        item.Set("table_address", JsonValue::MakeString(HexU64(info.TableAddress)));
        item.Set("case_count", JsonValue::MakeNumber(static_cast<double>(info.CaseCount)));
        item.Set("default_target", JsonValue::MakeString(HexU64(info.DefaultTarget)));
        item.Set("range_min", JsonValue::MakeString(HexS64(info.RangeMin)));
        item.Set("range_max", JsonValue::MakeString(HexS64(info.RangeMax)));
        item.Set("range_known", JsonValue::MakeBoolean(info.RangeKnown));
        item.Set("signed_index", JsonValue::MakeBoolean(info.SignedIndex));
        item.Set("detail", JsonValue::MakeString(info.Detail));
        item.Set("index_expression", JsonValue::MakeString(info.IndexExpression));
        item.Set("case_targets", targets);
        item.Set("case_targets_truncated", JsonValue::MakeBoolean(info.CaseTargets.size() > 32));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildMemoryAccessesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    const InstructionIndex instructionByAddress = BuildInstructionIndex(request);
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
        item.Set("implicit", JsonValue::MakeBoolean(access.Implicit));
        item.Set("semantic", JsonValue::MakeString(access.Semantic));
        item.Set("stack_frame_relative", JsonValue::MakeBoolean(access.StackFrameRelative));
        item.Set("frame_base", JsonValue::MakeString(access.FrameBase));
        item.Set("frame_offset", JsonValue::MakeString(HexS64(access.FrameOffset)));
        item.Set("stack_pointer_delta", JsonValue::MakeString(HexS64(access.StackPointerDelta)));
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructionByAddress, access.Site);
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

JsonValue BuildTypeHintsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.TypeHints.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.TypeHints[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptTypeHintLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectRankedSpreadIndices(
        filteredIndices.size(),
        kPromptTypeHintLimit,
        [&request, &filteredIndices](size_t relativeIndex)
        {
            return ScorePromptTypeHint(request.Facts.TypeHints[filteredIndices[relativeIndex]]);
        });

    for (size_t relativeIndex : sampled)
    {
        const TypeRecoveryHint& hint = request.Facts.TypeHints[filteredIndices[relativeIndex]];
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

JsonValue BuildIdiomsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.Idioms.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.Idioms[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptIdiomLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectSpreadIndices(filteredIndices.size(), kPromptIdiomLimit);

    for (size_t relativeIndex : sampled)
    {
        const IdiomPattern& idiom = request.Facts.Idioms[filteredIndices[relativeIndex]];
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

JsonValue BuildCalleeSummariesJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    std::vector<size_t> filteredIndices;

    for (size_t index = 0; index < request.Facts.CalleeSummaries.size(); ++index)
    {
        if (instructionAddresses.find(request.Facts.CalleeSummaries[index].Site) != instructionAddresses.end())
        {
            filteredIndices.push_back(index);
        }
    }

    if (truncated != nullptr)
    {
        *truncated = filteredIndices.size() > kPromptCalleeSummaryLimit;
    }

    JsonValue array = JsonValue::MakeArray();
    const std::vector<size_t> sampled = SelectRankedSpreadIndices(
        filteredIndices.size(),
        kPromptCalleeSummaryLimit,
        [&request, &filteredIndices](size_t relativeIndex)
        {
            return ScorePromptCalleeSummary(request.Facts.CalleeSummaries[filteredIndices[relativeIndex]]);
        });

    for (size_t relativeIndex : sampled)
    {
        const CalleeSummary& summary = request.Facts.CalleeSummaries[filteredIndices[relativeIndex]];
        JsonValue item = JsonValue::MakeObject();
        item.Set("site", JsonValue::MakeString(HexU64(summary.Site)));
        item.Set("callee", JsonValue::MakeString(summary.Callee));
        item.Set("return_type", JsonValue::MakeString(summary.ReturnType));
        item.Set("parameter_model", JsonValue::MakeString(summary.ParameterModel));
        item.Set("side_effects", JsonValue::MakeString(summary.SideEffects));
        item.Set("memory_effects", JsonValue::MakeString(summary.MemoryEffects));
        item.Set("ownership", JsonValue::MakeString(summary.Ownership));
        item.Set("source", JsonValue::MakeString(summary.Source));
        item.Set("parameters", BuildPrototypeParametersJson(summary.Parameters, 16, nullptr));
        item.Set("tail_call", JsonValue::MakeBoolean(summary.TailCall));
        item.Set("confidence", JsonValue::MakeNumber(summary.Confidence));
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
    const std::vector<size_t> sampled = SelectRankedSpreadIndices(
        filteredIndices.size(),
        kPromptCallTargetLimit,
        [&request, &filteredIndices](size_t relativeIndex)
        {
            return ScorePromptCallTarget(request.Facts.CallTargets[filteredIndices[relativeIndex]]);
        });

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
        item.Set("memory_effects", JsonValue::MakeString(call.MemoryEffects));
        item.Set("ownership", JsonValue::MakeString(call.Ownership));
        item.Set("target_expression", JsonValue::MakeString(call.TargetExpression));
        item.Set("vtable_offset", JsonValue::MakeNumber(static_cast<double>(call.VtableOffset)));
        item.Set("indirect", JsonValue::MakeBoolean(call.Indirect));
        item.Set("tail_call", JsonValue::MakeBoolean(call.TailCall));
        item.Set("virtual_call", JsonValue::MakeBoolean(call.VirtualCall));
        item.Set("parameters", BuildPrototypeParametersJson(call.Parameters, 16, nullptr));
        item.Set("confidence", JsonValue::MakeNumber(call.Confidence));
        array.PushBack(item);
    }

    return array;
}

JsonValue BuildCallArgumentsJsonForAddresses(
    const AnalyzeRequest& request,
    const std::set<uint64_t>& instructionAddresses,
    bool* truncated)
{
    return BuildCallArgumentGroupsJson(request, BuildCallArgumentPromptGroups(request, &instructionAddresses), truncated);
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
}
