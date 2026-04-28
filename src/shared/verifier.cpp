#include "decomp/verifier.h"

#include <cctype>
#include <exception>
#include <set>
#include <unordered_set>

#include "decomp/string_utils.h"

namespace decomp
{
namespace
{
int ParseBlockNumber(const std::string& blockId)
{
    if (!StartsWithInsensitive(blockId, "bb"))
    {
        return -1;
    }

    try
    {
        return std::stoi(blockId.substr(2));
    }
    catch (const std::exception&)
    {
        return -1;
    }
}

bool GraphHasBackEdge(const AnalysisFacts& facts)
{
    for (const auto& region : facts.ControlFlow)
    {
        if (region.Kind == "natural_loop")
        {
            return true;
        }
    }

    for (const auto& block : facts.Blocks)
    {
        const int from = ParseBlockNumber(block.Id);

        for (const auto& successor : block.Successors)
        {
            const int to = ParseBlockNumber(successor);

            if (from >= 0 && to >= 0 && to <= from)
            {
                return true;
            }
        }
    }

    return false;
}

bool MentionsLoop(const AnalyzeResponse& response)
{
    return ContainsInsensitive(response.Summary, "loop")
        || ContainsInsensitive(response.PseudoC, "for (")
        || ContainsInsensitive(response.PseudoC, "while (")
        || ContainsInsensitive(response.PseudoC, "do\n{");
}

bool MentionsSwitch(const AnalyzeResponse& response)
{
    return ContainsInsensitive(response.Summary, "switch")
        || ContainsInsensitive(response.PseudoC, "switch (");
}

bool MentionsNoReturn(const AnalyzeResponse& response)
{
    return ContainsInsensitive(response.Summary, "no-return")
        || ContainsInsensitive(response.Summary, "noreturn")
        || ContainsInsensitive(response.PseudoC, "__declspec(noreturn)")
        || ContainsInsensitive(response.PseudoC, "[[noreturn]]");
}

bool MentionsBranch(const AnalyzeResponse& response)
{
    return ContainsInsensitive(response.PseudoC, "if (")
        || ContainsInsensitive(response.PseudoC, "else")
        || ContainsInsensitive(response.Summary, "branch");
}

bool HasConditionalBranchEvidence(const AnalysisFacts& facts)
{
    if (!facts.NormalizedConditions.empty())
    {
        return true;
    }

    for (const auto& instruction : facts.Instructions)
    {
        if (instruction.IsConditionalBranch)
        {
            return true;
        }
    }

    return false;
}

const BasicBlock* FindBlock(const AnalysisFacts& facts, const std::string& blockId)
{
    for (const auto& block : facts.Blocks)
    {
        if (block.Id == blockId)
        {
            return &block;
        }
    }

    return nullptr;
}

bool HasSuccessor(const BasicBlock& block, const std::string& successor)
{
    for (const auto& candidate : block.Successors)
    {
        if (candidate == successor)
        {
            return true;
        }
    }

    return false;
}

void AddIssue(
    VerifyReport& report,
    const std::string& code,
    const std::string& severity,
    const std::string& message,
    const std::string& evidence = std::string())
{
    VerificationIssue issue;
    issue.Code = code;
    issue.Severity = severity;
    issue.Message = message;
    issue.Evidence = evidence;
    report.Issues.push_back(issue);
    report.Warnings.push_back(message);
}

bool HasReturnInstruction(const AnalysisFacts& facts)
{
    for (const auto& instruction : facts.Instructions)
    {
        if (instruction.IsReturn)
        {
            return true;
        }
    }

    return false;
}

std::string LowerNoSpace(std::string value)
{
    value = ToLowerAscii(value);
    std::string compact;

    for (const char ch : value)
    {
        if (std::isspace(static_cast<unsigned char>(ch)) == 0)
        {
            compact.push_back(ch);
        }
    }

    return compact;
}

bool ContainsCallText(const AnalyzeResponse& response, const std::string& callee)
{
    if (callee.empty())
    {
        return false;
    }

    return ContainsInsensitive(response.PseudoC, callee + "(")
        || ContainsInsensitive(response.PseudoC, callee)
        || ContainsInsensitive(response.Summary, callee);
}

bool LooksLikeAssignedCallResult(const AnalyzeResponse& response, const std::string& callee)
{
    if (callee.empty())
    {
        return false;
    }

    const std::string pseudo = LowerNoSpace(response.PseudoC);
    const std::string name = LowerNoSpace(callee);

    return pseudo.find("=" + name + "(") != std::string::npos
        || pseudo.find("=" + name) != std::string::npos;
}

uint32_t CountConditionalBranches(const AnalysisFacts& facts)
{
    uint32_t count = 0;

    for (const auto& instruction : facts.Instructions)
    {
        if (instruction.IsConditionalBranch)
        {
            ++count;
        }
    }

    return count;
}

uint32_t CountPseudoIfs(const AnalyzeResponse& response)
{
    uint32_t count = 0;
    size_t offset = 0;

    while ((offset = response.PseudoC.find("if (", offset)) != std::string::npos)
    {
        ++count;
        offset += 4;
    }

    return count;
}

void CheckBranchTargetEdges(const AnalyzeRequest& request, VerifyReport& report)
{
    for (const auto& condition : request.Facts.NormalizedConditions)
    {
        const BasicBlock* block = FindBlock(request.Facts, condition.BlockId);

        if (block == nullptr)
        {
            AddIssue(
                report,
                "branch.condition_block_missing",
                "error",
                "normalized branch condition references a missing basic block",
                condition.BlockId);
            ++report.FactConflicts;
            continue;
        }

        if (!condition.TrueTargetBlock.empty() && !HasSuccessor(*block, condition.TrueTargetBlock))
        {
            AddIssue(
                report,
                "branch.true_target_not_successor",
                "error",
                "normalized branch true target is not a CFG successor",
                condition.BlockId + " -> " + condition.TrueTargetBlock + " expression=" + condition.Expression);
            ++report.FactConflicts;
        }

        if (!condition.FalseTargetBlock.empty() && !HasSuccessor(*block, condition.FalseTargetBlock))
        {
            AddIssue(
                report,
                "branch.false_target_not_successor",
                "error",
                "normalized branch false target is not a CFG successor",
                condition.BlockId + " -> " + condition.FalseTargetBlock + " expression=" + condition.Expression);
            ++report.FactConflicts;
        }
    }
}

void CheckPseudoBranchDensity(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    const uint32_t pseudoIfs = CountPseudoIfs(response);
    const uint32_t analyzerBranches = CountConditionalBranches(request.Facts);

    if (pseudoIfs > analyzerBranches + 2 && analyzerBranches != 0)
    {
        AddIssue(
            report,
            "branch.too_many_pseudo_conditions",
            "warning",
            "pseudo_c contains more branch expressions than recovered CFG branch evidence",
            "pseudo_if_count=" + std::to_string(pseudoIfs) + " cfg_conditional_branches=" + std::to_string(analyzerBranches));
    }
}

void CheckCalleeSummaryConsistency(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    for (const auto& summary : request.Facts.CalleeSummaries)
    {
        if (!ContainsCallText(response, summary.Callee))
        {
            continue;
        }

        if (ContainsInsensitive(summary.ReturnType, "void") && LooksLikeAssignedCallResult(response, summary.Callee))
        {
            AddIssue(
                report,
                "callee.void_return_assigned",
                "warning",
                "pseudo_c assigns the result of a callee summarized as void",
                summary.Callee + " return_type=" + summary.ReturnType);
        }

        if ((ContainsInsensitive(summary.SideEffects, "no-return") || ContainsInsensitive(summary.SideEffects, "noreturn"))
            && ContainsInsensitive(response.PseudoC, "return "))
        {
            AddIssue(
                report,
                "callee.noreturn_followed_by_return",
                "error",
                "pseudo_c returns after a callee summarized as no-return",
                summary.Callee + " side_effects=" + summary.SideEffects);
            ++report.FactConflicts;
        }

        if ((ContainsInsensitive(summary.MemoryEffects, "write") || ContainsInsensitive(summary.SideEffects, "mutates"))
            && !ContainsInsensitive(response.PseudoC, "*")
            && !ContainsInsensitive(response.PseudoC, "mem")
            && !ContainsInsensitive(response.PseudoC, "copy")
            && !ContainsInsensitive(response.PseudoC, "set"))
        {
            AddIssue(
                report,
                "callee.memory_effect_not_reflected",
                "info",
                "callee summary reports memory writes but pseudo_c does not visibly reflect a memory effect",
                summary.Callee + " memory_effects=" + summary.MemoryEffects);
        }
    }
}

std::vector<std::string> ExtractIdentifiers(const std::string& text)
{
    std::vector<std::string> identifiers;
    std::string current;

    auto flush = [&identifiers, &current]()
    {
        if (current.empty())
        {
            return;
        }

        if (std::isalpha(static_cast<unsigned char>(current.front())) != 0 || current.front() == '_')
        {
            identifiers.push_back(current);
        }

        current.clear();
    };

    for (char ch : text)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_')
        {
            current.push_back(ch);
        }
        else
        {
            flush();
        }
    }

    flush();
    return identifiers;
}

bool LooksLikeUseBeforeDef(const AnalyzeRequest& request, const AnalyzeResponse& response)
{
    std::unordered_set<std::string> known;
    static const std::unordered_set<std::string> keywords = {
        "if", "else", "for", "while", "do", "switch", "case", "default", "return",
        "break", "continue", "sizeof", "true", "false", "NULL", "nullptr",
        "UNKNOWN_TYPE", "UNKNOWN_VALUE", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t", "void", "char", "int", "long", "short",
        "const", "volatile", "struct"
    };

    for (const auto& param : response.Params)
    {
        known.insert(param.Name);
    }

    for (const auto& local : response.Locals)
    {
        known.insert(local.Name);
    }

    for (const auto& argument : request.Facts.RecoveredArguments)
    {
        known.insert(argument.Name);
        known.insert(argument.Register);
    }

    for (const auto& local : request.Facts.RecoveredLocals)
    {
        known.insert(local.Name);
    }

    size_t suspicious = 0;

    for (const std::string& identifier : ExtractIdentifiers(response.PseudoC))
    {
        if (identifier.size() < 3
            || keywords.find(identifier) != keywords.end()
            || known.find(identifier) != known.end()
            || StartsWithInsensitive(identifier, "bb")
            || ContainsInsensitive(identifier, "UNKNOWN"))
        {
            continue;
        }

        if (ContainsInsensitive(response.PseudoC, identifier + " =")
            || ContainsInsensitive(response.PseudoC, identifier + "("))
        {
            continue;
        }

        ++suspicious;

        if (suspicious >= 8)
        {
            return true;
        }
    }

    return false;
}
}

VerifyReport VerifyResponse(const AnalyzeRequest& request, AnalyzeResponse& response)
{
    VerifyReport report;
    report.SchemaOk = !response.Status.empty() && (!response.PseudoC.empty() || !response.Summary.empty());

    std::set<std::string> blockIds;

    for (const auto& block : request.Facts.Blocks)
    {
        blockIds.insert(block.Id);
    }

    for (const auto& evidence : response.Evidence)
    {
        for (const auto& blockId : evidence.Blocks)
        {
            if (blockIds.find(blockId) == blockIds.end())
            {
                ++report.MissingEvidence;
                AddIssue(
                    report,
                    "evidence.block_missing",
                    "warning",
                    "response evidence references a missing basic block",
                    blockId);
            }
        }
    }

    CheckBranchTargetEdges(request, report);
    CheckPseudoBranchDensity(request, response, report);
    CheckCalleeSummaryConsistency(request, response, report);

    if (MentionsLoop(response) && !GraphHasBackEdge(request.Facts))
    {
        ++report.FactConflicts;
        AddIssue(report, "control_flow.loop_without_back_edge", "error", "loop mentioned without a graph back-edge");
    }

    if (MentionsSwitch(response) && request.Facts.Switches.empty())
    {
        ++report.FactConflicts;
        AddIssue(report, "control_flow.switch_without_evidence", "error", "switch mentioned without analyzer switch evidence");
    }

    if (MentionsNoReturn(response) && request.Facts.Abi.NoReturnCalls.empty())
    {
        ++report.FactConflicts;
        AddIssue(report, "abi.noreturn_without_evidence", "error", "no-return behavior mentioned without analyzer no-return evidence");
    }

    if (MentionsBranch(response) && !HasConditionalBranchEvidence(request.Facts))
    {
        ++report.FactConflicts;
        AddIssue(report, "branch.without_evidence", "error", "branch structure mentioned without conditional branch evidence");
    }

    if (ContainsInsensitive(response.PseudoC, "return ") && !HasReturnInstruction(request.Facts) && request.Facts.Abi.TailCalls.empty())
    {
        AddIssue(report, "return.without_instruction", "warning", "pseudo_c returns a value but analyzer did not recover a return instruction or tail-call");
    }

    if (LooksLikeUseBeforeDef(request, response) && response.Confidence > 0.60)
    {
        AddIssue(report, "identifier.suspicious_unknowns", "warning", "pseudo_c contains several identifiers not present in recovered params, locals, or definitions");
    }

    if (response.Confidence > 0.65 && response.Evidence.empty() && !request.Facts.Blocks.empty())
    {
        ++report.MissingEvidence;
        AddIssue(report, "evidence.missing_for_high_confidence", "warning", "response confidence is high but no block evidence was provided");
    }

    if (request.Facts.Abi.NoReturnCalls.empty())
    {
        for (const auto& call : request.Facts.Calls)
        {
            if (!call.Returns)
            {
                AddIssue(report, "abi.call_noreturn_list_empty", "warning", "call marked non-returning but ABI no-return list is empty", call.Target);
                break;
            }
        }
    }

    if (request.Facts.ControlFlow.empty() && request.Facts.Blocks.size() > 1 && response.Confidence > 0.65)
    {
        AddIssue(report, "control_flow.structuring_uncertain", "warning", "response confidence is high but analyzer control-flow structuring is uncertain");
    }

    if (request.Facts.Instructions.empty() && response.Confidence > 0.50)
    {
        ++report.FactConflicts;
        AddIssue(report, "instructions.missing_for_high_confidence", "error", "response confidence is high but no instructions were analyzed");
    }

    if (!request.Facts.UncertainPoints.empty() && response.Uncertainties.empty() && response.Confidence > 0.55)
    {
        AddIssue(report, "uncertainty.omitted", "warning", "response omitted uncertainties despite analyzer uncertainty");
    }

    if (response.Params.size() > 4 && StartsWithInsensitive(request.Facts.CallingConvention, "ms_x64"))
    {
        ++report.FactConflicts;
        AddIssue(report, "abi.too_many_register_params", "error", "parameter count exceeds obvious register argument slots");
    }

    const double blended = Clamp01((response.Confidence * 0.65) + (request.Facts.PreLlmConfidence * 0.35));
    double adjusted = blended;
    adjusted -= static_cast<double>(report.FactConflicts) * 0.10;
    adjusted -= static_cast<double>(report.MissingEvidence) * 0.05;

    if (!report.SchemaOk)
    {
        adjusted = 0.0;
        AddIssue(report, "schema.incomplete", "error", "response schema is incomplete");
    }

    report.AdjustedConfidence = Clamp01(adjusted);
    response.Verifier = report;
    return report;
}
}

