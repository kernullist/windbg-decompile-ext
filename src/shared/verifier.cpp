#include "decomp/verifier.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <set>
#include <unordered_set>

#include "decomp/pseudo_tokens.h"
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

bool HasCodeTokenText(const AnalyzeResponse& response, const std::string& value);

bool MentionsLoop(const AnalyzeResponse& response)
{
    return ContainsInsensitive(response.Summary, "loop")
        || HasCodeTokenText(response, "for")
        || HasCodeTokenText(response, "while")
        || HasCodeTokenText(response, "do");
}

bool MentionsSwitch(const AnalyzeResponse& response)
{
    return ContainsInsensitive(response.Summary, "switch")
        || HasCodeTokenText(response, "switch");
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
    return HasCodeTokenText(response, "if")
        || HasCodeTokenText(response, "else")
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

bool IsTriviaOrLiteralToken(const PseudoCodeToken& token)
{
    return token.Kind == "whitespace"
        || token.Kind == "newline"
        || token.Kind == "comment"
        || token.Kind == "string"
        || token.Kind == "char"
        || token.Kind == "preprocessor";
}

std::vector<PseudoCodeToken> CodeTokens(const AnalyzeResponse& response)
{
    std::vector<PseudoCodeToken> tokens;

    for (const PseudoCodeToken& token : response.PseudoCTokens)
    {
        if (!IsTriviaOrLiteralToken(token))
        {
            tokens.push_back(token);
        }
    }

    return tokens;
}

bool TokenTextEquals(const PseudoCodeToken& token, const std::string& value)
{
    return ToLowerAscii(token.Text) == ToLowerAscii(value);
}

bool HasCodeTokenText(const AnalyzeResponse& response, const std::string& value)
{
    for (const PseudoCodeToken& token : CodeTokens(response))
    {
        if (TokenTextEquals(token, value))
        {
            return true;
        }
    }

    return false;
}

std::vector<std::string> BuildSymbolCandidates(const std::string& symbol)
{
    std::vector<std::string> candidates;

    auto addCandidate = [&candidates](std::string candidate)
    {
        candidate = TrimCopy(candidate);

        if (!candidate.empty()
            && std::find_if(
                   candidates.begin(),
                   candidates.end(),
                   [&candidate](const std::string& existing)
                   {
                       return StartsWithInsensitive(existing, candidate) && existing.size() == candidate.size();
                   })
                == candidates.end())
        {
            candidates.push_back(candidate);
        }
    };

    addCandidate(symbol);

    const size_t bang = symbol.rfind('!');

    if (bang != std::string::npos && bang + 1 < symbol.size())
    {
        addCandidate(symbol.substr(bang + 1));
    }

    for (size_t index = 0; index < candidates.size(); ++index)
    {
        std::string candidate = candidates[index];
        const size_t candidateBang = candidate.rfind('!');

        if (candidateBang != std::string::npos && candidateBang + 1 < candidate.size())
        {
            candidate = candidate.substr(candidateBang + 1);
        }

        if (StartsWithInsensitive(candidate, "__imp_"))
        {
            addCandidate(candidate.substr(6));
        }
        else if (StartsWithInsensitive(candidate, "_imp_"))
        {
            addCandidate(candidate.substr(5));
        }
    }

    return candidates;
}

bool ContainsCallText(const AnalyzeResponse& response, const std::string& callee)
{
    if (callee.empty())
    {
        return false;
    }

    const std::vector<std::string> candidates = BuildSymbolCandidates(callee);
    const std::vector<PseudoCodeToken> tokens = CodeTokens(response);

    for (const std::string& candidate : candidates)
    {
        if (candidate.empty())
        {
            continue;
        }

        for (size_t index = 0; index < tokens.size(); ++index)
        {
            if (tokens[index].Kind == "function_name" && TokenTextEquals(tokens[index], candidate))
            {
                return true;
            }
        }
    }

    return false;
}

bool TryCountCallArgumentsFromOpenParen(
    const std::vector<PseudoCodeToken>& tokens,
    size_t openParenIndex,
    uint32_t& count)
{
    if (openParenIndex >= tokens.size() || tokens[openParenIndex].Text != "(")
    {
        return false;
    }

    count = 0;
    size_t depth = 0;
    bool sawArgumentToken = false;

    for (size_t index = openParenIndex + 1U; index < tokens.size(); ++index)
    {
        const std::string& text = tokens[index].Text;

        if (text == "(" || text == "[" || text == "{")
        {
            ++depth;
            sawArgumentToken = true;
            continue;
        }

        if (text == ")" || text == "]" || text == "}")
        {
            if (depth == 0)
            {
                if (sawArgumentToken)
                {
                    ++count;
                }

                return text == ")";
            }

            --depth;
            sawArgumentToken = true;
            continue;
        }

        if (text == "," && depth == 0)
        {
            if (sawArgumentToken)
            {
                ++count;
                sawArgumentToken = false;
            }

            continue;
        }

        sawArgumentToken = true;
    }

    return false;
}

std::vector<uint32_t> FindCallArities(const AnalyzeResponse& response, const std::string& callee)
{
    std::vector<uint32_t> arities;
    const std::vector<std::string> candidates = BuildSymbolCandidates(callee);
    const std::vector<PseudoCodeToken> tokens = CodeTokens(response);

    for (size_t index = 0; index + 1U < tokens.size(); ++index)
    {
        if (tokens[index].Kind != "function_name" || tokens[index + 1U].Text != "(")
        {
            continue;
        }

        bool matches = false;

        for (const std::string& candidate : candidates)
        {
            matches = matches || TokenTextEquals(tokens[index], candidate);
        }

        if (!matches)
        {
            continue;
        }

        uint32_t arity = 0;

        if (TryCountCallArgumentsFromOpenParen(tokens, index + 1U, arity))
        {
            arities.push_back(arity);
        }
    }

    return arities;
}

bool LooksLikeAssignedCallResult(const AnalyzeResponse& response, const std::string& callee)
{
    if (callee.empty())
    {
        return false;
    }

    const std::vector<std::string> candidates = BuildSymbolCandidates(callee);
    const std::vector<PseudoCodeToken> tokens = CodeTokens(response);

    for (size_t index = 0; index < tokens.size(); ++index)
    {
        if (tokens[index].Kind != "function_name" && tokens[index].Kind != "identifier")
        {
            continue;
        }

        bool matches = false;

        for (const std::string& candidate : candidates)
        {
            matches = matches || TokenTextEquals(tokens[index], candidate);
        }

        if (!matches)
        {
            continue;
        }

        for (size_t cursor = index; cursor > 0 && index - cursor < 8; --cursor)
        {
            if (tokens[cursor - 1U].Kind == "operator" && tokens[cursor - 1U].Text == "=")
            {
                return true;
            }

            if (tokens[cursor - 1U].Text == ";" || tokens[cursor - 1U].Text == "{" || tokens[cursor - 1U].Text == "}")
            {
                break;
            }
        }
    }

    return false;
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

    for (const PseudoCodeToken& token : CodeTokens(response))
    {
        if (TokenTextEquals(token, "if"))
        {
            ++count;
        }
    }

    return count;
}

uint32_t CountPseudoSwitchCases(const AnalyzeResponse& response)
{
    uint32_t count = 0;

    for (const PseudoCodeToken& token : CodeTokens(response))
    {
        if (TokenTextEquals(token, "case"))
        {
            ++count;
        }
    }

    return count;
}

uint32_t CountRecoveredSwitchTargets(const AnalysisFacts& facts)
{
    uint32_t count = 0;

    for (const auto& switchInfo : facts.Switches)
    {
        count += static_cast<uint32_t>(switchInfo.CaseTargets.size());

        if (switchInfo.DefaultTarget != 0)
        {
            ++count;
        }
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

    if (analyzerBranches >= 4 && pseudoIfs + 1 < analyzerBranches / 2 && response.Confidence > 0.65)
    {
        AddIssue(
            report,
            "branch.too_few_pseudo_conditions",
            "warning",
            "pseudo_c contains far fewer branch expressions than recovered CFG branch evidence",
            "pseudo_if_count=" + std::to_string(pseudoIfs) + " cfg_conditional_branches=" + std::to_string(analyzerBranches));
    }
}

void CheckSwitchEvidenceConsistency(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    if (!MentionsSwitch(response) || request.Facts.Switches.empty())
    {
        return;
    }

    const uint32_t recoveredTargets = CountRecoveredSwitchTargets(request.Facts);
    uint32_t maxEstimatedCases = 0;

    for (const auto& switchInfo : request.Facts.Switches)
    {
        maxEstimatedCases = (std::max)(maxEstimatedCases, switchInfo.CaseCount);
    }

    if (recoveredTargets == 0 && maxEstimatedCases == 0 && response.Confidence > 0.60)
    {
        AddIssue(
            report,
            "control_flow.switch_without_case_evidence",
            "warning",
            "switch mentioned but analyzer has no recovered or estimated case evidence");
    }

    const uint32_t pseudoCases = CountPseudoSwitchCases(response);

    if (recoveredTargets != 0 && pseudoCases > recoveredTargets + 2)
    {
        AddIssue(
            report,
            "control_flow.too_many_switch_cases",
            "warning",
            "pseudo_c contains more switch cases than recovered jump-table targets",
            "pseudo_cases=" + std::to_string(pseudoCases) + " recovered_targets=" + std::to_string(recoveredTargets));
    }
}

void CheckRecoveredCallCoverage(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    if (response.Confidence <= 0.65)
    {
        return;
    }

    size_t missingHighConfidenceCalls = 0;

    for (const auto& call : request.Facts.CallTargets)
    {
        if (call.DisplayName.empty() || call.Confidence < 0.65)
        {
            continue;
        }

        if (!ContainsCallText(response, call.DisplayName))
        {
            ++missingHighConfidenceCalls;
        }
    }

    if (missingHighConfidenceCalls != 0)
    {
        AddIssue(
            report,
            "call.recovered_targets_omitted",
            "warning",
            "pseudo_c omits one or more high-confidence recovered call targets",
            "missing_high_confidence_calls=" + std::to_string(missingHighConfidenceCalls));
    }
}

uint32_t RecoveredCallArgumentArityAtSite(const AnalysisFacts& facts, uint64_t site)
{
    uint32_t arity = 0;

    for (const CallArgumentFact& argument : facts.CallArguments)
    {
        if (argument.Site == site && argument.Confidence >= 0.55)
        {
            arity = (std::max)(arity, argument.Ordinal);
        }
    }

    return arity;
}

uint32_t PrototypeParameterArity(const std::vector<PrototypeParameter>& parameters)
{
    uint32_t arity = 0;

    for (const PrototypeParameter& parameter : parameters)
    {
        if (parameter.Type == "..." || parameter.Name == "varargs")
        {
            continue;
        }

        arity = (std::max)(arity, parameter.Ordinal);
    }

    return arity;
}

void CheckRecoveredCallArgumentConsistency(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    if (response.Confidence <= 0.65)
    {
        return;
    }

    size_t suspiciousCalls = 0;
    std::set<uint64_t> checkedSites;

    for (const CallTargetInfo& call : request.Facts.CallTargets)
    {
        if (call.DisplayName.empty() || call.Confidence < 0.65)
        {
            continue;
        }

        const uint32_t recoveredArity = RecoveredCallArgumentArityAtSite(request.Facts, call.Site);
        const uint32_t prototypeArity = PrototypeParameterArity(call.Parameters);
        const uint32_t expectedArity = (std::max)(recoveredArity, prototypeArity);

        if (expectedArity == 0)
        {
            continue;
        }

        const std::vector<uint32_t> pseudoArities = FindCallArities(response, call.DisplayName);

        if (pseudoArities.empty())
        {
            continue;
        }

        const uint32_t maxPseudoArity = *std::max_element(pseudoArities.begin(), pseudoArities.end());

        if (maxPseudoArity < expectedArity)
        {
            ++suspiciousCalls;
        }

        checkedSites.insert(call.Site);
    }

    for (const CalleeSummary& summary : request.Facts.CalleeSummaries)
    {
        if (summary.Callee.empty()
            || summary.Confidence < 0.65
            || checkedSites.find(summary.Site) != checkedSites.end())
        {
            continue;
        }

        const uint32_t expectedArity = PrototypeParameterArity(summary.Parameters);

        if (expectedArity == 0)
        {
            continue;
        }

        const std::vector<uint32_t> pseudoArities = FindCallArities(response, summary.Callee);

        if (pseudoArities.empty())
        {
            continue;
        }

        const uint32_t maxPseudoArity = *std::max_element(pseudoArities.begin(), pseudoArities.end());

        if (maxPseudoArity < expectedArity)
        {
            ++suspiciousCalls;
        }
    }

    if (suspiciousCalls != 0)
    {
        AddIssue(
            report,
            "call.arguments_omitted",
            "warning",
            "pseudo_c calls recovered callees with fewer arguments than recovered call-site or prototype facts",
            "calls_with_too_few_arguments=" + std::to_string(suspiciousCalls));
        ++report.MissingEvidence;
    }
}

bool IsKnownResponseName(const AnalyzeRequest& request, const std::string& name)
{
    if (name.empty())
    {
        return true;
    }

    for (const auto& argument : request.Facts.RecoveredArguments)
    {
        if (argument.Name == name || argument.Register == name)
        {
            return true;
        }
    }

    for (const auto& local : request.Facts.RecoveredLocals)
    {
        if (local.Name == name)
        {
            return true;
        }
    }

    for (const auto& param : request.Facts.Pdb.Params)
    {
        if (param.Name == name)
        {
            return true;
        }
    }

    for (const auto& param : request.Facts.Pdb.PrototypeParameters)
    {
        if (param.Name == name)
        {
            return true;
        }
    }

    for (const auto& local : request.Facts.Pdb.Locals)
    {
        if (local.Name == name)
        {
            return true;
        }
    }

    auto hasNumericSuffix = [&name](const std::string& prefix)
    {
        if (!StartsWithInsensitive(name, prefix) || name.size() <= prefix.size())
        {
            return false;
        }

        for (size_t index = prefix.size(); index < name.size(); ++index)
        {
            if (std::isdigit(static_cast<unsigned char>(name[index])) == 0)
            {
                return false;
            }
        }

        return true;
    };

    return hasNumericSuffix("arg")
        || hasNumericSuffix("v")
        || StartsWithInsensitive(name, "local_")
        || StartsWithInsensitive(name, "slot_")
        || StartsWithInsensitive(name, "tmp");
}

void CheckResponseNameGrounding(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    if (response.Confidence <= 0.65)
    {
        return;
    }

    size_t unknownNames = 0;

    for (const auto& param : response.Params)
    {
        if (!IsKnownResponseName(request, param.Name))
        {
            ++unknownNames;
        }
    }

    for (const auto& local : response.Locals)
    {
        if (!IsKnownResponseName(request, local.Name))
        {
            ++unknownNames;
        }
    }

    if (unknownNames != 0)
    {
        AddIssue(
            report,
            "identifier.ungrounded_declared_names",
            "warning",
            "response declares parameter or local names not grounded in recovered analyzer or PDB facts",
            "ungrounded_names=" + std::to_string(unknownNames));
    }
}

std::string FindBlockIdContainingSite(const AnalysisFacts& facts, uint64_t site)
{
    for (const BasicBlock& block : facts.Blocks)
    {
        if (site >= block.StartAddress && site < block.EndAddress)
        {
            return block.Id;
        }
    }

    return std::string();
}

std::set<std::string> BuildEvidenceBlockSet(const AnalyzeResponse& response)
{
    std::set<std::string> blocks;

    for (const EvidenceItem& evidence : response.Evidence)
    {
        for (const std::string& blockId : evidence.Blocks)
        {
            blocks.insert(blockId);
        }
    }

    return blocks;
}

void AddRequiredEvidenceBlock(std::set<std::string>& blocks, const std::string& blockId)
{
    if (!blockId.empty())
    {
        blocks.insert(blockId);
    }
}

void CheckEvidenceCoverage(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    if (response.Confidence <= 0.70 || response.Evidence.empty() || request.Facts.Blocks.size() < 3)
    {
        return;
    }

    std::set<std::string> requiredBlocks;

    if (!request.Facts.Blocks.empty())
    {
        AddRequiredEvidenceBlock(requiredBlocks, request.Facts.Blocks.front().Id);
    }

    for (const NormalizedCondition& condition : request.Facts.NormalizedConditions)
    {
        AddRequiredEvidenceBlock(requiredBlocks, condition.BlockId);
    }

    for (const ControlFlowRegion& region : request.Facts.ControlFlow)
    {
        if (region.Confidence < 0.55)
        {
            continue;
        }

        AddRequiredEvidenceBlock(requiredBlocks, region.HeaderBlock);

        for (const std::string& blockId : region.LatchBlocks)
        {
            AddRequiredEvidenceBlock(requiredBlocks, blockId);
        }

        for (const std::string& blockId : region.ExitBlocks)
        {
            AddRequiredEvidenceBlock(requiredBlocks, blockId);
        }
    }

    for (const SwitchInfo& info : request.Facts.Switches)
    {
        AddRequiredEvidenceBlock(requiredBlocks, FindBlockIdContainingSite(request.Facts, info.Site));

        for (const uint64_t target : info.CaseTargets)
        {
            AddRequiredEvidenceBlock(requiredBlocks, FindBlockIdContainingSite(request.Facts, target));
        }
    }

    for (const CallTargetInfo& call : request.Facts.CallTargets)
    {
        if (call.Confidence >= 0.65)
        {
            AddRequiredEvidenceBlock(requiredBlocks, FindBlockIdContainingSite(request.Facts, call.Site));
        }
    }

    for (const DisassembledInstruction& instruction : request.Facts.Instructions)
    {
        if (instruction.IsReturn || instruction.IsConditionalBranch)
        {
            AddRequiredEvidenceBlock(requiredBlocks, FindBlockIdContainingSite(request.Facts, instruction.Address));
        }
    }

    if (requiredBlocks.size() < 3)
    {
        return;
    }

    const std::set<std::string> evidencedBlocks = BuildEvidenceBlockSet(response);
    size_t covered = 0;

    for (const std::string& blockId : requiredBlocks)
    {
        covered += evidencedBlocks.find(blockId) != evidencedBlocks.end() ? 1U : 0U;
    }

    const double coverage = static_cast<double>(covered) / static_cast<double>(requiredBlocks.size());

    if (coverage < 0.45)
    {
        ++report.MissingEvidence;
        AddIssue(
            report,
            "evidence.low_coverage",
            "warning",
            "response evidence covers too few high-signal analyzer blocks for its confidence",
            "covered=" + std::to_string(covered) + " required=" + std::to_string(requiredBlocks.size()));
    }
}

void CheckEvidenceGraphConsistency(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    std::set<std::string> blockIds;
    std::set<std::string> nodeIds;

    for (const BasicBlock& block : request.Facts.Blocks)
    {
        blockIds.insert(block.Id);
    }

    if (request.Facts.EvidenceGraph.Nodes.empty()
        && (!request.Facts.IrValues.empty()
            || !request.Facts.BlockValueStates.empty()
            || !request.Facts.ControlFlow.empty()
            || !request.Facts.TypeHints.empty()
            || !request.Facts.CalleeSummaries.empty())
        && response.Confidence > 0.60)
    {
        ++report.MissingEvidence;
        AddIssue(
            report,
            "evidence_graph.missing",
            "warning",
            "high-confidence response has semantic analyzer facts but no evidence graph");
    }

    for (const EvidenceNode& node : request.Facts.EvidenceGraph.Nodes)
    {
        if (!node.Id.empty())
        {
            nodeIds.insert(node.Id);
        }

        if (!node.BlockId.empty() && blockIds.find(node.BlockId) == blockIds.end())
        {
            ++report.FactConflicts;
            AddIssue(
                report,
                "evidence_graph.node_block_missing",
                "warning",
                "evidence graph node references a missing basic block",
                node.Id + " block=" + node.BlockId);
        }
    }

    for (const EvidenceEdge& edge : request.Facts.EvidenceGraph.Edges)
    {
        if (nodeIds.find(edge.SourceId) == nodeIds.end()
            || nodeIds.find(edge.TargetId) == nodeIds.end())
        {
            ++report.FactConflicts;
            AddIssue(
                report,
                "evidence_graph.edge_endpoint_missing",
                "warning",
                "evidence graph edge references a missing node",
                edge.SourceId + " -> " + edge.TargetId);
        }
    }

    if (!request.Facts.EvidenceGraph.Nodes.empty()
        && request.Facts.EvidenceGraph.Coverage < 0.30
        && response.Confidence > 0.70)
    {
        ++report.MissingEvidence;
        AddIssue(
            report,
            "evidence_graph.low_coverage",
            "warning",
            "high-confidence response has weak analyzer evidence graph grounding",
            "coverage=" + std::to_string(request.Facts.EvidenceGraph.Coverage));
    }
}

void CheckBlockValueStateConsistency(const AnalyzeRequest& request, const AnalyzeResponse& response, VerifyReport& report)
{
    std::set<std::string> blockIds;
    std::set<std::string> valueIds;
    bool hasUnconvergedState = false;

    for (const BasicBlock& block : request.Facts.Blocks)
    {
        blockIds.insert(block.Id);
    }

    for (const IrValue& value : request.Facts.IrValues)
    {
        valueIds.insert(value.Id);
    }

    for (const BlockValueState& state : request.Facts.BlockValueStates)
    {
        if (!state.BlockId.empty() && blockIds.find(state.BlockId) == blockIds.end())
        {
            ++report.FactConflicts;
            AddIssue(
                report,
                "dataflow.block_state_missing_block",
                "warning",
                "block value state references a missing basic block",
                state.BlockId);
        }

        hasUnconvergedState = hasUnconvergedState || !state.Converged;

        auto checkValues = [&valueIds, &report](const std::vector<ReachingValue>& values, const std::string& direction)
        {
            for (const ReachingValue& value : values)
            {
                if (!value.ValueId.empty() && valueIds.find(value.ValueId) == valueIds.end())
                {
                    ++report.FactConflicts;
                    AddIssue(
                        report,
                        "dataflow.reaching_value_missing_ir",
                        "warning",
                        "block value state references a missing IR value",
                        direction + " " + value.Name + "=" + value.ValueId);
                }
            }
        };

        checkValues(state.LiveIn, "live_in");
        checkValues(state.LiveOut, "live_out");
    }

    if (hasUnconvergedState && response.Confidence > 0.70 && response.Uncertainties.empty())
    {
        ++report.MissingEvidence;
        AddIssue(
            report,
            "dataflow.unconverged_without_uncertainty",
            "warning",
            "high-confidence response omitted uncertainty despite unconverged block value dataflow");
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

std::vector<std::string> ExtractIdentifiers(const AnalyzeResponse& response)
{
    std::vector<std::string> identifiers;

    for (const PseudoCodeToken& token : CodeTokens(response))
    {
        if (token.Kind == "identifier" || token.Kind == "function_name")
        {
            identifiers.push_back(token.Text);
        }
    }

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

    for (const std::string& identifier : ExtractIdentifiers(response))
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

bool IsSafeFixSwitchValue(const std::string& value)
{
    if (value.empty())
    {
        return false;
    }

    for (const char ch : value)
    {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0
            || ch == '"'
            || ch == '\''
            || ch == ';'
            || ch == '\r'
            || ch == '\n')
        {
            return false;
        }
    }

    return true;
}

bool IsGenericUserVisibleName(const std::string& name)
{
    auto hasNumericSuffix = [&name](const std::string& prefix)
    {
        if (!StartsWithInsensitive(name, prefix) || name.size() <= prefix.size())
        {
            return false;
        }

        for (size_t index = prefix.size(); index < name.size(); ++index)
        {
            if (std::isdigit(static_cast<unsigned char>(name[index])) == 0)
            {
                return false;
            }
        }

        return true;
    };

    return hasNumericSuffix("arg")
        || hasNumericSuffix("v")
        || StartsWithInsensitive(name, "local_")
        || StartsWithInsensitive(name, "slot_")
        || StartsWithInsensitive(name, "tmp");
}

bool HasSuggestedFixSwitch(const std::vector<SuggestedFix>& fixes, const std::string& switchText)
{
    for (const SuggestedFix& fix : fixes)
    {
        if (fix.SwitchText == switchText)
        {
            return true;
        }
    }

    return false;
}

void AddSuggestedFix(
    std::vector<SuggestedFix>& fixes,
    const SuggestedFix& fix)
{
    if (fix.SwitchText.empty()
        || !IsSafeFixSwitchValue(fix.SwitchText)
        || HasSuggestedFixSwitch(fixes, fix.SwitchText)
        || fixes.size() >= 5)
    {
        return;
    }

    fixes.push_back(fix);
}

void AddNoReturnSuggestedFixes(
    const AnalyzeRequest& request,
    const AnalyzeResponse& response,
    std::vector<SuggestedFix>& fixes)
{
    for (const VerificationIssue& issue : response.Verifier.Issues)
    {
        if (issue.Code != "abi.call_noreturn_list_empty")
        {
            continue;
        }

        std::string target = TrimCopy(issue.Evidence);

        if (target.empty())
        {
            for (const CallSite& call : request.Facts.Calls)
            {
                if (!call.Returns)
                {
                    target = call.Target;
                    break;
                }
            }
        }

        if (target.empty())
        {
            continue;
        }

        SuggestedFix fix;
        fix.Kind = "noreturn";
        fix.SwitchText = "/fix:noreturn:" + target;
        fix.Reason = "mark recovered non-returning call so CFG and verifier agree";
        fix.Evidence = issue.Evidence.empty() ? target : issue.Evidence;
        fix.Confidence = 0.82;
        AddSuggestedFix(fixes, fix);
    }
}

void AddRenameSuggestedFixes(
    const AnalyzeRequest& request,
    const AnalyzeResponse& response,
    std::vector<SuggestedFix>& fixes)
{
    const size_t paramCount = (std::min)(response.Params.size(), request.Facts.Pdb.Params.size());

    for (size_t index = 0; index < paramCount; ++index)
    {
        const std::string& oldName = response.Params[index].Name;
        const std::string& newName = request.Facts.Pdb.Params[index].Name;

        if (!IsGenericUserVisibleName(oldName)
            || newName.empty()
            || oldName == newName)
        {
            continue;
        }

        SuggestedFix fix;
        fix.Kind = "rename";
        fix.SwitchText = "/fix:rename:" + oldName + "=" + newName;
        fix.Reason = "replace generic parameter name with scoped PDB name";
        fix.Evidence = "pdb_param:" + newName;
        fix.Site = request.Facts.Pdb.Params[index].Site;
        fix.Confidence = request.Facts.Pdb.Params[index].Confidence;
        AddSuggestedFix(fixes, fix);
    }

    const size_t prototypeCount = (std::min)(response.Params.size(), request.Facts.Pdb.PrototypeParameters.size());

    for (size_t index = 0; index < prototypeCount; ++index)
    {
        const std::string& oldName = response.Params[index].Name;
        const std::string& newName = request.Facts.Pdb.PrototypeParameters[index].Name;

        if (!IsGenericUserVisibleName(oldName)
            || newName.empty()
            || oldName == newName)
        {
            continue;
        }

        SuggestedFix fix;
        fix.Kind = "rename";
        fix.SwitchText = "/fix:rename:" + oldName + "=" + newName;
        fix.Reason = "replace generic parameter name with PDB prototype name";
        fix.Evidence = "pdb_prototype_param:" + newName;
        fix.Confidence = request.Facts.Pdb.PrototypeParameters[index].Confidence;
        AddSuggestedFix(fixes, fix);
    }

    const size_t localCount = (std::min)(response.Locals.size(), request.Facts.Pdb.Locals.size());

    for (size_t index = 0; index < localCount; ++index)
    {
        const std::string& oldName = response.Locals[index].Name;
        const std::string& newName = request.Facts.Pdb.Locals[index].Name;

        if (!IsGenericUserVisibleName(oldName)
            || newName.empty()
            || oldName == newName)
        {
            continue;
        }

        SuggestedFix fix;
        fix.Kind = "rename";
        fix.SwitchText = "/fix:rename:" + oldName + "=" + newName;
        fix.Reason = "replace generic local name with scoped PDB name";
        fix.Evidence = "pdb_local:" + newName;
        fix.Site = request.Facts.Pdb.Locals[index].Site;
        fix.Confidence = request.Facts.Pdb.Locals[index].Confidence;
        AddSuggestedFix(fixes, fix);
    }
}

bool HasTypeHintForExpression(const AnalysisFacts& facts, const std::string& expression)
{
    for (const TypeRecoveryHint& hint : facts.TypeHints)
    {
        if (hint.Expression == expression)
        {
            return true;
        }
    }

    return false;
}

void AddFieldSuggestedFixes(
    const AnalyzeRequest& request,
    std::vector<SuggestedFix>& fixes)
{
    for (const ObservedMemoryHotspot& hotspot : request.Facts.ObservedBehavior.MemoryHotspots)
    {
        const uint32_t totalAccesses = hotspot.ReadCount + hotspot.WriteCount;
        const std::string expression = TrimCopy(hotspot.Expression);

        if (totalAccesses < 4
            || expression.empty()
            || expression.find('[') == std::string::npos
            || ContainsInsensitive(expression, "rsp")
            || ContainsInsensitive(expression, "rbp")
            || HasTypeHintForExpression(request.Facts, expression))
        {
            continue;
        }

        SuggestedFix fix;
        fix.Kind = "field";
        fix.SwitchText = "/fix:field:" + expression + "=TYPE";
        fix.Reason = "replace TYPE with the real field type for a repeated observed memory hotspot";
        fix.Evidence = "hotspot_accesses=" + std::to_string(totalAccesses);
        fix.Site = hotspot.Sites.empty() ? 0 : hotspot.Sites.front();
        fix.Confidence = hotspot.Confidence;
        AddSuggestedFix(fixes, fix);
    }
}
}

VerifyReport VerifyResponse(const AnalyzeRequest& request, AnalyzeResponse& response)
{
    EnsurePseudoCodeTokens(response);

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
    CheckSwitchEvidenceConsistency(request, response, report);
    CheckCalleeSummaryConsistency(request, response, report);
    CheckRecoveredCallCoverage(request, response, report);
    CheckRecoveredCallArgumentConsistency(request, response, report);
    CheckResponseNameGrounding(request, response, report);
    CheckEvidenceCoverage(request, response, report);
    CheckEvidenceGraphConsistency(request, response, report);
    CheckBlockValueStateConsistency(request, response, report);

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

std::vector<SuggestedFix> BuildSuggestedFixes(
    const AnalyzeRequest& request,
    const AnalyzeResponse& response)
{
    std::vector<SuggestedFix> fixes;

    AddNoReturnSuggestedFixes(request, response, fixes);
    AddRenameSuggestedFixes(request, response, fixes);
    AddFieldSuggestedFixes(request, fixes);

    return fixes;
}
}
