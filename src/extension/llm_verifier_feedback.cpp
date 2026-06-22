#include "decomp/llm_verifier_feedback.h"

#include <array>
#include <cstddef>

#include "decomp/string_utils.h"
#include "decomp/types.h"

namespace decomp
{
namespace
{
struct VerifierIssueCorrectionRule
{
    std::array<const char*, 3> Codes = {};
    size_t CodeCount = 0;
    const char* Hint = "";
};

bool MatchesVerifierIssueCorrectionRule(
    const std::string& code,
    const VerifierIssueCorrectionRule& rule)
{
    for (size_t index = 0; index < rule.CodeCount; ++index)
    {
        if (rule.Codes[index] != nullptr && code == rule.Codes[index])
        {
            return true;
        }
    }

    return false;
}

std::string BuildVerifierIssueCorrectionHint(const VerificationIssue& issue)
{
    static const VerifierIssueCorrectionRule rules[] = {
        {
            {
                "obfuscation.dead_edge_claim_without_opaque_predicate",
                "obfuscation.dead_edge_claim_without_matching_evidence",
                "obfuscation.dead_edge_rendered_as_live"
            },
            3,
            "Do not prune or render a dead edge unless it is grounded by obfuscation.opaque_predicates or a semantic_control_flow dead edge; otherwise keep the branch visible or list uncertainty."
        },
        {
            {
                "obfuscation.substitution_claim_without_evidence",
                "obfuscation.substitution_memory_semantics_claim",
                "obfuscation.constant_return_contradiction"
            },
            3,
            "Remove unsupported substitution rewrites; use obfuscation.substitution_idioms only for local scalar simplifications, keep pointer, load, store, volatile, or alias-sensitive expressions uncertain, and honor proven opaque constant-return predicate bits exactly."
        },
        {
            {
                "obfuscation.dispatcher_claim_without_evidence",
                "obfuscation.raw_dispatcher_loop_without_uncertainty",
                "obfuscation.raw_dispatcher_emitted_with_deobf_on"
            },
            3,
            "Use obfuscation.dispatchers.recovered_edges or semantic_control_flow edges for recovered structure; when deobf is enabled and safe_to_rewrite_control_flow is true, do not emit a raw magic-state dispatcher chain as the primary pseudo_c."
        },
        {
            {
                "control_flow.edge_claim_without_evidence",
                nullptr,
                nullptr
            },
            1,
            "Remove invented control-flow edges unless they are present in raw CFG successors, semantic_control_flow edges, or obfuscation.dispatchers.recovered_edges; otherwise lower confidence and list the missing edge as uncertainty."
        },
        {
            {
                "control_flow.loop_without_back_edge",
                "control_flow.infinite_loop_without_exit",
                nullptr
            },
            2,
            "Do not introduce source-level loops unless recovered raw CFG or semantic_control_flow evidence contains a back edge; if an infinite dispatcher loop is emitted, include a real break, return, or loop condition for the recovered exit state."
        },
        {
            {
                "control_flow.switch_without_evidence",
                "control_flow.switch_without_case_evidence",
                "control_flow.too_many_switch_cases"
            },
            3,
            "Do not invent switch structure or extra cases unless grounded by recovered switch facts, case targets, or dispatcher recovered edges; otherwise emit simpler branch structure and uncertainty."
        },
        {
            {
                "branch.without_evidence",
                "branch.too_few_pseudo_conditions",
                nullptr
            },
            2,
            "Ground branch structure in normalized_conditions, conditional branch instructions, or semantic_control_flow facts; avoid adding or collapsing branches beyond recovered evidence."
        },
        {
            {
                "evidence.missing_for_high_confidence",
                "evidence.low_coverage",
                nullptr
            },
            2,
            "Add block-grounded evidence entries for high-signal blocks, calls, branches, and memory effects before keeping high confidence; otherwise lower confidence and explain the coverage gap in uncertainties."
        },
        {
            {
                "evidence_graph.missing",
                "evidence_graph.low_coverage",
                nullptr
            },
            2,
            "When evidence_graph is absent or weak, avoid presenting semantic claims as fully cross-checked; cite available facts directly, lower confidence, and add uncertainty about weak graph grounding."
        },
        {
            {
                "dataflow.unconverged_without_uncertainty",
                nullptr,
                nullptr
            },
            1,
            "When block_value_states are unconverged, avoid definitive reaching-value or alias-sensitive rewrites; add uncertainty and cap confidence until dataflow convergence is proven."
        },
        {
            {
                "call.arguments_excess",
                "call.argument_expression_omitted",
                "call.result_not_captured",
            },
            3,
            "Rewrite recovered helper calls using exact helper_call_contract and call_arguments expressions; capture used helper returns as target = Callee(args) directly and never assign from undefined placeholders such as result."
        },
        {
            {
                "identifier.undefined_result_placeholder",
                nullptr,
                nullptr
            },
            3,
            "Rewrite recovered helper calls using exact helper_call_contract and call_arguments expressions; capture used helper returns as target = Callee(args) directly and never assign from undefined placeholders such as result."
        }
    };

    for (const VerifierIssueCorrectionRule& rule : rules)
    {
        if (MatchesVerifierIssueCorrectionRule(issue.Code, rule))
        {
            return rule.Hint;
        }
    }

    if (StartsWithInsensitive(issue.Code, "obfuscation."))
    {
        return "Revise the obfuscation claim using only grounded obfuscation and semantic_control_flow facts, or lower confidence and move the claim to uncertainties.";
    }

    return std::string();
}

bool IsHardVerifierIssue(const VerificationIssue& issue)
{
    return issue.Severity == "error";
}
}

size_t CountHardVerifierIssues(const VerifyReport& report)
{
    size_t count = 0;

    for (const VerificationIssue& issue : report.Issues)
    {
        if (IsHardVerifierIssue(issue))
        {
            ++count;
        }
    }

    return count;
}

bool ShouldAcceptVerifierFeedbackRetry(
    const VerifyReport& originalReport,
    const VerifyReport& retryReport)
{
    const size_t originalHardIssues = CountHardVerifierIssues(originalReport);
    const size_t retryHardIssues = CountHardVerifierIssues(retryReport);

    if (originalHardIssues != 0)
    {
        return retryHardIssues < originalHardIssues;
    }

    if (retryReport.AdjustedConfidence + 0.02 >= originalReport.AdjustedConfidence)
    {
        return true;
    }

    return retryReport.FactConflicts < originalReport.FactConflicts;
}

bool ShouldRetryWithVerifierFeedback(const VerifyReport& report)
{
    if (!report.SchemaOk || report.AdjustedConfidence < 0.55)
    {
        return true;
    }

    for (const auto& issue : report.Issues)
    {
        if (issue.Severity == "error")
        {
            return true;
        }
    }

    return report.FactConflicts != 0 || report.MissingEvidence > 1;
}

std::string BuildVerifierFeedbackPrompt(const VerifyReport& report)
{
    std::string prompt;
    prompt += "\n\nVerifier feedback from the previous attempt:\n";
    prompt += "- Adjusted confidence: ";
    prompt += std::to_string(report.AdjustedConfidence);
    prompt += "\n";

    for (const auto& issue : report.Issues)
    {
        prompt += "- [";
        prompt += issue.Severity.empty() ? "warning" : issue.Severity;
        prompt += "/";
        prompt += issue.Code.empty() ? "unknown" : issue.Code;
        prompt += "] ";
        prompt += issue.Message;

        if (!issue.Evidence.empty())
        {
            prompt += " evidence: ";
            prompt += issue.Evidence;
        }

        const std::string correctionHint = BuildVerifierIssueCorrectionHint(issue);

        if (!correctionHint.empty())
        {
            prompt += " correction: ";
            prompt += correctionHint;
        }

        prompt += "\n";
    }

    prompt += "\nRevise the JSON response to satisfy the verifier. If the recovered facts are insufficient, lower confidence and explicitly list uncertainty instead of inventing unsupported code.\n";
    return prompt;
}
}
