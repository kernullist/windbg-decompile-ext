#include "decomp/verifier.h"

#include <exception>
#include <set>

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
            }
        }
    }

    if (MentionsLoop(response) && !GraphHasBackEdge(request.Facts))
    {
        ++report.FactConflicts;
        report.Warnings.push_back("loop mentioned without a graph back-edge");
    }

    if (request.Facts.Instructions.empty() && response.Confidence > 0.50)
    {
        ++report.FactConflicts;
        report.Warnings.push_back("response confidence is high but no instructions were analyzed");
    }

    if (!request.Facts.UncertainPoints.empty() && response.Uncertainties.empty() && response.Confidence > 0.55)
    {
        report.Warnings.push_back("response omitted uncertainties despite analyzer uncertainty");
    }

    if (response.Params.size() > 4 && StartsWithInsensitive(request.Facts.CallingConvention, "ms_x64"))
    {
        ++report.FactConflicts;
        report.Warnings.push_back("parameter count exceeds obvious register argument slots");
    }

    const double blended = Clamp01((response.Confidence * 0.65) + (request.Facts.PreLlmConfidence * 0.35));
    double adjusted = blended;
    adjusted -= static_cast<double>(report.FactConflicts) * 0.10;
    adjusted -= static_cast<double>(report.MissingEvidence) * 0.05;

    if (!report.SchemaOk)
    {
        adjusted = 0.0;
        report.Warnings.push_back("response schema is incomplete");
    }

    report.AdjustedConfidence = Clamp01(adjusted);
    response.Verifier = report;
    return report;
}
}

