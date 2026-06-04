#pragma once

#include "decomp/types.h"

#include <vector>

namespace decomp
{
VerifyReport VerifyResponse(const AnalyzeRequest& request, AnalyzeResponse& response);
std::vector<SuggestedFix> BuildSuggestedFixes(
    const AnalyzeRequest& request,
    const AnalyzeResponse& response);
}
