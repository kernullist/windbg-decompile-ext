#pragma once

#include <vector>

#include "decomp/types.h"

namespace decomp
{
std::vector<PseudoCodeToken> TokenizePseudoCode(const std::string& pseudoCode);
void EnsurePseudoCodeTokens(AnalyzeResponse& response);
}
