#pragma once

#include <string>

#include "decomp/json.h"
#include "decomp/types.h"

namespace decomp
{
std::string SerializeAnalyzeRequest(const AnalyzeRequest& request, bool pretty = false);
std::string SerializeAnalyzeResponse(const AnalyzeResponse& response, bool pretty = false);

bool ParseAnalyzeRequest(const std::string& text, AnalyzeRequest& request, std::string& error);
bool ParseAnalyzeResponse(const std::string& text, AnalyzeResponse& response, std::string& error);

JsonValue ToJson(const AnalyzeRequest& request);
JsonValue ToJson(const AnalyzeResponse& response);
}
