#pragma once

#include <string>

namespace decomp
{
struct VerifyReport;

bool ShouldRetryWithVerifierFeedback(const VerifyReport& report);
std::string BuildVerifierFeedbackPrompt(const VerifyReport& report);
}
