#pragma once

#include <cstddef>
#include <string>

namespace decomp
{
struct VerifyReport;

size_t CountHardVerifierIssues(const VerifyReport& report);
bool ShouldAcceptVerifierFeedbackRetry(
    const VerifyReport& originalReport,
    const VerifyReport& retryReport);
bool ShouldRetryWithVerifierFeedback(const VerifyReport& report);
std::string BuildVerifierFeedbackPrompt(const VerifyReport& report);
}
