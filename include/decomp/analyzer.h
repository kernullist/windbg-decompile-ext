#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "decomp/types.h"

namespace decomp
{
AnalysisFacts BuildAnalysisFacts(
    const std::string& queryText,
    const ModuleInfo& moduleInfo,
    DebugSessionKind sessionKind,
    const DecompOptions& options,
    uint64_t queryAddress,
    uint64_t entryAddress,
    const std::vector<FunctionRegion>& regions,
    const std::vector<uint8_t>& bytes,
    const std::vector<DisassembledInstruction>& rawInstructions);

std::string ComputeSha256Hex(const std::vector<uint8_t>& bytes);
}
