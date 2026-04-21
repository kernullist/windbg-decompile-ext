#include "decomp/analyzer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>


#include "decomp/string_utils.h"


namespace decomp
{
namespace
{
const std::array<uint32_t, 64> kSha256RoundConstants = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
};

uint32_t RotateRight(uint32_t value, uint32_t count)
{
    return (value >> count) | (value << (32U - count));
}

uint32_t LoadBigEndianU32(const uint8_t* data)
{
    return (static_cast<uint32_t>(data[0]) << 24U)
        | (static_cast<uint32_t>(data[1]) << 16U)
        | (static_cast<uint32_t>(data[2]) << 8U)
        | static_cast<uint32_t>(data[3]);
}

void AppendBigEndianU64(std::vector<uint8_t>& buffer, uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
    {
        buffer.push_back(static_cast<uint8_t>((value >> shift) & 0xFFU));
    }
}

std::array<uint8_t, 32> ComputeSha256Bytes(const std::vector<uint8_t>& bytes)
{
    std::array<uint32_t, 8> state = {
        0x6A09E667U,
        0xBB67AE85U,
        0x3C6EF372U,
        0xA54FF53AU,
        0x510E527FU,
        0x9B05688CU,
        0x1F83D9ABU,
        0x5BE0CD19U
    };
    std::vector<uint8_t> padded = bytes;
    const uint64_t bitLength = static_cast<uint64_t>(bytes.size()) * 8ULL;

    padded.push_back(0x80U);

    while ((padded.size() % 64U) != 56U)
    {
        padded.push_back(0U);
    }

    AppendBigEndianU64(padded, bitLength);

    for (size_t offset = 0; offset < padded.size(); offset += 64U)
    {
        std::array<uint32_t, 64> schedule = {};

        for (size_t index = 0; index < 16U; ++index)
        {
            schedule[index] = LoadBigEndianU32(&padded[offset + (index * 4U)]);
        }

        for (size_t index = 16U; index < 64U; ++index)
        {
            const uint32_t sigma0 = RotateRight(schedule[index - 15U], 7U)
                ^ RotateRight(schedule[index - 15U], 18U)
                ^ (schedule[index - 15U] >> 3U);
            const uint32_t sigma1 = RotateRight(schedule[index - 2U], 17U)
                ^ RotateRight(schedule[index - 2U], 19U)
                ^ (schedule[index - 2U] >> 10U);

            schedule[index] = schedule[index - 16U]
                + sigma0
                + schedule[index - 7U]
                + sigma1;
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (size_t index = 0; index < 64U; ++index)
        {
            const uint32_t sum1 = RotateRight(e, 6U) ^ RotateRight(e, 11U) ^ RotateRight(e, 25U);
            const uint32_t choose = (e & f) ^ ((~e) & g);
            const uint32_t temp1 = h + sum1 + choose + kSha256RoundConstants[index] + schedule[index];
            const uint32_t sum0 = RotateRight(a, 2U) ^ RotateRight(a, 13U) ^ RotateRight(a, 22U);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = sum0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    std::array<uint8_t, 32> digest = {};

    for (size_t index = 0; index < state.size(); ++index)
    {
        digest[(index * 4U) + 0U] = static_cast<uint8_t>((state[index] >> 24U) & 0xFFU);
        digest[(index * 4U) + 1U] = static_cast<uint8_t>((state[index] >> 16U) & 0xFFU);
        digest[(index * 4U) + 2U] = static_cast<uint8_t>((state[index] >> 8U) & 0xFFU);
        digest[(index * 4U) + 3U] = static_cast<uint8_t>(state[index] & 0xFFU);
    }

    return digest;
}

std::string ExtractOperationText(const std::string& line)
{
    const std::string trimmed = TrimCopy(line);
    const size_t colon = trimmed.find(':');

    if (colon != std::string::npos && colon + 1 < trimmed.size())
    {
        const std::string afterColon = TrimCopy(trimmed.substr(colon + 1));

        if (!afterColon.empty() && std::isalpha(static_cast<unsigned char>(afterColon[0])) != 0)
        {
            return afterColon;
        }
    }

    std::string best = trimmed;
    size_t index = 0;

    while (index < trimmed.size())
    {
        size_t runStart = index;

        while (index < trimmed.size() && trimmed[index] == ' ')
        {
            ++index;
        }

        const size_t runLength = index - runStart;

        if (runLength >= 2 && index < trimmed.size())
        {
            const std::string candidate = TrimCopy(trimmed.substr(index));

            if (!candidate.empty() && std::isalpha(static_cast<unsigned char>(candidate[0])) != 0)
            {
                best = candidate;
            }
        }

        while (index < trimmed.size() && trimmed[index] != ' ')
        {
            ++index;
        }
    }

    return best;
}

std::string ExtractMnemonic(const std::string& operationText)
{
    const std::string trimmed = TrimCopy(operationText);
    const size_t firstSpace = trimmed.find(' ');

    if (firstSpace == std::string::npos)
    {
        return ToLowerAscii(trimmed);
    }

    return ToLowerAscii(trimmed.substr(0, firstSpace));
}

std::string ExtractOperandText(const std::string& operationText)
{
    const std::string trimmed = TrimCopy(operationText);
    const size_t firstSpace = trimmed.find(' ');

    if (firstSpace == std::string::npos)
    {
        return std::string();
    }

    return TrimCopy(trimmed.substr(firstSpace + 1));
}

bool IsConditionalJumpMnemonic(const std::string& mnemonic)
{
    return mnemonic.size() >= 2 && mnemonic[0] == 'j' && mnemonic != "jmp";
}

bool IsUnconditionalJumpMnemonic(const std::string& mnemonic)
{
    return mnemonic == "jmp";
}

bool IsReturnMnemonic(const std::string& mnemonic)
{
    return mnemonic == "ret" || mnemonic == "retn" || mnemonic == "retf";
}

bool IsCallMnemonic(const std::string& mnemonic)
{
    return mnemonic == "call";
}

bool IsIndirectOperand(const std::string& operand)
{
    static const std::array<const char*, 20> registers = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
        "r10", "r11", "r12", "r13", "r14", "r15", "eax", "ecx", "edx", "r11d"
    };

    if (operand.find('[') != std::string::npos || operand.find("ptr") != std::string::npos)
    {
        return true;
    }

    const std::string lower = ToLowerAscii(operand);

    for (const char* reg : registers)
    {
        if (TrimCopy(lower) == reg)
        {
            return true;
        }
    }

    return false;
}

bool TryExtractAddressToken(const std::string& text, uint64_t& address)
{
    std::string token;

    for (const char ch : text)
    {
        const bool isHexChar = std::isxdigit(static_cast<unsigned char>(ch)) != 0 || ch == '`' || ch == 'x' || ch == 'X';

        if (isHexChar)
        {
            token.push_back(ch);
            continue;
        }

        if (!token.empty())
        {
            if (TryParseUnsigned(token, address))
            {
                return true;
            }

            token.clear();
        }
    }

    if (!token.empty() && TryParseUnsigned(token, address))
    {
        return true;
    }

    return false;
}

bool IsNonvolatileRegisterPush(const std::string& operationText, std::string& reg)
{
    const std::string lower = ToLowerAscii(operationText);
    static const std::array<const char*, 8> registers = {
        "push rbx", "push rbp", "push rdi", "push rsi", "push r12", "push r13", "push r14", "push r15"
    };

    for (const char* entry : registers)
    {
        if (lower == entry)
        {
            reg = entry + 5;
            return true;
        }
    }

    return false;
}

bool IsNoReturnTarget(const std::string& target)
{
    return ContainsInsensitive(target, "__fastfail")
        || ContainsInsensitive(target, "RtlFailFast")
        || ContainsInsensitive(target, "RaiseFailFastException")
        || ContainsInsensitive(target, "TerminateProcess")
        || ContainsInsensitive(target, "ExitProcess");
}

bool LooksLikeSwitch(const DisassembledInstruction& instruction)
{
    return instruction.IsIndirect
        && instruction.IsUnconditionalBranch
        && instruction.OperandText.find('[') != std::string::npos;
}

bool IsTrapMnemonic(const std::string& mnemonic)
{
    return mnemonic == "int3"
        || mnemonic == "ud2"
        || mnemonic == "icebp"
        || mnemonic == "hlt";
}

bool IsTrapInstruction(const DisassembledInstruction& instruction)
{
    return IsTrapMnemonic(instruction.Mnemonic);
}

void AddUniqueSuccessor(BasicBlock& block, const std::string& successorId)
{
    if (successorId.empty())
    {
        return;
    }

    if (std::find(block.Successors.begin(), block.Successors.end(), successorId) == block.Successors.end())
    {
        block.Successors.push_back(successorId);
    }
}
std::vector<DisassembledInstruction> NormalizeInstructions(const std::vector<DisassembledInstruction>& rawInstructions)
{
    std::vector<DisassembledInstruction> normalized = rawInstructions;

    for (auto& instruction : normalized)
    {
        instruction.OperationText = ExtractOperationText(instruction.Text);
        instruction.Mnemonic = ExtractMnemonic(instruction.OperationText);
        instruction.OperandText = ExtractOperandText(instruction.OperationText);
        instruction.IsConditionalBranch = IsConditionalJumpMnemonic(instruction.Mnemonic);
        instruction.IsUnconditionalBranch = IsUnconditionalJumpMnemonic(instruction.Mnemonic);
        instruction.IsCall = IsCallMnemonic(instruction.Mnemonic);
        instruction.IsReturn = IsReturnMnemonic(instruction.Mnemonic);
        instruction.IsIndirect = IsIndirectOperand(instruction.OperandText);
        instruction.HasBranchTarget = false;
        instruction.BranchTarget = 0;

        if (instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsCall)
        {
            if (TryExtractAddressToken(instruction.OperandText, instruction.BranchTarget))
            {
                instruction.HasBranchTarget = true;
            }
        }
    }

    return normalized;
}

StackFrameFacts InferStackFrame(const std::vector<DisassembledInstruction>& instructions)
{
    StackFrameFacts facts;

    for (size_t index = 0; index < instructions.size() && index < 24; ++index)
    {
        const auto& instruction = instructions[index];
        const std::string lower = ToLowerAscii(instruction.OperationText);
        std::string savedReg;

        if (IsNonvolatileRegisterPush(lower, savedReg))
        {
            if (std::find(facts.SavedNonvolatile.begin(), facts.SavedNonvolatile.end(), savedReg) == facts.SavedNonvolatile.end())
            {
                facts.SavedNonvolatile.push_back(savedReg);
            }
        }

        if (StartsWithInsensitive(lower, "sub rsp,"))
        {
            const std::string amountText = TrimCopy(lower.substr(8));
            uint64_t amount = 0;

            if (TryParseUnsigned(amountText, amount))
            {
                facts.StackAlloc = static_cast<uint32_t>(amount);
            }
        }

        if (lower == "push rbp" || lower == "mov rbp, rsp")
        {
            facts.FramePointer = true;
        }

        if (ContainsInsensitive(lower, "security_cookie") || ContainsInsensitive(lower, "security_check_cookie"))
        {
            facts.UsesCookie = true;
        }
    }

    return facts;
}

std::vector<BasicBlock> BuildBasicBlocks(const std::vector<DisassembledInstruction>& instructions)
{
    constexpr size_t kMaxAnalysisBlockInstructions = 24;
    std::vector<BasicBlock> blocks;

    if (instructions.empty())
    {
        return blocks;
    }

    std::set<uint64_t> leaders;
    leaders.insert(instructions.front().Address);

    for (size_t index = 0; index < instructions.size(); ++index)
    {
        const DisassembledInstruction& instruction = instructions[index];
        const bool hasNextInstruction = index + 1 < instructions.size();

        if ((instruction.IsConditionalBranch || instruction.IsUnconditionalBranch) && instruction.HasBranchTarget)
        {
            leaders.insert(instruction.BranchTarget);
        }

        if (!hasNextInstruction)
        {
            continue;
        }

        const DisassembledInstruction& nextInstruction = instructions[index + 1];

        if (instruction.IsConditionalBranch
            || instruction.IsUnconditionalBranch
            || instruction.IsReturn
            || instruction.IsCall
            || IsTrapInstruction(instruction))
        {
            leaders.insert(nextInstruction.Address);
        }

        if (instruction.EndAddress != nextInstruction.Address)
        {
            leaders.insert(nextInstruction.Address);
        }
    }

    BasicBlock current;
    size_t blockNumber = 0;

    for (size_t index = 0; index < instructions.size(); ++index)
    {
        const DisassembledInstruction& instruction = instructions[index];
        const bool hasNextInstruction = index + 1 < instructions.size();
        const bool startsNewBlock = current.Id.empty() || leaders.find(instruction.Address) != leaders.end();

        if (startsNewBlock)
        {
            if (!current.Id.empty())
            {
                blocks.push_back(current);
            }

            current = BasicBlock();
            current.Id = "bb" + std::to_string(blockNumber++);
            current.StartAddress = instruction.Address;
            current.EndAddress = instruction.EndAddress;
        }

        current.InstructionAddresses.push_back(instruction.Address);
        current.EndAddress = instruction.EndAddress;

        if (instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || IsTrapInstruction(instruction))
        {
            current.HasTerminal = true;
        }

        bool shouldSplit = false;

        if (instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || instruction.IsCall || IsTrapInstruction(instruction))
        {
            shouldSplit = true;
        }
        else if (hasNextInstruction)
        {
            const DisassembledInstruction& nextInstruction = instructions[index + 1];

            if (instruction.EndAddress != nextInstruction.Address)
            {
                shouldSplit = true;
            }
            else if (leaders.find(nextInstruction.Address) != leaders.end())
            {
                shouldSplit = true;
            }
            else if (current.InstructionAddresses.size() >= kMaxAnalysisBlockInstructions)
            {
                shouldSplit = true;
            }
        }

        if (shouldSplit)
        {
            blocks.push_back(current);
            current = BasicBlock();
        }
    }

    if (!current.Id.empty())
    {
        blocks.push_back(current);
    }

    std::unordered_map<uint64_t, std::string> blockIdByStart;

    for (const BasicBlock& block : blocks)
    {
        blockIdByStart[block.StartAddress] = block.Id;
    }

    for (size_t blockIndex = 0; blockIndex < blocks.size(); ++blockIndex)
    {
        BasicBlock& block = blocks[blockIndex];
        const uint64_t lastAddress = block.InstructionAddresses.back();
        auto instructionIt = std::find_if(
            instructions.begin(),
            instructions.end(),
            [lastAddress](const DisassembledInstruction& instruction)
            {
                return instruction.Address == lastAddress;
            });

        if (instructionIt == instructions.end())
        {
            continue;
        }

        const DisassembledInstruction& instruction = *instructionIt;

        if (instruction.IsConditionalBranch)
        {
            if (instruction.HasBranchTarget)
            {
                const auto target = blockIdByStart.find(instruction.BranchTarget);

                if (target != blockIdByStart.end())
                {
                    AddUniqueSuccessor(block, target->second);
                }
            }

            if (blockIndex + 1 < blocks.size())
            {
                AddUniqueSuccessor(block, blocks[blockIndex + 1].Id);
            }
        }
        else if (instruction.IsUnconditionalBranch)
        {
            if (instruction.HasBranchTarget)
            {
                const auto target = blockIdByStart.find(instruction.BranchTarget);

                if (target != blockIdByStart.end())
                {
                    AddUniqueSuccessor(block, target->second);
                }
            }
        }
        else if (!instruction.IsReturn && !IsTrapInstruction(instruction))
        {
            if (blockIndex + 1 < blocks.size())
            {
                AddUniqueSuccessor(block, blocks[blockIndex + 1].Id);
            }
        }
    }

    return blocks;
}
std::vector<CallSite> CollectCalls(const std::vector<DisassembledInstruction>& instructions, bool indirectOnly)
{
    std::vector<CallSite> calls;

    for (const auto& instruction : instructions)
    {
        if (!instruction.IsCall)
        {
            continue;
        }

        if (instruction.IsIndirect != indirectOnly)
        {
            continue;
        }

        CallSite call;
        call.Site = instruction.Address;
        call.Target = instruction.OperandText.empty() ? (indirectOnly ? "<indirect>" : "<unknown>") : instruction.OperandText;
        call.Kind = indirectOnly ? "indirect" : "direct";
        call.Returns = !IsNoReturnTarget(call.Target);
        calls.push_back(call);
    }

    return calls;
}

std::vector<SwitchInfo> CollectSwitches(const std::vector<DisassembledInstruction>& instructions)
{
    std::vector<SwitchInfo> switches;

    for (const auto& instruction : instructions)
    {
        if (!LooksLikeSwitch(instruction))
        {
            continue;
        }

        SwitchInfo info;
        info.Site = instruction.Address;
        info.CaseCount = 0;
        info.Detail = instruction.OperandText;
        switches.push_back(info);
    }

    return switches;
}

std::vector<MemoryAccess> CollectMemoryAccesses(const std::vector<DisassembledInstruction>& instructions)
{
    std::vector<MemoryAccess> accesses;

    for (const auto& instruction : instructions)
    {
        if (instruction.OperandText.find('[') == std::string::npos)
        {
            continue;
        }

        MemoryAccess access;
        access.Site = instruction.Address;
        access.Access = instruction.OperandText;
        accesses.push_back(access);
    }

    return accesses;
}

double ScoreConfidence(
    const ModuleInfo& moduleInfo,
    const std::vector<FunctionRegion>& regions,
    const StackFrameFacts& stackFrame,
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<std::string>& uncertainPoints,
    const std::vector<CallSite>& calls)
{
    double score = 0.35;

    if (!moduleInfo.ModuleName.empty())
    {
        score += 0.10;
    }

    if (!regions.empty())
    {
        score += 0.15;
    }

    if (!instructions.empty())
    {
        score += 0.10;
    }

    if (!blocks.empty())
    {
        score += 0.10;
    }

    if (!calls.empty())
    {
        score += 0.05;
    }

    if (stackFrame.StackAlloc != 0)
    {
        score += 0.05;
    }

    if (!stackFrame.SavedNonvolatile.empty())
    {
        score += 0.05;
    }

    if (stackFrame.UsesCookie)
    {
        score += 0.03;
    }

    score -= static_cast<double>(uncertainPoints.size()) * 0.05;
    return Clamp01(score);
}
}

AnalysisFacts BuildAnalysisFacts(
    const std::string& queryText,
    const ModuleInfo& moduleInfo,
    DebugSessionKind sessionKind,
    const DecompOptions& options,
    uint64_t queryAddress,
    uint64_t entryAddress,
    const std::vector<FunctionRegion>& regions,
    const std::vector<uint8_t>& bytes,
    const std::vector<DisassembledInstruction>& rawInstructions)
{
    AnalysisFacts facts;
    const std::vector<DisassembledInstruction> instructions = NormalizeInstructions(rawInstructions);

    facts.QueryText = queryText;
    facts.Module = moduleInfo;
    facts.Session = sessionKind;
    facts.Mode = options.UseLiveMemory ? AnalysisMode::LiveMemory : AnalysisMode::FileImage;
    facts.QueryAddress = queryAddress;
    facts.EntryAddress = entryAddress;
    facts.Regions = regions;
    facts.Rva = (moduleInfo.Base != 0 && entryAddress >= moduleInfo.Base) ? (entryAddress - moduleInfo.Base) : 0;
    facts.Instructions = instructions;
    facts.StackFrame = InferStackFrame(instructions);
    facts.Blocks = BuildBasicBlocks(instructions);
    facts.Calls = CollectCalls(instructions, false);
    facts.IndirectCalls = CollectCalls(instructions, true);
    facts.Switches = CollectSwitches(instructions);
    facts.MemoryAccesses = CollectMemoryAccesses(instructions);
    facts.BytesSha256 = ComputeSha256Hex(bytes);

    if (regions.empty())
    {
        facts.UncertainPoints.push_back("function range recovered heuristically");
    }

    if (instructions.empty())
    {
        facts.UncertainPoints.push_back("no instructions were disassembled");
    }

    if (facts.StackFrame.StackAlloc == 0)
    {
        facts.Facts.push_back("no stack allocation detected in prologue window");
    }
    else
    {
        facts.Facts.push_back("stack allocation detected: " + std::to_string(facts.StackFrame.StackAlloc));
    }

    if (!facts.StackFrame.SavedNonvolatile.empty())
    {
        facts.Facts.push_back("saved nonvolatile regs: " + JoinStrings(facts.StackFrame.SavedNonvolatile, ", "));
    }

    facts.Facts.push_back("basic block count: " + std::to_string(facts.Blocks.size()));
    facts.Facts.push_back("direct call count: " + std::to_string(facts.Calls.size()));
    facts.Facts.push_back("indirect call count: " + std::to_string(facts.IndirectCalls.size()));

    if (!facts.Switches.empty())
    {
        facts.Facts.push_back("switch candidates: " + std::to_string(facts.Switches.size()));
    }

    facts.PreLlmConfidence = ScoreConfidence(
        moduleInfo,
        regions,
        facts.StackFrame,
        instructions,
        facts.Blocks,
        facts.UncertainPoints,
        facts.Calls);

    return facts;
}

std::string ComputeSha256Hex(const std::vector<uint8_t>& bytes)
{
    const std::array<uint8_t, 32> digest = ComputeSha256Bytes(bytes);
    std::ostringstream stream;

    for (const uint8_t byte : digest)
    {
        stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
    }

    return stream.str();
}
}





