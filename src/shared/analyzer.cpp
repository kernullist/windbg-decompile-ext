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

bool IsPotentialAddressTokenChar(const char ch)
{
    return std::isxdigit(static_cast<unsigned char>(ch)) != 0
        || ch == '`'
        || ch == 'x'
        || ch == 'X'
        || ch == 'h'
        || ch == 'H';
}

size_t CountAddressTokenDigits(std::string token)
{
    token.erase(
        std::remove(token.begin(), token.end(), '`'),
        token.end());

    if (StartsWithInsensitive(token, "0x"))
    {
        token = token.substr(2);
    }

    if (!token.empty() && (token.back() == 'h' || token.back() == 'H'))
    {
        token.pop_back();
    }

    if (token.empty())
    {
        return 0;
    }

    if (!std::all_of(
            token.begin(),
            token.end(),
            [](const unsigned char ch)
            {
                return std::isxdigit(ch) != 0;
            }))
    {
        return 0;
    }

    return token.size();
}

bool TryParseAbsoluteAddressToken(const std::string& token, uint64_t& address, size_t& digitCount)
{
    digitCount = CountAddressTokenDigits(token);

    if (digitCount < 8)
    {
        return false;
    }

    return TryParseUnsigned(token, address);
}

bool TryExtractAddressToken(const std::string& text, uint64_t& address)
{
    if (text.find('[') != std::string::npos)
    {
        return false;
    }

    struct AddressCandidate
    {
        uint64_t Value = 0;
        size_t DigitCount = 0;
    };

    std::vector<AddressCandidate> candidates;

    for (size_t start = 0; start < text.size();)
    {
        if (!IsPotentialAddressTokenChar(text[start]))
        {
            ++start;
            continue;
        }

        size_t end = start;

        while (end < text.size() && IsPotentialAddressTokenChar(text[end]))
        {
            ++end;
        }

        const char before = start == 0 ? '\0' : text[start - 1];
        const char after = end >= text.size() ? '\0' : text[end];

        if ((start == 0 || std::isalnum(static_cast<unsigned char>(before)) == 0)
            && (end >= text.size() || std::isalnum(static_cast<unsigned char>(after)) == 0))
        {
            const std::string token = text.substr(start, end - start);
            uint64_t parsed = 0;
            size_t digitCount = 0;

            if (TryParseAbsoluteAddressToken(token, parsed, digitCount))
            {
                candidates.push_back({ parsed, digitCount });
            }
        }

        start = end;
    }

    if (candidates.empty())
    {
        return false;
    }

    const auto best = std::max_element(
        candidates.begin(),
        candidates.end(),
        [](const AddressCandidate& left, const AddressCandidate& right)
        {
            return left.DigitCount < right.DigitCount;
        });

    address = best->Value;
    return true;
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

bool IsNoReturnCall(const DisassembledInstruction& instruction)
{
    return instruction.IsCall
        && !instruction.IsIndirect
        && IsNoReturnTarget(instruction.OperandText);
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

bool InstructionTerminatesBasicBlock(const DisassembledInstruction& instruction)
{
    return instruction.IsConditionalBranch
        || instruction.IsUnconditionalBranch
        || instruction.IsReturn
        || IsTrapInstruction(instruction)
        || IsNoReturnCall(instruction);
}

std::vector<std::string> SplitOperands(const std::string& operandText)
{
    std::vector<std::string> operands;
    std::string current;
    int bracketDepth = 0;

    for (const char ch : operandText)
    {
        if (ch == '[')
        {
            ++bracketDepth;
        }
        else if (ch == ']' && bracketDepth > 0)
        {
            --bracketDepth;
        }

        if (ch == ',' && bracketDepth == 0)
        {
            operands.push_back(TrimCopy(current));
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty())
    {
        operands.push_back(TrimCopy(current));
    }

    return operands;
}

bool IsRegisterName(const std::string& token)
{
    static const std::array<const char*, 49> registers = {
        "al", "ah", "ax", "eax", "rax",
        "bl", "bh", "bx", "ebx", "rbx",
        "cl", "ch", "cx", "ecx", "rcx",
        "dl", "dh", "dx", "edx", "rdx",
        "si", "esi", "rsi",
        "di", "edi", "rdi",
        "bp", "ebp", "rbp",
        "sp", "esp", "rsp",
        "r8", "r8d", "r9", "r9d", "r10", "r10d", "r11", "r11d",
        "r12", "r12d", "r13", "r13d", "r14", "r14d", "r15", "r15d",
        "rip"
    };
    const std::string lower = ToLowerAscii(TrimCopy(token));
    return std::find_if(
               registers.begin(),
               registers.end(),
               [&lower](const char* entry)
               {
                   return lower == entry;
               })
        != registers.end();
}

std::string DetectMemoryAccessSize(const std::string& operand, uint32_t& widthBits)
{
    widthBits = 0;
    const std::string lower = ToLowerAscii(operand);

    if (lower.find("zmmword ptr") != std::string::npos)
    {
        widthBits = 512;
        return "zmmword";
    }

    if (lower.find("ymmword ptr") != std::string::npos)
    {
        widthBits = 256;
        return "ymmword";
    }

    if (lower.find("xmmword ptr") != std::string::npos)
    {
        widthBits = 128;
        return "xmmword";
    }

    if (lower.find("tbyte ptr") != std::string::npos)
    {
        widthBits = 80;
        return "tbyte";
    }

    if (lower.find("qword ptr") != std::string::npos)
    {
        widthBits = 64;
        return "qword";
    }

    if (lower.find("dword ptr") != std::string::npos)
    {
        widthBits = 32;
        return "dword";
    }

    if (lower.find("word ptr") != std::string::npos)
    {
        widthBits = 16;
        return "word";
    }

    if (lower.find("byte ptr") != std::string::npos)
    {
        widthBits = 8;
        return "byte";
    }

    return "unknown";
}

bool IsReadModifyWriteMnemonic(const std::string& mnemonic)
{
    static const std::array<const char*, 26> mnemonics = {
        "adc", "add", "and", "btc", "btr", "bts", "cmpxchg", "cmpxchg8b", "cmpxchg16b",
        "dec", "inc", "neg", "not", "or", "rol", "ror", "rcl", "rcr", "sar", "sbb",
        "shl", "shr", "sub", "xadd", "xchg", "xor"
    };

    return std::find_if(
               mnemonics.begin(),
               mnemonics.end(),
               [&mnemonic](const char* entry)
               {
                   return mnemonic == entry;
               })
        != mnemonics.end();
}

std::string InferMemoryAccessKind(
    const DisassembledInstruction& instruction,
    size_t memoryOperandIndex,
    size_t operandCount)
{
    const std::string mnemonic = instruction.Mnemonic;

    if (mnemonic == "lea")
    {
        return "address";
    }

    if (mnemonic == "call" || mnemonic == "jmp" || mnemonic == "push" || mnemonic == "cmp" || mnemonic == "test")
    {
        return "read";
    }

    if (operandCount <= 1)
    {
        if (mnemonic == "pop" || StartsWithInsensitive(mnemonic, "set"))
        {
            return "write";
        }

        if (IsReadModifyWriteMnemonic(mnemonic))
        {
            return "read_write";
        }

        return "read";
    }

    if (memoryOperandIndex == 0)
    {
        if (mnemonic == "mov" || mnemonic == "movnti" || mnemonic == "movntdq" || mnemonic == "movntps" || mnemonic == "movntpd")
        {
            return "write";
        }

        if (StartsWithInsensitive(mnemonic, "set"))
        {
            return "write";
        }

        if (IsReadModifyWriteMnemonic(mnemonic))
        {
            return "read_write";
        }

        if (mnemonic == "cmp" || mnemonic == "test")
        {
            return "read";
        }

        return "write";
    }

    if (mnemonic == "xchg" || mnemonic == "cmpxchg" || mnemonic == "xadd")
    {
        return "read_write";
    }

    return "read";
}

bool TryExtractBracketExpression(const std::string& operand, std::string& expression)
{
    const size_t open = operand.find('[');
    const size_t close = operand.rfind(']');

    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        return false;
    }

    expression = TrimCopy(operand.substr(open + 1, close - open - 1));
    return !expression.empty();
}

void ParseMemoryExpression(const std::string& expression, MemoryAccess& access)
{
    int sign = 1;
    int64_t displacementValue = 0;
    bool hasDisplacement = false;
    std::string current;

    auto flushTerm = [&]()
    {
        std::string term = TrimCopy(current);
        current.clear();

        if (term.empty())
        {
            return;
        }

        term.erase(
            std::remove_if(
                term.begin(),
                term.end(),
                [](const unsigned char ch)
                {
                    return std::isspace(ch) != 0;
                }),
            term.end());

        if (term.empty())
        {
            return;
        }

        const size_t multiply = term.find('*');

        if (multiply != std::string::npos)
        {
            const std::string left = ToLowerAscii(term.substr(0, multiply));
            const std::string right = ToLowerAscii(term.substr(multiply + 1));
            std::string indexRegister;
            uint64_t scaleValue = 0;

            if (IsRegisterName(left) && TryParseUnsigned(right, scaleValue))
            {
                indexRegister = left;
            }
            else if (IsRegisterName(right) && TryParseUnsigned(left, scaleValue))
            {
                indexRegister = right;
            }

            if (!indexRegister.empty())
            {
                access.IndexRegister = indexRegister;
                access.Scale = static_cast<uint32_t>(scaleValue);
            }

            return;
        }

        const std::string lower = ToLowerAscii(term);

        if (IsRegisterName(lower))
        {
            if (access.BaseRegister.empty())
            {
                access.BaseRegister = lower;
            }
            else if (access.IndexRegister.empty())
            {
                access.IndexRegister = lower;
                access.Scale = access.Scale == 0 ? 1U : access.Scale;
            }

            access.RipRelative = access.RipRelative || lower == "rip";
            return;
        }

        uint64_t immediate = 0;

        if (TryParseUnsigned(term, immediate))
        {
            displacementValue += sign * static_cast<int64_t>(immediate);
            hasDisplacement = true;
        }
    };

    for (const char ch : expression)
    {
        if (ch == '+' || ch == '-')
        {
            flushTerm();
            sign = (ch == '-') ? -1 : 1;
            continue;
        }

        current.push_back(ch);
    }

    flushTerm();

    if (hasDisplacement)
    {
        access.Displacement = HexS64(displacementValue);
    }
}

bool TryBuildMemoryAccess(const DisassembledInstruction& instruction, MemoryAccess& access)
{
    const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
    size_t memoryOperandIndex = 0;
    std::string memoryOperand;

    for (size_t index = 0; index < operands.size(); ++index)
    {
        if (operands[index].find('[') != std::string::npos)
        {
            memoryOperand = operands[index];
            memoryOperandIndex = index;
            break;
        }
    }

    if (memoryOperand.empty())
    {
        return false;
    }

    access.Site = instruction.Address;
    access.Access = memoryOperand;
    access.Kind = InferMemoryAccessKind(instruction, memoryOperandIndex, operands.size());
    access.Size = DetectMemoryAccessSize(memoryOperand, access.WidthBits);

    std::string expression;

    if (TryExtractBracketExpression(memoryOperand, expression))
    {
        ParseMemoryExpression(expression, access);
    }

    if (!access.IndexRegister.empty() && access.Scale == 0)
    {
        access.Scale = 1;
    }

    return true;
}

bool TryParseImmediateOperand(const std::string& operand, uint64_t& value)
{
    const std::string trimmed = TrimCopy(operand);

    if (trimmed.empty()
        || trimmed.find('[') != std::string::npos
        || trimmed.find('!') != std::string::npos
        || trimmed.find('*') != std::string::npos)
    {
        return false;
    }

    return TryParseUnsigned(trimmed, value);
}

bool IsMaskValue(uint64_t value)
{
    return value != 0 && ((value + 1) & value) == 0;
}

uint32_t EstimateSwitchCaseCount(const std::vector<DisassembledInstruction>& instructions, size_t switchIndex)
{
    const size_t start = switchIndex > 8 ? switchIndex - 8 : 0;
    bool sawGuardBranch = false;

    for (size_t cursor = switchIndex; cursor > start; --cursor)
    {
        const DisassembledInstruction& candidate = instructions[cursor - 1];

        if (candidate.IsConditionalBranch)
        {
            sawGuardBranch = true;
            continue;
        }

        const std::vector<std::string> operands = SplitOperands(candidate.OperandText);

        if (candidate.Mnemonic == "cmp" && operands.size() == 2)
        {
            uint64_t immediate = 0;

            if (TryParseImmediateOperand(operands[1], immediate) && immediate < 0x10000ULL)
            {
                if (sawGuardBranch || cursor + 2 >= switchIndex)
                {
                    return static_cast<uint32_t>(immediate + 1ULL);
                }
            }
        }

        if (candidate.Mnemonic == "and" && operands.size() == 2)
        {
            uint64_t immediate = 0;

            if (TryParseImmediateOperand(operands[1], immediate) && immediate < 0x10000ULL && IsMaskValue(immediate))
            {
                return static_cast<uint32_t>(immediate + 1ULL);
            }
        }
    }

    return 0;
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

        if (InstructionTerminatesBasicBlock(instruction))
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

        if (InstructionTerminatesBasicBlock(instruction))
        {
            current.HasTerminal = true;
        }

        bool shouldSplit = false;

        if (InstructionTerminatesBasicBlock(instruction))
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
        else if (!instruction.IsReturn && !IsTrapInstruction(instruction) && !IsNoReturnCall(instruction))
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
        call.Returns = indirectOnly ? !IsNoReturnTarget(call.Target) : !IsNoReturnCall(instruction);
        calls.push_back(call);
    }

    return calls;
}

std::vector<SwitchInfo> CollectSwitches(const std::vector<DisassembledInstruction>& instructions)
{
    std::vector<SwitchInfo> switches;

    for (size_t index = 0; index < instructions.size(); ++index)
    {
        const auto& instruction = instructions[index];

        if (!LooksLikeSwitch(instruction))
        {
            continue;
        }

        SwitchInfo info;
        info.Site = instruction.Address;
        info.CaseCount = EstimateSwitchCaseCount(instructions, index);
        info.Detail = instruction.OperandText;

        if (info.CaseCount != 0)
        {
            info.Detail += " ; estimated_cases=" + std::to_string(info.CaseCount);
        }

        switches.push_back(info);
    }

    return switches;
}

std::vector<MemoryAccess> CollectMemoryAccesses(const std::vector<DisassembledInstruction>& instructions)
{
    std::vector<MemoryAccess> accesses;

    for (const auto& instruction : instructions)
    {
        MemoryAccess access;

        if (TryBuildMemoryAccess(instruction, access))
        {
            accesses.push_back(access);
        }
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
        uint32_t maxCaseCount = 0;

        for (const auto& info : facts.Switches)
        {
            maxCaseCount = (std::max)(maxCaseCount, info.CaseCount);
        }

        std::string switchFact = "switch candidates: " + std::to_string(facts.Switches.size());

        if (maxCaseCount != 0)
        {
            switchFact += " (max estimated cases: " + std::to_string(maxCaseCount) + ")";
        }

        facts.Facts.push_back(switchFact);
    }

    if (!facts.MemoryAccesses.empty())
    {
        size_t reads = 0;
        size_t writes = 0;
        size_t readWrites = 0;
        size_t addresses = 0;
        size_t ripRelative = 0;

        for (const auto& access : facts.MemoryAccesses)
        {
            if (access.Kind == "read")
            {
                ++reads;
            }
            else if (access.Kind == "write")
            {
                ++writes;
            }
            else if (access.Kind == "read_write")
            {
                ++readWrites;
            }
            else if (access.Kind == "address")
            {
                ++addresses;
            }

            if (access.RipRelative)
            {
                ++ripRelative;
            }
        }

        facts.Facts.push_back(
            "memory accesses: "
            + std::to_string(facts.MemoryAccesses.size())
            + " (read="
            + std::to_string(reads)
            + ", write="
            + std::to_string(writes)
            + ", read_write="
            + std::to_string(readWrites)
            + ", address="
            + std::to_string(addresses)
            + ", rip_relative="
            + std::to_string(ripRelative)
            + ")");
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





