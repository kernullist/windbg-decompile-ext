#include "decomp/analyzer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>


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
    if (ContainsInsensitive(target, "__fastfail")
        || ContainsInsensitive(target, "RtlFailFast")
        || ContainsInsensitive(target, "RaiseFailFastException")
        || ContainsInsensitive(target, "TerminateProcess")
        || ContainsInsensitive(target, "ExitProcess"))
    {
        return true;
    }

    const char* overrides = std::getenv("DECOMP_NORETURN_OVERRIDES");

    if (overrides == nullptr)
    {
        return false;
    }

    std::string current;
    const std::string text = overrides;

    for (char ch : text)
    {
        if (ch == ',' || ch == ';')
        {
            const std::string token = TrimCopy(current);

            if (!token.empty() && ContainsInsensitive(target, token))
            {
                return true;
            }

            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    const std::string token = TrimCopy(current);
    return !token.empty() && ContainsInsensitive(target, token);
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
    static const std::array<const char*, 69> registers = {
        "al", "ah", "ax", "eax", "rax",
        "bl", "bh", "bx", "ebx", "rbx",
        "cl", "ch", "cx", "ecx", "rcx",
        "dl", "dh", "dx", "edx", "rdx",
        "sil", "si", "esi", "rsi",
        "dil", "di", "edi", "rdi",
        "bpl", "bp", "ebp", "rbp",
        "spl", "sp", "esp", "rsp",
        "r8b", "r8w", "r8d", "r8",
        "r9b", "r9w", "r9d", "r9",
        "r10b", "r10w", "r10d", "r10",
        "r11b", "r11w", "r11d", "r11",
        "r12b", "r12w", "r12d", "r12",
        "r13b", "r13w", "r13d", "r13",
        "r14b", "r14w", "r14d", "r14",
        "r15b", "r15w", "r15d", "r15",
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
        if (instruction.OperationText.empty())
        {
            instruction.OperationText = ExtractOperationText(instruction.Text);
        }

        if (instruction.Mnemonic.empty())
        {
            instruction.Mnemonic = ExtractMnemonic(instruction.OperationText);
        }

        if (instruction.OperandText.empty())
        {
            instruction.OperandText = ExtractOperandText(instruction.OperationText);
        }

        instruction.IsConditionalBranch = instruction.IsConditionalBranch || IsConditionalJumpMnemonic(instruction.Mnemonic);
        instruction.IsUnconditionalBranch = instruction.IsUnconditionalBranch || IsUnconditionalJumpMnemonic(instruction.Mnemonic);
        instruction.IsCall = instruction.IsCall || IsCallMnemonic(instruction.Mnemonic);
        instruction.IsReturn = instruction.IsReturn || IsReturnMnemonic(instruction.Mnemonic);
        instruction.IsIndirect = instruction.IsIndirect || IsIndirectOperand(instruction.OperandText);

        if (!instruction.HasBranchTarget && (instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsCall))
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

bool TryParseSignedValue(const std::string& text, int64_t& value)
{
    std::string clean = TrimCopy(text);

    if (clean.empty())
    {
        return false;
    }

    bool negative = false;

    if (clean.front() == '+')
    {
        clean = clean.substr(1);
    }
    else if (clean.front() == '-')
    {
        negative = true;
        clean = clean.substr(1);
    }

    uint64_t parsed = 0;

    if (!TryParseUnsigned(clean, parsed))
    {
        return false;
    }

    value = negative ? -static_cast<int64_t>(parsed) : static_cast<int64_t>(parsed);
    return true;
}

std::string RemoveAllCopy(std::string text, const std::string& needle)
{
    size_t position = 0;

    while ((position = text.find(needle, position)) != std::string::npos)
    {
        text.erase(position, needle.size());
    }

    return text;
}

std::string StripPointerDecorators(std::string operand)
{
    operand = ToLowerAscii(TrimCopy(operand));

    static const std::array<const char*, 18> decorators = {
        "byte ptr", "word ptr", "dword ptr", "qword ptr", "xmmword ptr", "ymmword ptr",
        "zmmword ptr", "tbyte ptr", "ptr", "short ", "near ", "far ", "cs:", "ds:",
        "es:", "fs:", "gs:", "ss:"
    };

    for (const char* decorator : decorators)
    {
        operand = RemoveAllCopy(operand, decorator);
    }

    while (operand.find("  ") != std::string::npos)
    {
        operand = RemoveAllCopy(operand, "  ");
    }

    return TrimCopy(operand);
}

std::string NormalizeRegisterAlias(const std::string& token)
{
    const std::string lower = ToLowerAscii(TrimCopy(token));

    if (lower == "al" || lower == "ah" || lower == "ax" || lower == "eax" || lower == "rax")
    {
        return "rax";
    }

    if (lower == "bl" || lower == "bh" || lower == "bx" || lower == "ebx" || lower == "rbx")
    {
        return "rbx";
    }

    if (lower == "cl" || lower == "ch" || lower == "cx" || lower == "ecx" || lower == "rcx")
    {
        return "rcx";
    }

    if (lower == "dl" || lower == "dh" || lower == "dx" || lower == "edx" || lower == "rdx")
    {
        return "rdx";
    }

    if (lower == "sil" || lower == "si" || lower == "esi" || lower == "rsi")
    {
        return "rsi";
    }

    if (lower == "dil" || lower == "di" || lower == "edi" || lower == "rdi")
    {
        return "rdi";
    }

    if (lower == "bpl" || lower == "bp" || lower == "ebp" || lower == "rbp")
    {
        return "rbp";
    }

    if (lower == "spl" || lower == "sp" || lower == "esp" || lower == "rsp")
    {
        return "rsp";
    }

    if (StartsWithInsensitive(lower, "r8"))
    {
        return "r8";
    }

    if (StartsWithInsensitive(lower, "r9"))
    {
        return "r9";
    }

    if (StartsWithInsensitive(lower, "r10"))
    {
        return "r10";
    }

    if (StartsWithInsensitive(lower, "r11"))
    {
        return "r11";
    }

    if (StartsWithInsensitive(lower, "r12"))
    {
        return "r12";
    }

    if (StartsWithInsensitive(lower, "r13"))
    {
        return "r13";
    }

    if (StartsWithInsensitive(lower, "r14"))
    {
        return "r14";
    }

    if (StartsWithInsensitive(lower, "r15"))
    {
        return "r15";
    }

    return lower;
}

std::vector<std::string> ExtractOperandRegisterTokens(const std::string& operand)
{
    std::vector<std::string> tokens;
    std::string current;
    const std::string lower = ToLowerAscii(operand);

    auto flushCurrent = [&tokens, &current]()
    {
        if (current.empty())
        {
            return;
        }

        if (IsRegisterName(current))
        {
            const std::string canonical = NormalizeRegisterAlias(current);

            if (std::find(tokens.begin(), tokens.end(), canonical) == tokens.end())
            {
                tokens.push_back(canonical);
            }
        }

        current.clear();
    };

    for (const char ch : lower)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0)
        {
            current.push_back(ch);
        }
        else
        {
            flushCurrent();
        }
    }

    flushCurrent();
    return tokens;
}

bool OperandReferencesRegister(const std::string& operand, const std::string& canonicalRegister)
{
    const std::vector<std::string> registers = ExtractOperandRegisterTokens(operand);
    return std::find(registers.begin(), registers.end(), canonicalRegister) != registers.end();
}

bool InstructionWritesDestinationOperand(const DisassembledInstruction& instruction, const std::vector<std::string>& operands)
{
    if (operands.empty())
    {
        return false;
    }

    if (instruction.IsConditionalBranch || instruction.IsUnconditionalBranch || instruction.IsReturn || instruction.IsCall)
    {
        return false;
    }

    return instruction.Mnemonic != "cmp"
        && instruction.Mnemonic != "test"
        && instruction.Mnemonic != "push";
}

bool DestinationOperandIsRead(const DisassembledInstruction& instruction, const std::vector<std::string>& operands)
{
    if (!InstructionWritesDestinationOperand(instruction, operands) || operands.empty())
    {
        return false;
    }

    if (instruction.Mnemonic == "mov"
        || instruction.Mnemonic == "movzx"
        || instruction.Mnemonic == "movsx"
        || instruction.Mnemonic == "movsxd"
        || instruction.Mnemonic == "lea"
        || instruction.Mnemonic == "pop"
        || StartsWithInsensitive(instruction.Mnemonic, "set"))
    {
        return false;
    }

    if (instruction.Mnemonic == "xor" && operands.size() >= 2)
    {
        const std::string left = StripPointerDecorators(operands[0]);
        const std::string right = StripPointerDecorators(operands[1]);

        if (!left.empty() && left == right)
        {
            return false;
        }
    }

    return true;
}

bool InstructionWritesRegister(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const std::string& canonicalRegister)
{
    return !operands.empty()
        && InstructionWritesDestinationOperand(instruction, operands)
        && OperandReferencesRegister(operands[0], canonicalRegister);
}

bool InstructionReadsRegister(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const std::string& canonicalRegister)
{
    if (operands.empty())
    {
        return false;
    }

    if (DestinationOperandIsRead(instruction, operands) && OperandReferencesRegister(operands[0], canonicalRegister))
    {
        return true;
    }

    const size_t startIndex = InstructionWritesDestinationOperand(instruction, operands) ? 1U : 0U;

    for (size_t index = startIndex; index < operands.size(); ++index)
    {
        if (OperandReferencesRegister(operands[index], canonicalRegister))
        {
            return true;
        }
    }

    return false;
}

std::string InferTypeHintFromWidth(uint32_t widthBits, bool pointerLike)
{
    if (pointerLike)
    {
        return "UNKNOWN_TYPE*";
    }

    switch (widthBits)
    {
    case 8:
        return "uint8_t";
    case 16:
        return "uint16_t";
    case 32:
        return "uint32_t";
    case 64:
        return "uint64_t";
    default:
        return "UNKNOWN_TYPE";
    }
}

bool IsZeroLikeOperand(const std::string& operand)
{
    int64_t value = 0;
    return TryParseSignedValue(StripPointerDecorators(operand), value) && value == 0;
}

std::string FormatHexMagnitude(uint64_t value)
{
    std::ostringstream stream;
    stream << std::hex << std::uppercase << value;
    return stream.str();
}

bool TryParseStackOperand(const std::string& operand, std::string& baseRegister, int64_t& offset)
{
    const std::string stripped = StripPointerDecorators(operand);
    const size_t open = stripped.find('[');
    const size_t close = stripped.rfind(']');

    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        return false;
    }

    std::string expression = stripped.substr(open + 1, close - open - 1);
    expression.erase(
        std::remove_if(
            expression.begin(),
            expression.end(),
            [](const unsigned char ch)
            {
                return std::isspace(ch) != 0;
            }),
        expression.end());

    if (expression.empty() || expression.find('*') != std::string::npos)
    {
        return false;
    }

    baseRegister.clear();
    offset = 0;
    int sign = 1;
    std::string current;

    auto consumeToken = [&baseRegister, &offset](const std::string& token, int tokenSign) -> bool
    {
        if (token.empty())
        {
            return false;
        }

        if (IsRegisterName(token))
        {
            const std::string canonical = NormalizeRegisterAlias(token);

            if (canonical != "rbp" && canonical != "rsp")
            {
                return false;
            }

            if (!baseRegister.empty() && baseRegister != canonical)
            {
                return false;
            }

            baseRegister = canonical;
            return true;
        }

        uint64_t parsed = 0;

        if (!TryParseUnsigned(token, parsed))
        {
            return false;
        }

        offset += static_cast<int64_t>(parsed) * static_cast<int64_t>(tokenSign);
        return true;
    };

    for (const char ch : expression)
    {
        if (ch == '+' || ch == '-')
        {
            if (!current.empty())
            {
                if (!consumeToken(current, sign))
                {
                    return false;
                }

                current.clear();
            }

            sign = (ch == '-') ? -1 : 1;
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty() && !consumeToken(current, sign))
    {
        return false;
    }

    return baseRegister == "rbp" || baseRegister == "rsp";
}

std::string BuildStackSlotKey(const std::string& baseRegister, int64_t offset)
{
    return baseRegister + ":" + std::to_string(offset);
}

std::string BuildStackSlotName(int64_t offset)
{
    const uint64_t magnitude = offset < 0 ? static_cast<uint64_t>(-(offset + 1)) + 1ULL : static_cast<uint64_t>(offset);
    return std::string(offset < 0 ? "local_" : "slot_") + FormatHexMagnitude(magnitude);
}

std::string BuildArgumentName(const std::string& canonicalRegister)
{
    if (canonicalRegister == "rcx")
    {
        return "arg1";
    }

    if (canonicalRegister == "rdx")
    {
        return "arg2";
    }

    if (canonicalRegister == "r8")
    {
        return "arg3";
    }

    if (canonicalRegister == "r9")
    {
        return "arg4";
    }

    return "arg";
}

std::vector<RecoveredArgument> RecoverArguments(const std::vector<DisassembledInstruction>& instructions)
{
    struct ArgumentStats
    {
        uint64_t FirstUseSite = 0;
        uint32_t UseCount = 0;
        uint32_t MemoryBaseUseCount = 0;
        uint32_t CompareUseCount = 0;
        uint32_t ArithmeticUseCount = 0;
    };

    static const std::array<const char*, 4> registers = { "rcx", "rdx", "r8", "r9" };
    std::unordered_map<std::string, ArgumentStats> stats;
    std::unordered_set<std::string> defined;

    for (const DisassembledInstruction& instruction : instructions)
    {
        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

        for (const char* reg : registers)
        {
            const std::string canonicalRegister = reg;
            const bool readsRegister = InstructionReadsRegister(instruction, operands, canonicalRegister);

            if (readsRegister && defined.find(canonicalRegister) == defined.end())
            {
                ArgumentStats& argument = stats[canonicalRegister];

                if (argument.FirstUseSite == 0)
                {
                    argument.FirstUseSite = instruction.Address;
                }

                ++argument.UseCount;

                if (instruction.OperandText.find('[') != std::string::npos)
                {
                    for (const auto& operand : operands)
                    {
                        if (operand.find('[') != std::string::npos && OperandReferencesRegister(operand, canonicalRegister))
                        {
                            ++argument.MemoryBaseUseCount;
                        }
                    }
                }

                if (instruction.Mnemonic == "cmp" || instruction.Mnemonic == "test")
                {
                    ++argument.CompareUseCount;
                }
                else if (instruction.Mnemonic == "add"
                    || instruction.Mnemonic == "sub"
                    || instruction.Mnemonic == "imul"
                    || instruction.Mnemonic == "shl"
                    || instruction.Mnemonic == "shr")
                {
                    ++argument.ArithmeticUseCount;
                }
            }
        }

        for (const char* reg : registers)
        {
            const std::string canonicalRegister = reg;

            if (InstructionWritesRegister(instruction, operands, canonicalRegister))
            {
                defined.insert(canonicalRegister);
            }
        }
    }

    std::vector<RecoveredArgument> arguments;

    for (const char* reg : registers)
    {
        const std::string canonicalRegister = reg;
        const auto it = stats.find(canonicalRegister);

        if (it == stats.end())
        {
            continue;
        }

        const ArgumentStats& info = it->second;
        RecoveredArgument argument;
        argument.Name = BuildArgumentName(canonicalRegister);
        argument.Register = canonicalRegister;
        argument.TypeHint = InferTypeHintFromWidth(64, info.MemoryBaseUseCount != 0);
        argument.RoleHint =
            (info.MemoryBaseUseCount != 0) ? "pointer_like"
            : (info.ArithmeticUseCount > info.CompareUseCount && info.ArithmeticUseCount != 0) ? "count_or_length"
            : (info.CompareUseCount != 0) ? "scalar_or_flag"
            : "scalar";
        argument.FirstUseSite = info.FirstUseSite;
        argument.UseCount = info.UseCount;
        argument.Confidence = Clamp01(
            0.55
            + (info.MemoryBaseUseCount != 0 ? 0.12 : 0.0)
            + (info.UseCount > 6 ? 0.18 : static_cast<double>(info.UseCount) * 0.03));
        arguments.push_back(argument);
    }

    return arguments;
}

std::vector<RecoveredLocal> RecoverLocals(
    const std::vector<MemoryAccess>& memoryAccesses,
    const StackFrameFacts& stackFrame)
{
    struct LocalStats
    {
        std::string BaseRegister;
        int64_t Offset = 0;
        uint32_t WidthBits = 0;
        uint64_t FirstSite = 0;
        uint64_t LastSite = 0;
        uint32_t ReadCount = 0;
        uint32_t WriteCount = 0;
        uint32_t AddressCount = 0;
    };

    std::unordered_map<std::string, LocalStats> statsByKey;

    for (const MemoryAccess& access : memoryAccesses)
    {
        if (access.BaseRegister != "rbp" && access.BaseRegister != "rsp")
        {
            continue;
        }

        int64_t offset = 0;

        if (!TryParseSignedValue(access.Displacement, offset))
        {
            offset = 0;
        }

        bool isCandidate = false;
        std::string storage = "stack_slot";

        if (access.BaseRegister == "rbp" && offset < 0)
        {
            isCandidate = true;
            storage = "stack_local";
        }
        else if (access.BaseRegister == "rsp" && offset >= 0
            && (stackFrame.StackAlloc == 0 || static_cast<uint32_t>(offset) < stackFrame.StackAlloc))
        {
            isCandidate = true;
            storage = "stack_local";
        }
        else if ((access.BaseRegister == "rbp" && offset > 0 && offset <= 0x40)
            || (access.BaseRegister == "rsp" && offset >= 0 && stackFrame.StackAlloc != 0 && static_cast<uint32_t>(offset) < stackFrame.StackAlloc + 0x40))
        {
            isCandidate = true;
            storage = "stack_home";
        }

        if (!isCandidate)
        {
            continue;
        }

        const std::string key = BuildStackSlotKey(access.BaseRegister, offset);
        LocalStats& stats = statsByKey[key];

        if (stats.BaseRegister.empty())
        {
            stats.BaseRegister = access.BaseRegister;
            stats.Offset = offset;
            stats.FirstSite = access.Site;
        }

        stats.LastSite = access.Site;
        stats.WidthBits = (std::max)(stats.WidthBits, access.WidthBits);

        if (access.Kind == "read")
        {
            ++stats.ReadCount;
        }
        else if (access.Kind == "write")
        {
            ++stats.WriteCount;
        }
        else if (access.Kind == "read_write")
        {
            ++stats.ReadCount;
            ++stats.WriteCount;
        }
        else if (access.Kind == "address")
        {
            ++stats.AddressCount;
        }

        (void)storage;
    }

    std::vector<RecoveredLocal> locals;

    for (const auto& entry : statsByKey)
    {
        const LocalStats& stats = entry.second;
        RecoveredLocal local;
        local.Name = BuildStackSlotName(stats.Offset);
        local.BaseRegister = stats.BaseRegister;
        local.Offset = stats.Offset;
        local.Storage = ((stats.BaseRegister == "rbp" && stats.Offset < 0)
            || (stats.BaseRegister == "rsp" && stats.Offset >= 0 && (stackFrame.StackAlloc == 0 || static_cast<uint32_t>(stats.Offset) < stackFrame.StackAlloc)))
            ? "stack_local"
            : "stack_home";
        local.TypeHint = InferTypeHintFromWidth(stats.WidthBits, stats.AddressCount != 0);
        local.RoleHint =
            (stats.AddressCount != 0) ? "address_taken_local"
            : (stats.ReadCount != 0 && stats.WriteCount != 0) ? "mutable_local"
            : (stats.WriteCount != 0) ? "spill_or_out_param"
            : "incoming_home_or_saved";
        local.FirstSite = stats.FirstSite;
        local.LastSite = stats.LastSite;
        local.ReadCount = stats.ReadCount;
        local.WriteCount = stats.WriteCount;
        local.Confidence = Clamp01(
            0.45
            + ((local.Storage == "stack_local") ? 0.15 : 0.05)
            + static_cast<double>(stats.ReadCount + stats.WriteCount + stats.AddressCount) * 0.04);
        locals.push_back(local);
    }

    std::sort(
        locals.begin(),
        locals.end(),
        [](const RecoveredLocal& left, const RecoveredLocal& right)
        {
            return left.FirstSite < right.FirstSite;
        });

    return locals;
}

std::unordered_map<std::string, std::string> BuildArgumentRegisterNameMap(const std::vector<RecoveredArgument>& arguments)
{
    std::unordered_map<std::string, std::string> mapping;

    for (const RecoveredArgument& argument : arguments)
    {
        mapping[argument.Register] = argument.Name;
    }

    return mapping;
}

std::unordered_map<std::string, std::string> BuildLocalKeyNameMap(const std::vector<RecoveredLocal>& locals)
{
    std::unordered_map<std::string, std::string> mapping;

    for (const RecoveredLocal& local : locals)
    {
        mapping[BuildStackSlotKey(local.BaseRegister, local.Offset)] = local.Name;
    }

    return mapping;
}

std::string RewriteOperandWithRecoveredNames(
    const std::string& operand,
    const std::unordered_map<std::string, std::string>& argumentRegisterMap,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    std::string baseRegister;
    int64_t offset = 0;

    if (TryParseStackOperand(operand, baseRegister, offset))
    {
        const auto localIt = localKeyNameMap.find(BuildStackSlotKey(baseRegister, offset));

        if (localIt != localKeyNameMap.end())
        {
            return localIt->second;
        }
    }

    const std::string stripped = StripPointerDecorators(operand);
    const std::vector<std::string> registers = ExtractOperandRegisterTokens(stripped);

    if (registers.size() == 1)
    {
        const auto argumentIt = argumentRegisterMap.find(registers.front());

        if (argumentIt != argumentRegisterMap.end())
        {
            return argumentIt->second;
        }
    }

    return stripped;
}

std::unordered_map<std::string, std::vector<std::string>> BuildBlockPredecessors(const std::vector<BasicBlock>& blocks)
{
    std::unordered_map<std::string, std::vector<std::string>> predecessors;

    for (const BasicBlock& block : blocks)
    {
        for (const std::string& successor : block.Successors)
        {
            predecessors[successor].push_back(block.Id);
        }
    }

    return predecessors;
}

std::string DescribeAssignmentValue(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const std::unordered_map<std::string, std::string>& argumentRegisterMap,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    if (instruction.Mnemonic == "xor" && operands.size() >= 2)
    {
        const std::string left = StripPointerDecorators(operands[0]);
        const std::string right = StripPointerDecorators(operands[1]);

        if (!left.empty() && left == right)
        {
            return "0";
        }
    }

    if (instruction.IsCall)
    {
        return "call_result";
    }

    if (StartsWithInsensitive(instruction.Mnemonic, "set"))
    {
        return instruction.Mnemonic + "_result";
    }

    if (operands.size() >= 2)
    {
        const std::string left = RewriteOperandWithRecoveredNames(operands[0], argumentRegisterMap, localKeyNameMap);
        const std::string right = RewriteOperandWithRecoveredNames(operands[1], argumentRegisterMap, localKeyNameMap);

        if (instruction.Mnemonic == "mov"
            || instruction.Mnemonic == "movzx"
            || instruction.Mnemonic == "movsx"
            || instruction.Mnemonic == "movsxd")
        {
            return right;
        }

        if (instruction.Mnemonic == "lea")
        {
            return "&" + right;
        }

        if (instruction.Mnemonic == "add")
        {
            return left + " + " + right;
        }

        if (instruction.Mnemonic == "sub")
        {
            return left + " - " + right;
        }

        if (instruction.Mnemonic == "and")
        {
            return left + " & " + right;
        }

        if (instruction.Mnemonic == "or")
        {
            return left + " | " + right;
        }

        if (instruction.Mnemonic == "shl")
        {
            return left + " << " + right;
        }

        if (instruction.Mnemonic == "shr")
        {
            return left + " >> " + right;
        }

        if (instruction.Mnemonic == "imul")
        {
            return left + " * " + right;
        }
    }

    if (!operands.empty())
    {
        const std::string operand = RewriteOperandWithRecoveredNames(operands[0], argumentRegisterMap, localKeyNameMap);

        if (instruction.Mnemonic == "inc")
        {
            return operand + " + 1";
        }

        if (instruction.Mnemonic == "dec")
        {
            return operand + " - 1";
        }

        if (instruction.Mnemonic == "neg")
        {
            return "-" + operand;
        }
    }

    return instruction.Mnemonic;
}

std::vector<ValueMerge> CollectValueMerges(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<MemoryAccess>& memoryAccesses,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;
    std::unordered_map<uint64_t, const MemoryAccess*> accessBySite;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> blockDefinitions;
    const std::unordered_map<std::string, std::string> argumentRegisterMap = BuildArgumentRegisterNameMap(arguments);
    const std::unordered_map<std::string, std::string> localKeyNameMap = BuildLocalKeyNameMap(locals);

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    for (const MemoryAccess& access : memoryAccesses)
    {
        accessBySite[access.Site] = &access;
    }

    for (const BasicBlock& block : blocks)
    {
        std::unordered_map<std::string, std::string> definitions;

        for (uint64_t address : block.InstructionAddresses)
        {
            const auto instructionIt = instructionByAddress.find(address);

            if (instructionIt == instructionByAddress.end())
            {
                continue;
            }

            const DisassembledInstruction& instruction = *instructionIt->second;
            const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
            const std::string value = DescribeAssignmentValue(instruction, operands, argumentRegisterMap, localKeyNameMap);

            for (const auto& argument : argumentRegisterMap)
            {
                if (InstructionWritesRegister(instruction, operands, argument.first))
                {
                    definitions[argument.second] = value;
                }
            }

            const auto accessIt = accessBySite.find(address);

            if (accessIt != accessBySite.end())
            {
                const MemoryAccess& access = *accessIt->second;
                int64_t offset = 0;

                if ((access.Kind == "write" || access.Kind == "read_write")
                    && (access.BaseRegister == "rbp" || access.BaseRegister == "rsp")
                    && TryParseSignedValue(access.Displacement, offset))
                {
                    const auto localIt = localKeyNameMap.find(BuildStackSlotKey(access.BaseRegister, offset));

                    if (localIt != localKeyNameMap.end())
                    {
                        definitions[localIt->second] = value;
                    }
                }
            }
        }

        blockDefinitions[block.Id] = std::move(definitions);
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);
    std::vector<ValueMerge> merges;

    for (const BasicBlock& block : blocks)
    {
        const auto predecessorIt = predecessors.find(block.Id);

        if (predecessorIt == predecessors.end() || predecessorIt->second.size() < 2)
        {
            continue;
        }

        std::unordered_map<std::string, std::vector<std::string>> valuesByVariable;
        std::unordered_map<std::string, std::vector<std::string>> predecessorByVariable;

        for (const std::string& predecessor : predecessorIt->second)
        {
            const auto definitionsIt = blockDefinitions.find(predecessor);

            if (definitionsIt == blockDefinitions.end())
            {
                continue;
            }

            for (const auto& definition : definitionsIt->second)
            {
                valuesByVariable[definition.first].push_back(definition.second);
                predecessorByVariable[definition.first].push_back(predecessor);
            }
        }

        for (const auto& entry : valuesByVariable)
        {
            std::set<std::string> uniqueValues(entry.second.begin(), entry.second.end());

            if (uniqueValues.size() < 2)
            {
                continue;
            }

            ValueMerge merge;
            merge.BlockId = block.Id;
            merge.Variable = entry.first;
            merge.IncomingValues.assign(uniqueValues.begin(), uniqueValues.end());
            merge.Predecessors = predecessorByVariable[entry.first];
            merge.Confidence = Clamp01(0.55 + static_cast<double>(merge.IncomingValues.size()) * 0.08);
            merges.push_back(std::move(merge));
        }
    }

    return merges;
}

std::unordered_map<uint64_t, std::string> BuildBlockIdByInstructionAddress(const std::vector<BasicBlock>& blocks)
{
    std::unordered_map<uint64_t, std::string> blockByAddress;

    for (const BasicBlock& block : blocks)
    {
        for (uint64_t address : block.InstructionAddresses)
        {
            blockByAddress[address] = block.Id;
        }
    }

    return blockByAddress;
}

bool IsConstantExpression(const std::string& expression)
{
    int64_t ignored = 0;
    return TryParseSignedValue(expression, ignored);
}

std::string BuildIrTarget(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const MemoryAccess* access,
    const std::unordered_map<std::string, std::string>& argumentRegisterMap,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    if (instruction.IsCall)
    {
        return "rax";
    }

    if (operands.empty())
    {
        return std::string();
    }

    if (access != nullptr
        && (access->Kind == "write" || access->Kind == "read_write")
        && (access->BaseRegister == "rbp" || access->BaseRegister == "rsp"))
    {
        int64_t offset = 0;

        if (TryParseSignedValue(access->Displacement, offset))
        {
            const auto localIt = localKeyNameMap.find(BuildStackSlotKey(access->BaseRegister, offset));

            if (localIt != localKeyNameMap.end())
            {
                return localIt->second;
            }
        }
    }

    const std::vector<std::string> destinationRegisters = ExtractOperandRegisterTokens(operands[0]);

    if (destinationRegisters.size() == 1 && operands[0].find('[') == std::string::npos)
    {
        return destinationRegisters.front();
    }

    const std::string rewritten = RewriteOperandWithRecoveredNames(operands[0], argumentRegisterMap, localKeyNameMap);

    if (!rewritten.empty())
    {
        return rewritten;
    }

    return StripPointerDecorators(operands[0]);
}

std::vector<IrValue> CollectIrValues(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<MemoryAccess>& memoryAccesses,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    std::unordered_map<uint64_t, const MemoryAccess*> accessBySite;
    std::unordered_map<uint64_t, std::string> blockByAddress = BuildBlockIdByInstructionAddress(blocks);
    const std::unordered_map<std::string, std::string> argumentRegisterMap = BuildArgumentRegisterNameMap(arguments);
    const std::unordered_map<std::string, std::string> localKeyNameMap = BuildLocalKeyNameMap(locals);
    std::unordered_map<std::string, std::string> latestCanonicalByTarget;
    std::unordered_map<std::string, std::string> latestIdByTarget;
    std::unordered_map<std::string, size_t> latestIndexByTarget;
    std::unordered_map<std::string, size_t> indexById;
    std::vector<IrValue> values;

    for (const MemoryAccess& access : memoryAccesses)
    {
        accessBySite[access.Site] = &access;
    }

    for (const DisassembledInstruction& instruction : instructions)
    {
        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
        const auto accessIt = accessBySite.find(instruction.Address);
        const MemoryAccess* access = accessIt == accessBySite.end() ? nullptr : accessIt->second;

        if (!instruction.IsCall && !InstructionWritesDestinationOperand(instruction, operands))
        {
            continue;
        }

        IrValue value;
        value.Id = "v" + std::to_string(values.size() + 1U);
        value.DefSite = instruction.Address;
        value.BlockId = blockByAddress[instruction.Address];
        value.Target = BuildIrTarget(instruction, operands, access, argumentRegisterMap, localKeyNameMap);
        value.Expression = DescribeAssignmentValue(instruction, operands, argumentRegisterMap, localKeyNameMap);

        if (value.Target.empty())
        {
            continue;
        }

        const auto copyIt = latestCanonicalByTarget.find(value.Expression);
        value.Canonical = copyIt != latestCanonicalByTarget.end() ? copyIt->second : value.Expression;
        value.IsConstant = IsConstantExpression(value.Canonical);
        value.IsCopy = copyIt != latestCanonicalByTarget.end() || value.Target == value.Expression;
        value.Kind = instruction.IsCall ? "call_result"
            : value.IsConstant ? "constant"
            : value.IsCopy ? "copy"
            : (access != nullptr && (access->Kind == "write" || access->Kind == "read_write")) ? "stack_store"
            : "assignment";
        value.Confidence = Clamp01(
            0.58
            + (value.IsConstant ? 0.12 : 0.0)
            + (value.IsCopy ? 0.06 : 0.0)
            + (!value.BlockId.empty() ? 0.06 : 0.0));

        for (const std::string& reg : ExtractOperandRegisterTokens(instruction.OperandText))
        {
            const auto latest = latestIdByTarget.find(reg);

            if (latest != latestIdByTarget.end()
                && std::find(value.Uses.begin(), value.Uses.end(), latest->second) == value.Uses.end())
            {
                value.Uses.push_back(latest->second);

                const auto usedIndex = indexById.find(latest->second);

                if (usedIndex != indexById.end() && usedIndex->second < values.size())
                {
                    values[usedIndex->second].IsDead = false;
                }
            }
        }

        const auto previousIndex = latestIndexByTarget.find(value.Target);

        if (previousIndex != latestIndexByTarget.end() && previousIndex->second < values.size())
        {
            values[previousIndex->second].IsDead = values[previousIndex->second].Uses.empty();
        }

        indexById[value.Id] = values.size();
        latestCanonicalByTarget[value.Target] = value.Canonical.empty() ? value.Expression : value.Canonical;
        latestIdByTarget[value.Target] = value.Id;
        latestIndexByTarget[value.Target] = values.size();
        values.push_back(std::move(value));
    }

    return values;
}

std::unordered_map<std::string, std::set<std::string>> BuildDominatorSets(const std::vector<BasicBlock>& blocks)
{
    std::unordered_map<std::string, std::set<std::string>> dominators;
    std::set<std::string> allBlocks;
    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);

    for (const BasicBlock& block : blocks)
    {
        allBlocks.insert(block.Id);
    }

    for (const BasicBlock& block : blocks)
    {
        if (&block == &blocks.front())
        {
            dominators[block.Id] = { block.Id };
        }
        else
        {
            dominators[block.Id] = allBlocks;
        }
    }

    bool changed = true;

    while (changed)
    {
        changed = false;

        for (size_t index = 1; index < blocks.size(); ++index)
        {
            const BasicBlock& block = blocks[index];
            const auto predecessorIt = predecessors.find(block.Id);
            std::set<std::string> next = allBlocks;

            if (predecessorIt == predecessors.end() || predecessorIt->second.empty())
            {
                next.clear();
            }
            else
            {
                for (const std::string& predecessor : predecessorIt->second)
                {
                    std::set<std::string> intersection;
                    const auto domIt = dominators.find(predecessor);

                    if (domIt == dominators.end())
                    {
                        continue;
                    }

                    std::set_intersection(
                        next.begin(), next.end(),
                        domIt->second.begin(), domIt->second.end(),
                        std::inserter(intersection, intersection.begin()));
                    next = std::move(intersection);
                }
            }

            next.insert(block.Id);

            if (dominators[block.Id] != next)
            {
                dominators[block.Id] = std::move(next);
                changed = true;
            }
        }
    }

    return dominators;
}

const NormalizedCondition* FindConditionForBlock(const std::vector<NormalizedCondition>& conditions, const std::string& blockId)
{
    for (const NormalizedCondition& condition : conditions)
    {
        if (condition.BlockId == blockId)
        {
            return &condition;
        }
    }

    return nullptr;
}

std::vector<ControlFlowRegion> AnalyzeControlFlow(
    const std::vector<BasicBlock>& blocks,
    const std::vector<NormalizedCondition>& conditions,
    const std::vector<SwitchInfo>& switches)
{
    std::vector<ControlFlowRegion> regions;

    if (blocks.empty())
    {
        return regions;
    }

    const std::unordered_map<std::string, std::set<std::string>> dominators = BuildDominatorSets(blocks);

    for (const BasicBlock& block : blocks)
    {
        for (const std::string& successor : block.Successors)
        {
            const auto domIt = dominators.find(block.Id);

            if (domIt != dominators.end() && domIt->second.find(successor) != domIt->second.end())
            {
                ControlFlowRegion loop;
                loop.Kind = "natural_loop";
                loop.HeaderBlock = successor;
                loop.LatchBlocks.push_back(block.Id);
                loop.BodyBlocks.push_back(successor);
                loop.BodyBlocks.push_back(block.Id);

                const NormalizedCondition* condition = FindConditionForBlock(conditions, successor);
                loop.Condition = condition != nullptr ? condition->Expression : std::string();
                loop.Evidence = block.Id + " -> " + successor + " back-edge";
                loop.Confidence = Clamp01(0.70 + (!loop.Condition.empty() ? 0.10 : 0.0));
                regions.push_back(std::move(loop));
            }
        }
    }

    for (const BasicBlock& block : blocks)
    {
        if (block.Successors.size() < 2)
        {
            continue;
        }

        ControlFlowRegion branch;
        branch.Kind = "if_else_candidate";
        branch.HeaderBlock = block.Id;
        branch.BodyBlocks = block.Successors;
        branch.ExitBlocks = block.Successors;

        const NormalizedCondition* condition = FindConditionForBlock(conditions, block.Id);
        branch.Condition = condition != nullptr ? condition->Expression : std::string();
        branch.Evidence = "conditional block with " + std::to_string(block.Successors.size()) + " successors";
        branch.Confidence = Clamp01(0.60 + (!branch.Condition.empty() ? 0.12 : 0.0));
        regions.push_back(std::move(branch));
    }

    for (const SwitchInfo& switchInfo : switches)
    {
        ControlFlowRegion region;
        region.Kind = "switch_candidate";
        region.Evidence = switchInfo.Detail;
        region.Confidence = Clamp01(0.52 + (switchInfo.CaseCount != 0 ? 0.18 : 0.0));

        for (const BasicBlock& block : blocks)
        {
            if (switchInfo.Site >= block.StartAddress && switchInfo.Site < block.EndAddress)
            {
                region.HeaderBlock = block.Id;
                region.BodyBlocks = block.Successors;
                break;
            }
        }

        regions.push_back(std::move(region));
    }

    return regions;
}

bool IsTailJumpCandidate(const DisassembledInstruction& instruction, uint64_t entryAddress)
{
    return instruction.IsUnconditionalBranch
        && instruction.HasBranchTarget
        && (instruction.BranchTarget < entryAddress || instruction.BranchTarget > entryAddress + 0x100000ULL);
}

AbiFacts AnalyzeAbiFacts(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<MemoryAccess>& memoryAccesses,
    const StackFrameFacts& stackFrame,
    uint64_t entryAddress)
{
    AbiFacts abi;
    abi.FramePointerEstablished = stackFrame.FramePointer;
    abi.FrameBase = stackFrame.FramePointer ? "rbp" : "rsp";
    abi.PrologRecognized = stackFrame.StackAlloc != 0 || stackFrame.FramePointer || !stackFrame.SavedNonvolatile.empty();
    abi.Confidence = abi.PrologRecognized ? 0.68 : 0.45;

    for (const MemoryAccess& access : memoryAccesses)
    {
        if (access.BaseRegister != "rsp" && access.BaseRegister != "rbp")
        {
            continue;
        }

        int64_t offset = 0;

        if (!TryParseSignedValue(access.Displacement, offset))
        {
            continue;
        }

        if (offset >= 0 && offset < 0x40)
        {
            const std::string slot = access.BaseRegister + HexS64(offset) + " at " + HexU64(access.Site);

            if (std::find(abi.HomeSlots.begin(), abi.HomeSlots.end(), slot) == abi.HomeSlots.end())
            {
                abi.HomeSlots.push_back(slot);
            }
        }
    }

    for (const DisassembledInstruction& instruction : instructions)
    {
        if (IsNoReturnCall(instruction))
        {
            abi.NoReturnCalls.push_back(HexU64(instruction.Address) + " -> " + instruction.OperandText);
        }

        if (IsTailJumpCandidate(instruction, entryAddress))
        {
            abi.TailCalls.push_back(HexU64(instruction.Address) + " -> " + HexU64(instruction.BranchTarget));
        }

        if (instruction.IsReturn)
        {
            abi.EpilogRecognized = true;
        }
    }

    if (instructions.size() <= 3 && !instructions.empty())
    {
        const DisassembledInstruction& last = instructions.back();

        if ((last.IsUnconditionalBranch && !last.IsIndirect) || (last.IsCall && !last.IsIndirect))
        {
            abi.Thunks.push_back(HexU64(instructions.front().Address) + " small wrapper ending at " + HexU64(last.Address));
        }
    }

    if (instructions.size() <= 6 && abi.TailCalls.size() == 1)
    {
        abi.ImportWrappers.push_back("single tail-call wrapper candidate");
    }

    if (!abi.HomeSlots.empty())
    {
        abi.Notes.push_back("shadow/home slot references detected in first 64 bytes above frame base");
        abi.Confidence = Clamp01(abi.Confidence + 0.08);
    }

    if (!abi.NoReturnCalls.empty())
    {
        abi.Notes.push_back("known no-return call terminates successor flow");
        abi.Confidence = Clamp01(abi.Confidence + 0.06);
    }

    if (!abi.TailCalls.empty())
    {
        abi.Notes.push_back("tail-call jump candidate detected");
        abi.Confidence = Clamp01(abi.Confidence + 0.05);
    }

    return abi;
}

std::string BuildMemoryExpression(const MemoryAccess& access)
{
    std::string expression = access.BaseRegister.empty() ? "mem" : access.BaseRegister;

    if (!access.Displacement.empty() && access.Displacement != "0")
    {
        expression += access.Displacement.front() == '-' ? access.Displacement : ("+" + access.Displacement);
    }

    if (!access.IndexRegister.empty())
    {
        expression += "+" + access.IndexRegister;

        if (access.Scale > 1)
        {
            expression += "*" + std::to_string(access.Scale);
        }
    }

    return "[" + expression + "]";
}

bool IsLikelyPointerRegister(const std::vector<RecoveredArgument>& arguments, const std::string& reg)
{
    for (const RecoveredArgument& argument : arguments)
    {
        if (argument.Register == reg && (argument.RoleHint == "pointer_like" || argument.TypeHint.find('*') != std::string::npos))
        {
            return true;
        }
    }

    return false;
}

bool IsPowerOfTwo(uint64_t value)
{
    return value != 0 && (value & (value - 1ULL)) == 0;
}

std::vector<TypeRecoveryHint> CollectTypeRecoveryHints(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<MemoryAccess>& memoryAccesses,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    std::vector<TypeRecoveryHint> hints;

    auto addHint = [&hints](TypeRecoveryHint hint)
    {
        const auto duplicate = std::find_if(
            hints.begin(),
            hints.end(),
            [&hint](const TypeRecoveryHint& existing)
            {
                return existing.Site == hint.Site
                    && existing.Expression == hint.Expression
                    && existing.Kind == hint.Kind
                    && existing.Type == hint.Type;
            });

        if (duplicate == hints.end())
        {
            hints.push_back(std::move(hint));
        }
    };

    for (const RecoveredArgument& argument : arguments)
    {
        TypeRecoveryHint hint;
        hint.Site = argument.FirstUseSite;
        hint.Expression = argument.Name;
        hint.Type = argument.TypeHint;
        hint.Source = "argument_usage";
        hint.Kind = argument.RoleHint;
        hint.Evidence = argument.Register + " first used " + std::to_string(argument.UseCount) + " times before definition";
        hint.PointerLike = argument.TypeHint.find('*') != std::string::npos || argument.RoleHint == "pointer_like";
        hint.Confidence = argument.Confidence;
        addHint(std::move(hint));
    }

    for (const RecoveredLocal& local : locals)
    {
        TypeRecoveryHint hint;
        hint.Site = local.FirstSite;
        hint.Expression = local.Name;
        hint.Type = local.TypeHint;
        hint.Source = "stack_usage";
        hint.Kind = local.RoleHint;
        hint.Evidence = local.Storage + " " + local.BaseRegister + HexS64(local.Offset);
        hint.PointerLike = local.TypeHint.find('*') != std::string::npos;
        hint.Confidence = local.Confidence;
        addHint(std::move(hint));
    }

    for (const MemoryAccess& access : memoryAccesses)
    {
        int64_t displacement = 0;
        const bool hasDisplacement = TryParseSignedValue(access.Displacement, displacement);

        if (!access.BaseRegister.empty() && access.BaseRegister != "rsp" && access.BaseRegister != "rbp" && IsLikelyPointerRegister(arguments, access.BaseRegister))
        {
            TypeRecoveryHint hint;
            hint.Site = access.Site;
            hint.Expression = BuildMemoryExpression(access);
            hint.Type = InferTypeHintFromWidth(access.WidthBits, false);
            hint.Source = "pointer_field_offset";
            hint.Kind = "field_offset";
            hint.Evidence = access.BaseRegister + (hasDisplacement ? HexS64(displacement) : std::string()) + " width=" + std::to_string(access.WidthBits);
            hint.PointerLike = false;
            hint.ArrayLike = !access.IndexRegister.empty();
            hint.Confidence = Clamp01(0.54 + (hasDisplacement ? 0.08 : 0.0) + (hint.ArrayLike ? 0.08 : 0.0));
            addHint(std::move(hint));
        }

        if (!access.IndexRegister.empty() && access.Scale > 1)
        {
            TypeRecoveryHint hint;
            hint.Site = access.Site;
            hint.Expression = BuildMemoryExpression(access);
            hint.Type = InferTypeHintFromWidth(access.WidthBits, false) + "[]";
            hint.Source = "scaled_index_memory";
            hint.Kind = "array_like";
            hint.Evidence = access.IndexRegister + "*" + std::to_string(access.Scale);
            hint.ArrayLike = true;
            hint.Confidence = 0.70;
            addHint(std::move(hint));
        }

        if (access.WidthBits == 64 && hasDisplacement && displacement == 0 && access.Kind == "read")
        {
            TypeRecoveryHint hint;
            hint.Site = access.Site;
            hint.Expression = BuildMemoryExpression(access);
            hint.Type = "vtable_or_function_table*";
            hint.Source = "qword_zero_offset_read";
            hint.Kind = "vtable_candidate";
            hint.Evidence = "qword read from object base";
            hint.PointerLike = true;
            hint.Confidence = 0.48;
            addHint(std::move(hint));
        }
    }

    for (const DisassembledInstruction& instruction : instructions)
    {
        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

        if (operands.size() != 2)
        {
            continue;
        }

        if (instruction.Mnemonic == "cmp")
        {
            uint64_t value = 0;
            std::string expression;

            if (TryParseUnsigned(StripPointerDecorators(operands[0]), value))
            {
                expression = StripPointerDecorators(operands[1]);
            }
            else if (TryParseUnsigned(StripPointerDecorators(operands[1]), value))
            {
                expression = StripPointerDecorators(operands[0]);
            }
            else
            {
                continue;
            }

            TypeRecoveryHint hint;
            hint.Site = instruction.Address;
            hint.Expression = expression;
            hint.Type = "enum_like_uint";
            hint.Source = "compare_immediate";
            hint.Kind = "enum_like";
            hint.Evidence = instruction.OperationText;
            hint.EnumLike = true;
            hint.Confidence = 0.58;
            addHint(std::move(hint));
        }
        else if (instruction.Mnemonic == "test" || instruction.Mnemonic == "and")
        {
            uint64_t value = 0;
            std::string expression;

            if (TryParseUnsigned(StripPointerDecorators(operands[0]), value))
            {
                expression = StripPointerDecorators(operands[1]);
            }
            else if (TryParseUnsigned(StripPointerDecorators(operands[1]), value))
            {
                expression = StripPointerDecorators(operands[0]);
            }
            else
            {
                continue;
            }

            TypeRecoveryHint hint;
            hint.Site = instruction.Address;
            hint.Expression = expression;
            hint.Type = IsPowerOfTwo(value) ? "single_bit_flag" : "bitmask_flags";
            hint.Source = "bit_test_immediate";
            hint.Kind = "bitflag_like";
            hint.Evidence = instruction.OperationText;
            hint.BitflagLike = true;
            hint.Confidence = IsPowerOfTwo(value) ? 0.68 : 0.60;
            addHint(std::move(hint));
        }
    }

    return hints;
}

std::string ClassifyCallIdiomName(const std::string& target)
{
    if (ContainsInsensitive(target, "memcpy") || ContainsInsensitive(target, "memmove"))
    {
        return "memory_copy";
    }

    if (ContainsInsensitive(target, "memset") || ContainsInsensitive(target, "RtlFillMemory") || ContainsInsensitive(target, "RtlZeroMemory"))
    {
        return "memory_fill";
    }

    if (ContainsInsensitive(target, "strcpy") || ContainsInsensitive(target, "wcscpy") || ContainsInsensitive(target, "strncpy") || ContainsInsensitive(target, "wcsncpy"))
    {
        return "string_copy";
    }

    if (ContainsInsensitive(target, "__security_check_cookie") || ContainsInsensitive(target, "__security_cookie"))
    {
        return "security_cookie";
    }

    if (ContainsInsensitive(target, "__chkstk") || ContainsInsensitive(target, "_alloca_probe"))
    {
        return "stack_probe";
    }

    if (ContainsInsensitive(target, "operator new") || ContainsInsensitive(target, "malloc") || ContainsInsensitive(target, "HeapAlloc"))
    {
        return "allocator";
    }

    if (ContainsInsensitive(target, "operator delete") || ContainsInsensitive(target, "free") || ContainsInsensitive(target, "HeapFree"))
    {
        return "deallocator";
    }

    return std::string();
}

std::vector<IdiomPattern> CollectIdiomPatterns(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<CallSite>& calls,
    const std::vector<MemoryAccess>& memoryAccesses,
    const AbiFacts& abi)
{
    std::vector<IdiomPattern> idioms;

    auto addIdiom = [&idioms](IdiomPattern idiom)
    {
        const auto duplicate = std::find_if(
            idioms.begin(),
            idioms.end(),
            [&idiom](const IdiomPattern& existing)
            {
                return existing.Site == idiom.Site && existing.Kind == idiom.Kind && existing.Name == idiom.Name;
            });

        if (duplicate == idioms.end())
        {
            idioms.push_back(std::move(idiom));
        }
    };

    for (const CallSite& call : calls)
    {
        const std::string idiomName = ClassifyCallIdiomName(call.Target);

        if (idiomName.empty())
        {
            continue;
        }

        IdiomPattern idiom;
        idiom.Site = call.Site;
        idiom.Kind = "library_call";
        idiom.Name = idiomName;
        idiom.Evidence = call.Target;
        idiom.Confidence = 0.78;

        if (idiomName == "memory_copy")
        {
            idiom.Summary = "standard memory copy helper";
            idiom.Replacement = "copy_bytes(dst, src, size)";
        }
        else if (idiomName == "memory_fill")
        {
            idiom.Summary = "standard memory fill/zero helper";
            idiom.Replacement = "fill_bytes(dst, value, size)";
        }
        else if (idiomName == "string_copy")
        {
            idiom.Summary = "standard string copy helper";
            idiom.Replacement = "copy_string(dst, src)";
        }
        else if (idiomName == "security_cookie")
        {
            idiom.Summary = "compiler security cookie check";
            idiom.Replacement = "verify_stack_cookie()";
        }
        else if (idiomName == "stack_probe")
        {
            idiom.Summary = "compiler stack probing helper";
            idiom.Replacement = "probe_stack_allocation(size)";
        }
        else if (idiomName == "allocator")
        {
            idiom.Summary = "heap allocation helper";
            idiom.Replacement = "allocate_memory(size)";
        }
        else if (idiomName == "deallocator")
        {
            idiom.Summary = "heap release helper";
            idiom.Replacement = "free_memory(ptr)";
        }

        addIdiom(std::move(idiom));
    }

    if (abi.PrologRecognized && abi.EpilogRecognized && !abi.NoReturnCalls.empty())
    {
        IdiomPattern idiom;
        idiom.Site = instructions.empty() ? 0 : instructions.front().Address;
        idiom.Kind = "compiler_pattern";
        idiom.Name = "fail_fast_guard";
        idiom.Summary = "guarded path terminates through a known no-return helper";
        idiom.Replacement = "if (guard_failed) fail_fast();";
        idiom.Evidence = JoinStrings(abi.NoReturnCalls, "; ");
        idiom.Confidence = 0.68;
        addIdiom(std::move(idiom));
    }

    for (size_t index = 0; index < instructions.size(); ++index)
    {
        const DisassembledInstruction& instruction = instructions[index];

        if (instruction.Mnemonic == "lea" && ContainsInsensitive(instruction.OperandText, "str"))
        {
            IdiomPattern idiom;
            idiom.Site = instruction.Address;
            idiom.Kind = "initializer";
            idiom.Name = "string_reference";
            idiom.Summary = "address of a string-like object is materialized";
            idiom.Replacement = "string_literal_or_global";
            idiom.Evidence = instruction.OperationText;
            idiom.Confidence = 0.48;
            addIdiom(std::move(idiom));
        }

        if (index + 2 < instructions.size())
        {
            size_t immediateStores = 0;

            for (size_t cursor = index; cursor < instructions.size() && cursor < index + 6; ++cursor)
            {
                const DisassembledInstruction& candidate = instructions[cursor];
                const std::vector<std::string> operands = SplitOperands(candidate.OperandText);

                if (candidate.Mnemonic == "mov"
                    && operands.size() == 2
                    && operands[0].find('[') != std::string::npos
                    && IsConstantExpression(StripPointerDecorators(operands[1])))
                {
                    ++immediateStores;
                }
            }

            if (immediateStores >= 3)
            {
                IdiomPattern idiom;
                idiom.Site = instruction.Address;
                idiom.Kind = "initializer";
                idiom.Name = "array_or_struct_initializer";
                idiom.Summary = "cluster of immediate stores initializes stack or aggregate storage";
                idiom.Replacement = "initialize_aggregate(...)";
                idiom.Evidence = std::to_string(immediateStores) + " immediate stores in a short window";
                idiom.Confidence = 0.62;
                addIdiom(std::move(idiom));
            }
        }
    }

    for (const MemoryAccess& access : memoryAccesses)
    {
        if (access.RipRelative && access.Kind == "read" && access.WidthBits == 64)
        {
            IdiomPattern idiom;
            idiom.Site = access.Site;
            idiom.Kind = "import_or_global";
            idiom.Name = "rip_relative_qword_load";
            idiom.Summary = "RIP-relative qword load likely references IAT or global state";
            idiom.Replacement = "global_or_import_reference";
            idiom.Evidence = access.Access;
            idiom.Confidence = 0.50;
            addIdiom(std::move(idiom));
        }
    }

    return idioms;
}

std::string InferOwnershipFromCalleeName(const std::string& name)
{
    if (ContainsInsensitive(name, "malloc")
        || ContainsInsensitive(name, "alloc")
        || ContainsInsensitive(name, "operator new")
        || ContainsInsensitive(name, "Create"))
    {
        return "may_return_owned_resource";
    }

    if (ContainsInsensitive(name, "free")
        || ContainsInsensitive(name, "delete")
        || ContainsInsensitive(name, "Close")
        || ContainsInsensitive(name, "Release"))
    {
        return "may_release_resource";
    }

    return "unknown";
}

std::string InferMemoryEffectsFromCalleeName(const std::string& name, const std::string& sideEffects)
{
    if (ContainsInsensitive(name, "memcpy") || ContainsInsensitive(name, "memmove") || ContainsInsensitive(name, "strcpy"))
    {
        return "writes destination buffer and reads source buffer";
    }

    if (ContainsInsensitive(name, "memset") || ContainsInsensitive(name, "ZeroMemory") || ContainsInsensitive(name, "FillMemory"))
    {
        return "writes destination buffer";
    }

    if (ContainsInsensitive(sideEffects, "terminates"))
    {
        return "does not return on success path";
    }

    if (ContainsInsensitive(sideEffects, "writes") || ContainsInsensitive(sideEffects, "mutates"))
    {
        return "may write through pointer arguments or global state";
    }

    return "unknown";
}

std::vector<CalleeSummary> CollectCalleeSummaries(const std::vector<CallSite>& calls)
{
    std::vector<CalleeSummary> summaries;

    for (const CallSite& call : calls)
    {
        CalleeSummary summary;
        summary.Site = call.Site;
        summary.Callee = call.Target;
        summary.ReturnType = call.Returns ? "UNKNOWN_TYPE" : "void/no-return";
        summary.ParameterModel = "ms_x64 register arguments plus stack arguments";
        summary.SideEffects = call.Returns ? "unknown" : "terminates control flow";
        summary.MemoryEffects = InferMemoryEffectsFromCalleeName(call.Target, summary.SideEffects);
        summary.Ownership = InferOwnershipFromCalleeName(call.Target);
        summary.Source = "call_site";
        summary.Confidence = call.Returns ? 0.42 : 0.66;
        summaries.push_back(std::move(summary));
    }

    return summaries;
}

std::string NormalizeBooleanDestinationKey(const std::string& operand)
{
    return StripPointerDecorators(operand);
}

std::string NormalizeBranchMnemonic(std::string mnemonic)
{
    mnemonic = ToLowerAscii(TrimCopy(mnemonic));

    if (mnemonic == "jz")
    {
        return "je";
    }

    if (mnemonic == "jnz")
    {
        return "jne";
    }

    if (mnemonic == "jnb")
    {
        return "jae";
    }

    if (mnemonic == "jc")
    {
        return "jb";
    }

    if (mnemonic == "jnc")
    {
        return "jae";
    }

    return mnemonic;
}

std::string NegateExpression(const std::string& expression)
{
    if (expression.empty())
    {
        return expression;
    }

    return "!(" + expression + ")";
}

struct ComparePattern
{
    std::string Kind;
    std::string Left;
    std::string Right;
    std::string RawLeftKey;
    std::string RawRightKey;
    bool Valid = false;
};

std::string BuildCompareExpression(const ComparePattern& pattern, const std::string& branchMnemonic)
{
    const std::string branch = NormalizeBranchMnemonic(branchMnemonic);

    if (pattern.Kind == "cmp")
    {
        if (branch == "je")
        {
            return pattern.Left + " == " + pattern.Right;
        }

        if (branch == "jne")
        {
            return pattern.Left + " != " + pattern.Right;
        }

        if (branch == "ja")
        {
            return pattern.Left + " >u " + pattern.Right;
        }

        if (branch == "jae")
        {
            return pattern.Left + " >=u " + pattern.Right;
        }

        if (branch == "jb")
        {
            return pattern.Left + " <u " + pattern.Right;
        }

        if (branch == "jbe")
        {
            return pattern.Left + " <=u " + pattern.Right;
        }

        if (branch == "jg")
        {
            return pattern.Left + " > " + pattern.Right;
        }

        if (branch == "jge")
        {
            return pattern.Left + " >= " + pattern.Right;
        }

        if (branch == "jl")
        {
            return pattern.Left + " < " + pattern.Right;
        }

        if (branch == "jle")
        {
            return pattern.Left + " <= " + pattern.Right;
        }

        if (branch == "js")
        {
            return "(" + pattern.Left + " - " + pattern.Right + ") < 0";
        }

        if (branch == "jns")
        {
            return "(" + pattern.Left + " - " + pattern.Right + ") >= 0";
        }
    }

    if (pattern.Kind == "test")
    {
        if (branch == "je")
        {
            if (pattern.RawLeftKey == pattern.RawRightKey)
            {
                return pattern.Left + " == 0";
            }

            return "(" + pattern.Left + " & " + pattern.Right + ") == 0";
        }

        if (branch == "jne")
        {
            if (pattern.RawLeftKey == pattern.RawRightKey)
            {
                return pattern.Left + " != 0";
            }

            return "(" + pattern.Left + " & " + pattern.Right + ") != 0";
        }

        if (branch == "js")
        {
            return pattern.Left + " < 0";
        }

        if (branch == "jns")
        {
            return pattern.Left + " >= 0";
        }
    }

    return std::string();
}

std::string BuildBranchExpression(
    const ComparePattern& pattern,
    const std::string& branchMnemonic,
    const std::unordered_map<std::string, std::string>& booleanDestinations)
{
    if (!pattern.Valid)
    {
        return std::string();
    }

    const std::string branch = NormalizeBranchMnemonic(branchMnemonic);
    const auto boolIt = booleanDestinations.find(pattern.RawLeftKey);

    if (boolIt != booleanDestinations.end()
        && ((pattern.Kind == "test" && pattern.RawLeftKey == pattern.RawRightKey)
            || (pattern.Kind == "cmp" && IsZeroLikeOperand(pattern.Right))))
    {
        if (branch == "je")
        {
            return NegateExpression(boolIt->second);
        }

        if (branch == "jne")
        {
            return boolIt->second;
        }
    }

    return BuildCompareExpression(pattern, branchMnemonic);
}

std::vector<NormalizedCondition> CollectNormalizedConditions(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;
    const std::unordered_map<std::string, std::string> argumentRegisterMap = BuildArgumentRegisterNameMap(arguments);
    const std::unordered_map<std::string, std::string> localKeyNameMap = BuildLocalKeyNameMap(locals);
    std::vector<NormalizedCondition> conditions;

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    for (const BasicBlock& block : blocks)
    {
        ComparePattern lastPattern;
        std::unordered_map<std::string, std::string> booleanDestinations;

        for (uint64_t address : block.InstructionAddresses)
        {
            const auto instructionIt = instructionByAddress.find(address);

            if (instructionIt == instructionByAddress.end())
            {
                continue;
            }

            const DisassembledInstruction& instruction = *instructionIt->second;
            const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

            if ((instruction.Mnemonic == "cmp" || instruction.Mnemonic == "test") && operands.size() >= 2)
            {
                lastPattern.Kind = instruction.Mnemonic;
                lastPattern.Left = RewriteOperandWithRecoveredNames(operands[0], argumentRegisterMap, localKeyNameMap);
                lastPattern.Right = RewriteOperandWithRecoveredNames(operands[1], argumentRegisterMap, localKeyNameMap);
                lastPattern.RawLeftKey = NormalizeBooleanDestinationKey(operands[0]);
                lastPattern.RawRightKey = NormalizeBooleanDestinationKey(operands[1]);
                lastPattern.Valid = true;
                continue;
            }

            if (StartsWithInsensitive(instruction.Mnemonic, "set") && operands.size() >= 1 && lastPattern.Valid)
            {
                std::string syntheticBranch = "j" + instruction.Mnemonic.substr(3);

                if (instruction.Mnemonic == "setz")
                {
                    syntheticBranch = "je";
                }
                else if (instruction.Mnemonic == "setnz")
                {
                    syntheticBranch = "jne";
                }

                const std::string expression = BuildCompareExpression(lastPattern, syntheticBranch);

                if (!expression.empty())
                {
                    booleanDestinations[NormalizeBooleanDestinationKey(operands[0])] = expression;
                }

                continue;
            }

            if (instruction.IsConditionalBranch)
            {
                const std::string expression = BuildBranchExpression(lastPattern, instruction.Mnemonic, booleanDestinations);

                if (expression.empty())
                {
                    continue;
                }

                NormalizedCondition condition;
                condition.Site = instruction.Address;
                condition.BlockId = block.Id;
                condition.BranchMnemonic = instruction.Mnemonic;
                condition.Expression = expression;
                condition.TrueTargetBlock = !block.Successors.empty() ? block.Successors.front() : std::string();
                condition.FalseTargetBlock = block.Successors.size() > 1 ? block.Successors[1] : std::string();
                condition.Confidence = Clamp01(0.58 + (StartsWithInsensitive(expression, "!(") ? 0.04 : 0.10));
                conditions.push_back(std::move(condition));
            }
        }
    }

    return conditions;
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
    facts.RecoveredArguments = RecoverArguments(instructions);
    facts.RecoveredLocals = RecoverLocals(facts.MemoryAccesses, facts.StackFrame);
    facts.ValueMerges = CollectValueMerges(instructions, facts.Blocks, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.IrValues = CollectIrValues(instructions, facts.Blocks, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.NormalizedConditions = CollectNormalizedConditions(instructions, facts.Blocks, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.ControlFlow = AnalyzeControlFlow(facts.Blocks, facts.NormalizedConditions, facts.Switches);
    facts.Abi = AnalyzeAbiFacts(instructions, facts.MemoryAccesses, facts.StackFrame, entryAddress);
    facts.TypeHints = CollectTypeRecoveryHints(instructions, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.Idioms = CollectIdiomPatterns(instructions, facts.Calls, facts.MemoryAccesses, facts.Abi);
    facts.CalleeSummaries = CollectCalleeSummaries(facts.Calls);
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

    if (!facts.RecoveredArguments.empty())
    {
        std::vector<std::string> argumentNames;

        for (const auto& argument : facts.RecoveredArguments)
        {
            argumentNames.push_back(argument.Name + ":" + argument.Register);
        }

        facts.Facts.push_back("recovered arguments: " + JoinStrings(argumentNames, ", "));
    }

    if (!facts.RecoveredLocals.empty())
    {
        facts.Facts.push_back("recovered stack locals: " + std::to_string(facts.RecoveredLocals.size()));
    }

    if (!facts.ValueMerges.empty())
    {
        facts.Facts.push_back("value merges detected: " + std::to_string(facts.ValueMerges.size()));
    }

    if (!facts.IrValues.empty())
    {
        size_t constants = 0;
        size_t copies = 0;
        size_t dead = 0;

        for (const auto& value : facts.IrValues)
        {
            constants += value.IsConstant ? 1U : 0U;
            copies += value.IsCopy ? 1U : 0U;
            dead += value.IsDead ? 1U : 0U;
        }

        facts.Facts.push_back(
            "ir values: "
            + std::to_string(facts.IrValues.size())
            + " (constants="
            + std::to_string(constants)
            + ", copies="
            + std::to_string(copies)
            + ", dead_defs="
            + std::to_string(dead)
            + ")");
    }

    if (!facts.NormalizedConditions.empty())
    {
        facts.Facts.push_back("normalized branch conditions: " + std::to_string(facts.NormalizedConditions.size()));
    }

    if (!facts.TypeHints.empty())
    {
        size_t enumHints = 0;
        size_t bitflagHints = 0;
        size_t arrayHints = 0;

        for (const auto& hint : facts.TypeHints)
        {
            enumHints += hint.EnumLike ? 1U : 0U;
            bitflagHints += hint.BitflagLike ? 1U : 0U;
            arrayHints += hint.ArrayLike ? 1U : 0U;
        }

        facts.Facts.push_back(
            "type recovery hints: "
            + std::to_string(facts.TypeHints.size())
            + " (enum_like="
            + std::to_string(enumHints)
            + ", bitflag_like="
            + std::to_string(bitflagHints)
            + ", array_like="
            + std::to_string(arrayHints)
            + ")");
    }

    if (!facts.Idioms.empty())
    {
        facts.Facts.push_back("idiom/library patterns: " + std::to_string(facts.Idioms.size()));
    }

    if (!facts.CalleeSummaries.empty())
    {
        facts.Facts.push_back("callee semantic summaries: " + std::to_string(facts.CalleeSummaries.size()));
    }

    if (!facts.ControlFlow.empty())
    {
        size_t loops = 0;
        size_t branches = 0;
        size_t switchCandidates = 0;

        for (const auto& region : facts.ControlFlow)
        {
            loops += region.Kind == "natural_loop" ? 1U : 0U;
            branches += region.Kind == "if_else_candidate" ? 1U : 0U;
            switchCandidates += region.Kind == "switch_candidate" ? 1U : 0U;
        }

        facts.Facts.push_back(
            "control-flow regions: "
            + std::to_string(facts.ControlFlow.size())
            + " (loops="
            + std::to_string(loops)
            + ", branches="
            + std::to_string(branches)
            + ", switches="
            + std::to_string(switchCandidates)
            + ")");
    }

    if (facts.Abi.PrologRecognized)
    {
        facts.Facts.push_back("x64 ABI frame recognized: frame_base=" + facts.Abi.FrameBase);
    }

    if (!facts.Abi.NoReturnCalls.empty())
    {
        facts.Facts.push_back("no-return calls: " + std::to_string(facts.Abi.NoReturnCalls.size()));
    }

    if (!facts.Abi.TailCalls.empty() || !facts.Abi.Thunks.empty() || !facts.Abi.ImportWrappers.empty())
    {
        facts.Facts.push_back(
            "tail/thunk/import-wrapper candidates: tail="
            + std::to_string(facts.Abi.TailCalls.size())
            + ", thunk="
            + std::to_string(facts.Abi.Thunks.size())
            + ", import_wrapper="
            + std::to_string(facts.Abi.ImportWrappers.size()));
    }

    if (facts.ControlFlow.empty() && facts.Blocks.size() > 1)
    {
        facts.UncertainPoints.push_back("control-flow structuring produced no high-confidence regions");
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





