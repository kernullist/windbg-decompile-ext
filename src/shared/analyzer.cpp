#include "decomp/analyzer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
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
bool TryParseSignedValue(const std::string& text, int64_t& value);
bool IsVectorRegisterName(const std::string& token);
bool IsTailJumpCandidate(
    const DisassembledInstruction& instruction,
    uint64_t entryAddress,
    const std::set<uint64_t>* instructionAddresses);

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
        != registers.end()
        || IsVectorRegisterName(lower);
}

bool TryParseVectorRegisterName(const std::string& token, std::string& prefix, uint32_t& index)
{
    const std::string lower = ToLowerAscii(TrimCopy(token));
    static const std::array<const char*, 3> prefixes = { "xmm", "ymm", "zmm" };

    for (const char* candidatePrefix : prefixes)
    {
        if (!StartsWithInsensitive(lower, candidatePrefix))
        {
            continue;
        }

        const std::string suffix = lower.substr(std::strlen(candidatePrefix));

        if (suffix.empty())
        {
            return false;
        }

        uint32_t parsed = 0;

        for (const char ch : suffix)
        {
            if (std::isdigit(static_cast<unsigned char>(ch)) == 0)
            {
                return false;
            }

            parsed = (parsed * 10U) + static_cast<uint32_t>(ch - '0');
        }

        if (parsed > 31U)
        {
            return false;
        }

        prefix = candidatePrefix;
        index = parsed;
        return true;
    }

    return false;
}

bool IsVectorRegisterName(const std::string& token)
{
    std::string prefix;
    uint32_t index = 0;
    return TryParseVectorRegisterName(token, prefix, index);
}

std::string NormalizeVectorRegisterAlias(const std::string& token)
{
    std::string prefix;
    uint32_t index = 0;

    if (!TryParseVectorRegisterName(token, prefix, index))
    {
        return std::string();
    }

    return "xmm" + std::to_string(index);
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

    for (size_t index = 0; index < operands.size(); ++index)
    {
        if (operands[index].find('[') == std::string::npos)
        {
            continue;
        }

        access = MemoryAccess();
        access.Site = instruction.Address;
        access.Access = operands[index];
        access.Kind = InferMemoryAccessKind(instruction, index, operands.size());
        access.Size = DetectMemoryAccessSize(access.Access, access.WidthBits);

        std::string expression;

        if (TryExtractBracketExpression(access.Access, expression))
        {
            ParseMemoryExpression(expression, access);
        }

        if (!access.IndexRegister.empty() && access.Scale == 0)
        {
            access.Scale = 1;
        }

        return true;
    }

    return false;
}

std::vector<MemoryAccess> BuildExplicitMemoryAccesses(const DisassembledInstruction& instruction)
{
    std::vector<MemoryAccess> accesses;
    const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

    for (size_t index = 0; index < operands.size(); ++index)
    {
        if (operands[index].find('[') == std::string::npos)
        {
            continue;
        }

        MemoryAccess access;
        access.Site = instruction.Address;
        access.Access = operands[index];
        access.Kind = InferMemoryAccessKind(instruction, index, operands.size());
        access.Size = DetectMemoryAccessSize(access.Access, access.WidthBits);

        std::string expression;

        if (TryExtractBracketExpression(access.Access, expression))
        {
            ParseMemoryExpression(expression, access);
        }

        if (!access.IndexRegister.empty() && access.Scale == 0)
        {
            access.Scale = 1;
        }

        accesses.push_back(std::move(access));
    }

    return accesses;
}

MemoryAccess MakeImplicitMemoryAccess(
    const DisassembledInstruction& instruction,
    const std::string& accessText,
    const std::string& kind,
    const std::string& size,
    uint32_t widthBits,
    const std::string& baseRegister,
    int64_t displacement,
    const std::string& semantic)
{
    MemoryAccess access;
    access.Site = instruction.Address;
    access.Access = accessText;
    access.Kind = kind;
    access.Size = size;
    access.WidthBits = widthBits;
    access.BaseRegister = baseRegister;
    access.Scale = 0;
    access.Displacement = HexS64(displacement);
    access.Implicit = true;
    access.Semantic = semantic;
    return access;
}

uint32_t StringInstructionWidthBits(const std::string& mnemonic)
{
    const std::string lower = ToLowerAscii(mnemonic);

    auto endsWith = [&lower](const char* suffix)
    {
        const size_t suffixLength = std::strlen(suffix);
        return lower.size() >= suffixLength
            && lower.compare(lower.size() - suffixLength, suffixLength, suffix) == 0;
    };

    if (endsWith("sq"))
    {
        return 64;
    }

    if (endsWith("sd"))
    {
        return 32;
    }

    if (endsWith("sw"))
    {
        return 16;
    }

    return 8;
}

std::string SizeNameForWidth(uint32_t widthBits)
{
    switch (widthBits)
    {
    case 8:
        return "byte";
    case 16:
        return "word";
    case 32:
        return "dword";
    case 64:
        return "qword";
    default:
        return "unknown";
    }
}

bool RegisterTokenMatchesFamily(const std::string& token, const std::string& canonicalRegister)
{
    if (canonicalRegister == "rax")
    {
        return token == "al" || token == "ah" || token == "ax" || token == "eax" || token == "rax";
    }

    if (canonicalRegister == "rsi")
    {
        return token == "sil" || token == "si" || token == "esi" || token == "rsi";
    }

    if (canonicalRegister == "rdi")
    {
        return token == "dil" || token == "di" || token == "edi" || token == "rdi";
    }

    return token == canonicalRegister;
}

bool OperandTextContainsRegisterFamily(const std::string& operandText, const std::string& canonicalRegister)
{
    std::string current;
    const std::string lower = ToLowerAscii(operandText);

    auto flushCurrent = [&current, &canonicalRegister]() -> bool
    {
        if (current.empty())
        {
            return false;
        }

        const std::string token = current;
        current.clear();
        return RegisterTokenMatchesFamily(token, canonicalRegister);
    };

    for (const char ch : lower)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0)
        {
            current.push_back(ch);
        }
        else if (flushCurrent())
        {
            return true;
        }
    }

    return flushCurrent();
}

bool LooksLikeStringInstructionOperands(const DisassembledInstruction& instruction, const std::string& sourceRegister, const std::string& destinationRegister)
{
    const std::string operands = ToLowerAscii(instruction.OperandText);

    if (operands.empty())
    {
        return true;
    }

    return operands.find('[') != std::string::npos
        && OperandTextContainsRegisterFamily(operands, sourceRegister)
        && OperandTextContainsRegisterFamily(operands, destinationRegister);
}

std::vector<MemoryAccess> CollectImplicitMemoryAccesses(const DisassembledInstruction& instruction)
{
    std::vector<MemoryAccess> accesses;
    const std::string mnemonic = ToLowerAscii(instruction.Mnemonic);
    const std::string operation = ToLowerAscii(instruction.OperationText);

    if (mnemonic == "push")
    {
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsp-0x8]", "write", "qword", 64, "rsp", -8, "push_stack_write"));
    }
    else if (mnemonic == "pop")
    {
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsp]", "read", "qword", 64, "rsp", 0, "pop_stack_read"));
    }
    else if (instruction.IsCall)
    {
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsp-0x8]", "write", "qword", 64, "rsp", -8, "call_return_address_write"));
    }
    else if (instruction.IsReturn)
    {
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsp]", "read", "qword", 64, "rsp", 0, "ret_return_address_read"));
    }
    else if (mnemonic == "leave")
    {
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rbp]", "read", "qword", 64, "rbp", 0, "leave_saved_frame_read"));
    }

    const bool hasRepPrefix = StartsWithInsensitive(operation, "rep ") || StartsWithInsensitive(operation, "repe ") || StartsWithInsensitive(operation, "repne ");

    if (StartsWithInsensitive(mnemonic, "movs") && LooksLikeStringInstructionOperands(instruction, "rsi", "rdi"))
    {
        const uint32_t widthBits = StringInstructionWidthBits(mnemonic);
        const std::string size = SizeNameForWidth(widthBits);
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsi]", "read", size, widthBits, "rsi", 0, hasRepPrefix ? "rep_movs_source_read" : "movs_source_read"));
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rdi]", "write", size, widthBits, "rdi", 0, hasRepPrefix ? "rep_movs_destination_write" : "movs_destination_write"));
    }
    else if (StartsWithInsensitive(mnemonic, "stos") && LooksLikeStringInstructionOperands(instruction, "rax", "rdi"))
    {
        const uint32_t widthBits = StringInstructionWidthBits(mnemonic);
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rdi]", "write", SizeNameForWidth(widthBits), widthBits, "rdi", 0, hasRepPrefix ? "rep_stos_destination_write" : "stos_destination_write"));
    }
    else if (StartsWithInsensitive(mnemonic, "lods") && LooksLikeStringInstructionOperands(instruction, "rsi", "rax"))
    {
        const uint32_t widthBits = StringInstructionWidthBits(mnemonic);
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsi]", "read", SizeNameForWidth(widthBits), widthBits, "rsi", 0, hasRepPrefix ? "rep_lods_source_read" : "lods_source_read"));
    }
    else if (StartsWithInsensitive(mnemonic, "scas") && LooksLikeStringInstructionOperands(instruction, "rax", "rdi"))
    {
        const uint32_t widthBits = StringInstructionWidthBits(mnemonic);
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rdi]", "read", SizeNameForWidth(widthBits), widthBits, "rdi", 0, hasRepPrefix ? "rep_scas_compare_read" : "scas_compare_read"));
    }
    else if (StartsWithInsensitive(mnemonic, "cmps") && LooksLikeStringInstructionOperands(instruction, "rsi", "rdi"))
    {
        const uint32_t widthBits = StringInstructionWidthBits(mnemonic);
        const std::string size = SizeNameForWidth(widthBits);
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rsi]", "read", size, widthBits, "rsi", 0, hasRepPrefix ? "rep_cmps_left_read" : "cmps_left_read"));
        accesses.push_back(MakeImplicitMemoryAccess(instruction, "[rdi]", "read", size, widthBits, "rdi", 0, hasRepPrefix ? "rep_cmps_right_read" : "cmps_right_read"));
    }

    return accesses;
}

bool TryParseImmediateOperand(const std::string& operand, uint64_t& value);

bool TryGetImmediateOperand(const std::vector<std::string>& operands, size_t index, uint64_t& value)
{
    if (index >= operands.size())
    {
        return false;
    }

    return TryParseImmediateOperand(operands[index], value);
}

bool TryParseRspLeaDelta(const std::string& operand, int64_t& delta)
{
    std::string expression;

    if (!TryExtractBracketExpression(operand, expression))
    {
        return false;
    }

    expression.erase(
        std::remove_if(
            expression.begin(),
            expression.end(),
            [](const unsigned char ch)
            {
                return std::isspace(ch) != 0;
            }),
        expression.end());

    if (!StartsWithInsensitive(expression, "rsp"))
    {
        return false;
    }

    delta = 0;

    if (expression.size() == 3)
    {
        return true;
    }

    const char sign = expression[3];

    if (sign != '+' && sign != '-')
    {
        return false;
    }

    uint64_t magnitude = 0;

    if (!TryParseUnsigned(expression.substr(4), magnitude))
    {
        return false;
    }

    delta = sign == '-' ? -static_cast<int64_t>(magnitude) : static_cast<int64_t>(magnitude);
    return true;
}

bool DestinationIsRegister(const std::vector<std::string>& operands, const std::string& reg)
{
    if (operands.empty() || operands[0].find('[') != std::string::npos)
    {
        return false;
    }

    return ToLowerAscii(TrimCopy(operands[0])) == reg;
}

struct StackPointerState
{
    int64_t SpDelta = 0;
    int64_t RbpDelta = 0;
    bool SpKnown = false;
    bool RbpKnown = false;
    bool Initialized = false;
};

bool StackPointerStatesEqual(const StackPointerState& left, const StackPointerState& right)
{
    return left.SpDelta == right.SpDelta
        && left.RbpDelta == right.RbpDelta
        && left.SpKnown == right.SpKnown
        && left.RbpKnown == right.RbpKnown
        && left.Initialized == right.Initialized;
}

std::unordered_map<std::string, std::vector<std::string>> BuildStackBlockPredecessors(const std::vector<BasicBlock>& blocks)
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

StackPointerState EntryStackPointerState()
{
    StackPointerState state;
    state.SpKnown = true;
    state.SpDelta = 0;
    state.RbpKnown = false;
    state.RbpDelta = 0;
    state.Initialized = true;
    return state;
}

StackPointerState UnknownStackPointerState()
{
    StackPointerState state;
    state.Initialized = true;
    return state;
}

StackPointerState MergeStackPointerStates(const std::vector<StackPointerState>& incoming)
{
    if (incoming.empty())
    {
        return UnknownStackPointerState();
    }

    StackPointerState merged = incoming.front();
    merged.Initialized = true;

    for (size_t index = 1; index < incoming.size(); ++index)
    {
        const StackPointerState& next = incoming[index];

        if (!next.SpKnown || !merged.SpKnown || next.SpDelta != merged.SpDelta)
        {
            merged.SpKnown = false;
            merged.SpDelta = 0;
        }

        if (!next.RbpKnown || !merged.RbpKnown || next.RbpDelta != merged.RbpDelta)
        {
            merged.RbpKnown = false;
            merged.RbpDelta = 0;
        }
    }

    return merged;
}

StackPointerState MergeStackPointerInputState(
    const BasicBlock& block,
    const BasicBlock& entryBlock,
    const std::unordered_map<std::string, std::vector<std::string>>& predecessors,
    const std::unordered_map<std::string, StackPointerState>& outStates)
{
    std::vector<StackPointerState> incoming;

    if (block.Id == entryBlock.Id)
    {
        incoming.push_back(EntryStackPointerState());
    }

    const auto predecessorIt = predecessors.find(block.Id);

    if (predecessorIt != predecessors.end())
    {
        for (const std::string& predecessor : predecessorIt->second)
        {
            const auto stateIt = outStates.find(predecessor);

            if (stateIt != outStates.end() && stateIt->second.Initialized)
            {
                incoming.push_back(stateIt->second);
            }
        }
    }

    return MergeStackPointerStates(incoming);
}

StackPointerFact BuildStackPointerFact(
    const DisassembledInstruction& instruction,
    const StackPointerState& before,
    const StackPointerState& after)
{
    StackPointerFact fact;
    fact.Site = instruction.Address;
    fact.DeltaBefore = before.SpDelta;
    fact.DeltaAfter = after.SpDelta;
    fact.FramePointerDelta = before.RbpDelta;
    fact.Known = before.SpKnown;
    fact.FramePointerKnown = before.RbpKnown;
    fact.Confidence = before.SpKnown ? 0.90 : (before.Initialized ? 0.35 : 0.20);
    return fact;
}

StackPointerState ApplyStackPointerInstructionEffect(
    const DisassembledInstruction& instruction,
    StackPointerState state)
{
    if (!state.Initialized)
    {
        state = UnknownStackPointerState();
    }

    const std::string mnemonic = ToLowerAscii(instruction.Mnemonic);
    const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
    uint64_t immediate = 0;

    if (mnemonic == "push" && state.SpKnown)
    {
        state.SpDelta -= 8;
    }
    else if (mnemonic == "pop" && state.SpKnown)
    {
        state.SpDelta += 8;
    }
    else if (mnemonic == "sub" && DestinationIsRegister(operands, "rsp") && TryGetImmediateOperand(operands, 1, immediate) && state.SpKnown)
    {
        state.SpDelta -= static_cast<int64_t>(immediate);
    }
    else if (mnemonic == "add" && DestinationIsRegister(operands, "rsp") && TryGetImmediateOperand(operands, 1, immediate) && state.SpKnown)
    {
        state.SpDelta += static_cast<int64_t>(immediate);
    }
    else if (mnemonic == "lea" && DestinationIsRegister(operands, "rsp") && operands.size() >= 2 && state.SpKnown)
    {
        int64_t delta = 0;

        if (TryParseRspLeaDelta(operands[1], delta))
        {
            state.SpDelta += delta;
        }
        else
        {
            state.SpKnown = false;
            state.SpDelta = 0;
        }
    }
    else if (mnemonic == "mov" && operands.size() >= 2 && DestinationIsRegister(operands, "rbp") && ToLowerAscii(TrimCopy(operands[1])) == "rsp" && state.SpKnown)
    {
        state.RbpDelta = state.SpDelta;
        state.RbpKnown = true;
    }
    else if (mnemonic == "mov" && operands.size() >= 2 && DestinationIsRegister(operands, "rsp") && ToLowerAscii(TrimCopy(operands[1])) == "rbp")
    {
        if (state.RbpKnown)
        {
            state.SpDelta = state.RbpDelta;
            state.SpKnown = true;
        }
        else
        {
            state.SpKnown = false;
            state.SpDelta = 0;
        }
    }
    else if (mnemonic == "leave")
    {
        if (state.RbpKnown)
        {
            state.SpDelta = state.RbpDelta + 8;
            state.SpKnown = true;
            state.RbpKnown = false;
            state.RbpDelta = 0;
        }
        else
        {
            state.SpKnown = false;
            state.SpDelta = 0;
        }
    }
    else if (DestinationIsRegister(operands, "rsp") && mnemonic != "call")
    {
        state.SpKnown = false;
        state.SpDelta = 0;
    }

    return state;
}

StackPointerState TransferStackPointerBlock(
    const BasicBlock& block,
    StackPointerState state,
    const std::unordered_map<uint64_t, const DisassembledInstruction*>& instructionByAddress,
    std::unordered_map<uint64_t, StackPointerFact>* factsBySite)
{
    for (const uint64_t address : block.InstructionAddresses)
    {
        const auto instructionIt = instructionByAddress.find(address);

        if (instructionIt == instructionByAddress.end())
        {
            continue;
        }

        const DisassembledInstruction& instruction = *instructionIt->second;
        const StackPointerState before = state;
        state = ApplyStackPointerInstructionEffect(instruction, state);

        if (factsBySite != nullptr)
        {
            (*factsBySite)[instruction.Address] = BuildStackPointerFact(instruction, before, state);
        }
    }

    return state;
}

std::vector<StackPointerFact> CollectStackPointerFacts(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks)
{
    std::vector<StackPointerFact> facts;

    if (instructions.empty())
    {
        return facts;
    }

    if (blocks.empty())
    {
        StackPointerState state = EntryStackPointerState();

        for (const DisassembledInstruction& instruction : instructions)
        {
            const StackPointerState before = state;
            state = ApplyStackPointerInstructionEffect(instruction, state);
            facts.push_back(BuildStackPointerFact(instruction, before, state));
        }

        return facts;
    }

    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildStackBlockPredecessors(blocks);
    std::unordered_map<std::string, StackPointerState> inStates;
    std::unordered_map<std::string, StackPointerState> outStates;
    bool changed = true;
    size_t iterations = 0;

    while (changed && iterations++ < blocks.size() + 2U)
    {
        changed = false;

        for (const BasicBlock& block : blocks)
        {
            const StackPointerState inState = MergeStackPointerInputState(block, blocks.front(), predecessors, outStates);
            const StackPointerState outState = TransferStackPointerBlock(block, inState, instructionByAddress, nullptr);

            if (!StackPointerStatesEqual(inStates[block.Id], inState))
            {
                inStates[block.Id] = inState;
                changed = true;
            }

            if (!StackPointerStatesEqual(outStates[block.Id], outState))
            {
                outStates[block.Id] = outState;
                changed = true;
            }
        }
    }

    std::unordered_map<uint64_t, StackPointerFact> factsBySite;

    for (const BasicBlock& block : blocks)
    {
        StackPointerState state = inStates[block.Id];

        if (!state.Initialized)
        {
            state = UnknownStackPointerState();
        }

        TransferStackPointerBlock(block, state, instructionByAddress, &factsBySite);
    }

    for (const DisassembledInstruction& instruction : instructions)
    {
        const auto factIt = factsBySite.find(instruction.Address);

        if (factIt != factsBySite.end())
        {
            facts.push_back(factIt->second);
            continue;
        }

        StackPointerState unknown = UnknownStackPointerState();
        facts.push_back(BuildStackPointerFact(instruction, unknown, unknown));
    }

    return facts;
}

std::unordered_map<uint64_t, StackPointerFact> BuildStackPointerFactBySite(const std::vector<StackPointerFact>& facts)
{
    std::unordered_map<uint64_t, StackPointerFact> bySite;

    for (const StackPointerFact& fact : facts)
    {
        bySite[fact.Site] = fact;
    }

    return bySite;
}

std::string NormalizeRegisterAlias(const std::string& token);
std::string FirstRegisterTokenRaw(const std::string& operand);
std::vector<std::string> ExtractOperandRegisterTokens(const std::string& operand);
bool InstructionWritesDestinationOperand(const DisassembledInstruction& instruction, const std::vector<std::string>& operands);
std::string StripPointerDecorators(std::string operand);

struct FrameAlias
{
    int64_t FrameOffset = 0;
};

using FrameAliasMap = std::unordered_map<std::string, FrameAlias>;

std::unordered_map<uint64_t, FrameAliasMap> CollectFrameAliases(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::unordered_map<uint64_t, StackPointerFact>& stackPointerBySite);

void AnnotateStackFrameRelativeAccess(
    MemoryAccess& access,
    const std::unordered_map<uint64_t, StackPointerFact>& stackPointerBySite,
    const std::unordered_map<uint64_t, FrameAliasMap>& aliasesBySite)
{
    if (access.BaseRegister != "rsp" && access.BaseRegister != "rbp")
    {
        const auto aliasSiteIt = aliasesBySite.find(access.Site);

        if (aliasSiteIt == aliasesBySite.end()
            || !access.IndexRegister.empty())
        {
            return;
        }

        const auto aliasIt = aliasSiteIt->second.find(access.BaseRegister);

        if (aliasIt == aliasSiteIt->second.end())
        {
            return;
        }

        int64_t displacement = 0;

        if (!access.Displacement.empty() && !TryParseSignedValue(access.Displacement, displacement))
        {
            return;
        }

        const auto factIt = stackPointerBySite.find(access.Site);

        access.StackFrameRelative = true;
        access.FrameBase = "entry_rsp";
        access.FrameOffset = aliasIt->second.FrameOffset + displacement;
        access.StackPointerDelta = factIt != stackPointerBySite.end() ? factIt->second.DeltaBefore : 0;
        return;
    }

    const auto factIt = stackPointerBySite.find(access.Site);

    if (factIt == stackPointerBySite.end())
    {
        return;
    }

    int64_t displacement = 0;

    if (!access.Displacement.empty() && !TryParseSignedValue(access.Displacement, displacement))
    {
        return;
    }

    const StackPointerFact& fact = factIt->second;

    if (access.BaseRegister == "rsp")
    {
        if (!fact.Known)
        {
            return;
        }

        access.StackFrameRelative = true;
        access.FrameBase = "entry_rsp";
        access.FrameOffset = fact.DeltaBefore + displacement;
        access.StackPointerDelta = fact.DeltaBefore;
        return;
    }

    if (fact.FramePointerKnown)
    {
        access.StackFrameRelative = true;
        access.FrameBase = "entry_rsp";
        access.FrameOffset = fact.FramePointerDelta + displacement;
        access.StackPointerDelta = fact.DeltaBefore;
    }
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

struct SwitchGuardInfo
{
    uint32_t CaseCount = 0;
    uint64_t DefaultTarget = 0;
    int64_t RangeMin = 0;
    int64_t RangeMax = 0;
    bool RangeKnown = false;
    bool SignedIndex = false;
    std::string IndexExpression;
};

bool IsUnsignedRangeGuardBranch(const std::string& mnemonic)
{
    return mnemonic == "ja"
        || mnemonic == "jnbe";
}

bool IsSignedRangeGuardBranch(const std::string& mnemonic)
{
    return mnemonic == "jg"
        || mnemonic == "jnle";
}

std::string ExtractSwitchIndexExpression(const DisassembledInstruction& instruction)
{
    std::string expression;

    if (!TryExtractBracketExpression(instruction.OperandText, expression))
    {
        return std::string();
    }

    MemoryAccess access;
    ParseMemoryExpression(expression, access);

    std::string result;

    if (!access.BaseRegister.empty() && access.BaseRegister != "rip")
    {
        result = access.BaseRegister;
    }

    if (!access.IndexRegister.empty())
    {
        if (!result.empty())
        {
            result += "+";
        }

        result += access.IndexRegister;

        if (access.Scale > 1U)
        {
            result += "*" + std::to_string(access.Scale);
        }
    }

    return result;
}

SwitchGuardInfo InferSwitchGuardInfo(const std::vector<DisassembledInstruction>& instructions, size_t switchIndex)
{
    const size_t start = switchIndex > 8 ? switchIndex - 8 : 0;
    SwitchGuardInfo info;
    const DisassembledInstruction* guardBranch = nullptr;

    for (size_t cursor = switchIndex; cursor > start; --cursor)
    {
        const DisassembledInstruction& candidate = instructions[cursor - 1];
        const std::string mnemonic = ToLowerAscii(candidate.Mnemonic);

        if (candidate.IsConditionalBranch)
        {
            if (guardBranch == nullptr
                && (IsUnsignedRangeGuardBranch(mnemonic) || IsSignedRangeGuardBranch(mnemonic)))
            {
                guardBranch = &candidate;
            }

            continue;
        }

        const std::vector<std::string> operands = SplitOperands(candidate.OperandText);

        if (candidate.Mnemonic == "cmp" && operands.size() == 2)
        {
            uint64_t immediate = 0;

            if (TryParseImmediateOperand(operands[1], immediate) && immediate < 0x10000ULL)
            {
                if (guardBranch != nullptr || cursor + 2 >= switchIndex)
                {
                    info.CaseCount = static_cast<uint32_t>(immediate + 1ULL);
                    info.RangeMin = 0;
                    info.RangeMax = static_cast<int64_t>(immediate);
                    info.RangeKnown = true;
                    info.IndexExpression = StripPointerDecorators(operands[0]);

                    if (guardBranch != nullptr)
                    {
                        const std::string branchMnemonic = ToLowerAscii(guardBranch->Mnemonic);
                        info.DefaultTarget = guardBranch->HasBranchTarget ? guardBranch->BranchTarget : 0;
                        info.SignedIndex = IsSignedRangeGuardBranch(branchMnemonic);
                    }

                    return info;
                }
            }
        }

        if (candidate.Mnemonic == "and" && operands.size() == 2)
        {
            uint64_t immediate = 0;

            if (TryParseImmediateOperand(operands[1], immediate) && immediate < 0x10000ULL && IsMaskValue(immediate))
            {
                info.CaseCount = static_cast<uint32_t>(immediate + 1ULL);
                info.RangeMin = 0;
                info.RangeMax = static_cast<int64_t>(immediate);
                info.RangeKnown = true;
                info.IndexExpression = StripPointerDecorators(operands[0]);
                return info;
            }
        }
    }

    return info;
}

uint32_t EstimateSwitchCaseCount(const std::vector<DisassembledInstruction>& instructions, size_t switchIndex)
{
    return InferSwitchGuardInfo(instructions, switchIndex).CaseCount;
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

std::vector<BasicBlock> BuildBasicBlocksWithExtraLeaders(
    const std::vector<DisassembledInstruction>& instructions,
    const std::set<uint64_t>& extraLeaders)
{
    constexpr size_t kMaxAnalysisBlockInstructions = 24;
    std::vector<BasicBlock> blocks;

    if (instructions.empty())
    {
        return blocks;
    }

    std::set<uint64_t> leaders;
    leaders.insert(instructions.front().Address);
    leaders.insert(extraLeaders.begin(), extraLeaders.end());

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

std::vector<BasicBlock> BuildBasicBlocks(const std::vector<DisassembledInstruction>& instructions)
{
    return BuildBasicBlocksWithExtraLeaders(instructions, std::set<uint64_t>());
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
        const SwitchGuardInfo guardInfo = InferSwitchGuardInfo(instructions, index);
        info.CaseCount = guardInfo.CaseCount;
        info.DefaultTarget = guardInfo.DefaultTarget;
        info.RangeMin = guardInfo.RangeMin;
        info.RangeMax = guardInfo.RangeMax;
        info.RangeKnown = guardInfo.RangeKnown;
        info.SignedIndex = guardInfo.SignedIndex;
        info.Detail = instruction.OperandText;
        const std::string tableIndexExpression = ExtractSwitchIndexExpression(instruction);
        info.IndexExpression = !tableIndexExpression.empty()
            ? tableIndexExpression
            : guardInfo.IndexExpression;

        if (info.CaseCount != 0)
        {
            info.Detail += " ; estimated_cases=" + std::to_string(info.CaseCount);
        }

        if (info.RangeKnown)
        {
            info.Detail += " ; range=" + std::to_string(info.RangeMin) + ".." + std::to_string(info.RangeMax);
        }

        if (info.DefaultTarget != 0)
        {
            info.Detail += " ; default=" + HexU64(info.DefaultTarget);
        }

        switches.push_back(info);
    }

    return switches;
}

bool FrameAliasMapsEqual(const FrameAliasMap& left, const FrameAliasMap& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (const auto& entry : left)
    {
        const auto it = right.find(entry.first);

        if (it == right.end() || it->second.FrameOffset != entry.second.FrameOffset)
        {
            return false;
        }
    }

    return true;
}

FrameAliasMap MergeFrameAliasMaps(const std::vector<FrameAliasMap>& incoming)
{
    if (incoming.empty())
    {
        return {};
    }

    FrameAliasMap merged = incoming.front();

    for (size_t index = 1; index < incoming.size(); ++index)
    {
        for (auto it = merged.begin(); it != merged.end();)
        {
            const auto nextIt = incoming[index].find(it->first);

            if (nextIt == incoming[index].end() || nextIt->second.FrameOffset != it->second.FrameOffset)
            {
                it = merged.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    return merged;
}

FrameAliasMap MergeFrameAliasInputState(
    const BasicBlock& block,
    const BasicBlock& entryBlock,
    const std::unordered_map<std::string, std::vector<std::string>>& predecessors,
    const std::unordered_map<std::string, FrameAliasMap>& outStates)
{
    std::vector<FrameAliasMap> incoming;

    if (block.Id == entryBlock.Id)
    {
        incoming.push_back(FrameAliasMap());
    }

    const auto predecessorIt = predecessors.find(block.Id);

    if (predecessorIt != predecessors.end())
    {
        for (const std::string& predecessor : predecessorIt->second)
        {
            const auto stateIt = outStates.find(predecessor);

            if (stateIt != outStates.end())
            {
                incoming.push_back(stateIt->second);
            }
        }
    }

    return MergeFrameAliasMaps(incoming);
}

bool TryBuildFrameAliasFromBaseAndDisplacement(
    const std::string& baseRegister,
    int64_t displacement,
    const FrameAliasMap& aliases,
    const StackPointerFact* stackPointer,
    FrameAlias& alias)
{
    if (baseRegister == "rsp")
    {
        if (stackPointer == nullptr || !stackPointer->Known)
        {
            return false;
        }

        alias.FrameOffset = stackPointer->DeltaBefore + displacement;
        return true;
    }

    if (baseRegister == "rbp")
    {
        if (stackPointer == nullptr || !stackPointer->FramePointerKnown)
        {
            return false;
        }

        alias.FrameOffset = stackPointer->FramePointerDelta + displacement;
        return true;
    }

    const auto aliasIt = aliases.find(baseRegister);

    if (aliasIt == aliases.end())
    {
        return false;
    }

    alias.FrameOffset = aliasIt->second.FrameOffset + displacement;
    return true;
}

bool TryBuildFrameAliasFromOperand(
    const std::string& operand,
    const FrameAliasMap& aliases,
    const StackPointerFact* stackPointer,
    FrameAlias& alias)
{
    const std::string stripped = StripPointerDecorators(operand);

    if (stripped.find('[') != std::string::npos)
    {
        std::string expression;
        MemoryAccess access;

        if (!TryExtractBracketExpression(stripped, expression))
        {
            return false;
        }

        ParseMemoryExpression(expression, access);

        if (access.BaseRegister.empty() || !access.IndexRegister.empty())
        {
            return false;
        }

        int64_t displacement = 0;

        if (!access.Displacement.empty() && !TryParseSignedValue(access.Displacement, displacement))
        {
            return false;
        }

        return TryBuildFrameAliasFromBaseAndDisplacement(access.BaseRegister, displacement, aliases, stackPointer, alias);
    }

    const std::vector<std::string> registers = ExtractOperandRegisterTokens(stripped);

    if (registers.size() != 1)
    {
        return false;
    }

    return TryBuildFrameAliasFromBaseAndDisplacement(registers.front(), 0, aliases, stackPointer, alias);
}

std::string DestinationRegisterForAliasTracking(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands)
{
    if (operands.empty()
        || operands[0].find('[') != std::string::npos
        || !InstructionWritesDestinationOperand(instruction, operands))
    {
        return std::string();
    }

    return NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0]));
}

FrameAliasMap TransferFrameAliasBlock(
    const BasicBlock& block,
    FrameAliasMap aliases,
    const std::unordered_map<uint64_t, const DisassembledInstruction*>& instructionByAddress,
    const std::unordered_map<uint64_t, StackPointerFact>& stackPointerBySite,
    std::unordered_map<uint64_t, FrameAliasMap>* aliasesBySite)
{
    for (const uint64_t address : block.InstructionAddresses)
    {
        const auto instructionIt = instructionByAddress.find(address);

        if (instructionIt == instructionByAddress.end())
        {
            continue;
        }

        const DisassembledInstruction& instruction = *instructionIt->second;
        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

        if (aliasesBySite != nullptr)
        {
            (*aliasesBySite)[instruction.Address] = aliases;
        }

        if (instruction.IsCall)
        {
            static const std::array<const char*, 7> volatileRegs = { "rax", "rcx", "rdx", "r8", "r9", "r10", "r11" };

            for (const char* reg : volatileRegs)
            {
                aliases.erase(reg);
            }

            continue;
        }

        const std::string destination = DestinationRegisterForAliasTracking(instruction, operands);

        if (destination.empty())
        {
            continue;
        }

        FrameAlias newAlias;
        bool hasNewAlias = false;
        const auto stackPointerIt = stackPointerBySite.find(instruction.Address);
        const StackPointerFact* stackPointer = stackPointerIt == stackPointerBySite.end() ? nullptr : &stackPointerIt->second;

        if ((instruction.Mnemonic == "mov" || instruction.Mnemonic == "lea") && operands.size() >= 2)
        {
            hasNewAlias = TryBuildFrameAliasFromOperand(operands[1], aliases, stackPointer, newAlias);
        }

        aliases.erase(destination);

        if (hasNewAlias && destination != "rsp" && destination != "rbp")
        {
            aliases[destination] = newAlias;
        }
    }

    return aliases;
}

std::unordered_map<uint64_t, FrameAliasMap> CollectFrameAliases(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::unordered_map<uint64_t, StackPointerFact>& stackPointerBySite)
{
    std::unordered_map<uint64_t, FrameAliasMap> aliasesBySite;

    if (instructions.empty() || blocks.empty())
    {
        return aliasesBySite;
    }

    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildStackBlockPredecessors(blocks);
    std::unordered_map<std::string, FrameAliasMap> inStates;
    std::unordered_map<std::string, FrameAliasMap> outStates;
    bool changed = true;
    size_t iterations = 0;

    while (changed && iterations++ < blocks.size() + 2U)
    {
        changed = false;

        for (const BasicBlock& block : blocks)
        {
            const FrameAliasMap inState = MergeFrameAliasInputState(block, blocks.front(), predecessors, outStates);
            const FrameAliasMap outState = TransferFrameAliasBlock(block, inState, instructionByAddress, stackPointerBySite, nullptr);

            if (!FrameAliasMapsEqual(inStates[block.Id], inState))
            {
                inStates[block.Id] = inState;
                changed = true;
            }

            if (!FrameAliasMapsEqual(outStates[block.Id], outState))
            {
                outStates[block.Id] = outState;
                changed = true;
            }
        }
    }

    for (const BasicBlock& block : blocks)
    {
        TransferFrameAliasBlock(block, inStates[block.Id], instructionByAddress, stackPointerBySite, &aliasesBySite);
    }

    return aliasesBySite;
}

std::vector<MemoryAccess> CollectMemoryAccesses(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<StackPointerFact>& stackPointerFacts)
{
    std::vector<MemoryAccess> accesses;
    const std::unordered_map<uint64_t, StackPointerFact> stackPointerBySite = BuildStackPointerFactBySite(stackPointerFacts);
    const std::unordered_map<uint64_t, FrameAliasMap> aliasesBySite = CollectFrameAliases(instructions, blocks, stackPointerBySite);

    for (const auto& instruction : instructions)
    {
        std::vector<MemoryAccess> explicitAccesses = BuildExplicitMemoryAccesses(instruction);

        for (MemoryAccess& access : explicitAccesses)
        {
            AnnotateStackFrameRelativeAccess(access, stackPointerBySite, aliasesBySite);
            accesses.push_back(std::move(access));
        }

        std::vector<MemoryAccess> implicitAccesses = CollectImplicitMemoryAccesses(instruction);

        for (MemoryAccess& access : implicitAccesses)
        {
            AnnotateStackFrameRelativeAccess(access, stackPointerBySite, aliasesBySite);
        }

        accesses.insert(accesses.end(), implicitAccesses.begin(), implicitAccesses.end());
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
    const std::string vectorAlias = NormalizeVectorRegisterAlias(lower);

    if (!vectorAlias.empty())
    {
        return vectorAlias;
    }

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

uint32_t RegisterOperandWidthBits(const std::string& token)
{
    const std::string lower = ToLowerAscii(TrimCopy(token));
    std::string vectorPrefix;
    uint32_t vectorIndex = 0;

    if (lower.empty())
    {
        return 0;
    }

    if (TryParseVectorRegisterName(lower, vectorPrefix, vectorIndex))
    {
        if (vectorPrefix == "zmm")
        {
            return 512;
        }

        if (vectorPrefix == "ymm")
        {
            return 256;
        }

        return 128;
    }

    static const std::array<const char*, 20> eightBit = {
        "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
        "sil", "dil", "bpl", "spl",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
    };
    static const std::array<const char*, 16> sixteenBit = {
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
    };
    static const std::array<const char*, 16> thirtyTwoBit = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
    };

    if (std::find(eightBit.begin(), eightBit.end(), lower) != eightBit.end())
    {
        return 8;
    }

    if (std::find(sixteenBit.begin(), sixteenBit.end(), lower) != sixteenBit.end())
    {
        return 16;
    }

    if (std::find(thirtyTwoBit.begin(), thirtyTwoBit.end(), lower) != thirtyTwoBit.end())
    {
        return 32;
    }

    return IsRegisterName(lower) ? 64 : 0;
}

std::string FirstRegisterTokenRaw(const std::string& operand)
{
    std::string current;
    const std::string lower = ToLowerAscii(StripPointerDecorators(operand));

    auto flushCurrent = [&current]() -> std::string
    {
        if (current.empty())
        {
            return std::string();
        }

        const std::string token = current;
        current.clear();
        return IsRegisterName(token) ? token : std::string();
    };

    for (const char ch : lower)
    {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0)
        {
            current.push_back(ch);
        }
        else
        {
            std::string token = flushCurrent();

            if (!token.empty())
            {
                return token;
            }
        }
    }

    return flushCurrent();
}

bool IsPartialRegisterWriteOperand(const std::string& operand)
{
    const std::string token = FirstRegisterTokenRaw(operand);
    const uint32_t widthBits = RegisterOperandWidthBits(token);
    return widthBits != 0 && widthBits < 32;
}

bool IsWholeRegisterZeroIdiomOperand(const std::string& operand)
{
    const std::string token = FirstRegisterTokenRaw(operand);
    const uint32_t widthBits = RegisterOperandWidthBits(token);
    return widthBits >= 32;
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
        && !StartsWithInsensitive(instruction.Mnemonic, "ucomi")
        && !StartsWithInsensitive(instruction.Mnemonic, "comi")
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
        && operands[0].find('[') == std::string::npos
        && OperandReferencesRegister(operands[0], canonicalRegister);
}

bool IsRegisterZeroIdiomInstruction(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands)
{
    const std::string mnemonic = ToLowerAscii(TrimCopy(instruction.Mnemonic));

    if (operands.size() >= 2)
    {
        const std::string left = StripPointerDecorators(operands[0]);
        const std::string right = StripPointerDecorators(operands[1]);

        if (!left.empty()
            && left == right
            && IsWholeRegisterZeroIdiomOperand(operands[0])
            && (mnemonic == "xor"
                || mnemonic == "sub"
                || mnemonic == "xorps"
                || mnemonic == "xorpd"
                || mnemonic == "pxor"))
        {
            return true;
        }
    }

    if (operands.size() >= 3
        && (mnemonic == "vxorps" || mnemonic == "vxorpd" || mnemonic == "vpxor" || mnemonic == "vpxord" || mnemonic == "vpxorq"))
    {
        const std::string left = StripPointerDecorators(operands[1]);
        const std::string right = StripPointerDecorators(operands[2]);

        return !left.empty()
            && left == right
            && IsWholeRegisterZeroIdiomOperand(operands[1]);
    }

    return false;
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

    if (IsRegisterZeroIdiomInstruction(instruction, operands))
    {
        for (const std::string& operand : operands)
        {
            if (OperandReferencesRegister(operand, canonicalRegister))
            {
                return false;
            }
        }
    }

    if (InstructionWritesDestinationOperand(instruction, operands)
        && operands[0].find('[') != std::string::npos
        && OperandReferencesRegister(operands[0], canonicalRegister))
    {
        return true;
    }

    if (InstructionWritesDestinationOperand(instruction, operands)
        && operands[0].find('[') == std::string::npos
        && IsPartialRegisterWriteOperand(operands[0])
        && OperandReferencesRegister(operands[0], canonicalRegister))
    {
        return true;
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

bool InstructionWritesFlags(const DisassembledInstruction& instruction)
{
    if (instruction.IsConditionalBranch || instruction.IsReturn)
    {
        return false;
    }

    if (instruction.IsCall)
    {
        return true;
    }

    const std::string mnemonic = ToLowerAscii(TrimCopy(instruction.Mnemonic));
    static const std::array<const char*, 45> flagWriters = {
        "adc", "add", "and", "bt", "btc", "btr", "bts", "clc", "cmc", "cmp",
        "cmpxchg", "cmpxchg8b", "cmpxchg16b", "dec", "div", "idiv", "imul", "inc",
        "mul", "neg", "or", "popfq", "popf", "rcl", "rcr", "rol", "ror", "sahf",
        "sal", "sar", "sbb", "shl", "shr", "stc", "sub", "test", "xadd", "xor",
        "repe", "repne", "scasb", "scasw", "scasd", "scasq", "ucomiss"
    };

    if (std::find(flagWriters.begin(), flagWriters.end(), mnemonic) != flagWriters.end())
    {
        return true;
    }

    return StartsWithInsensitive(mnemonic, "cmp")
        || StartsWithInsensitive(mnemonic, "test")
        || StartsWithInsensitive(mnemonic, "ucomi")
        || StartsWithInsensitive(mnemonic, "comi");
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
    case 128:
        return "__m128";
    case 256:
        return "__m256";
    case 512:
        return "__m512";
    default:
        return "UNKNOWN_TYPE";
    }
}

bool IsVectorArgumentRegister(const std::string& canonicalRegister)
{
    return StartsWithInsensitive(canonicalRegister, "xmm");
}

std::string InferRegisterArgumentTypeHint(const std::string& canonicalRegister, bool pointerLike)
{
    if (IsVectorArgumentRegister(canonicalRegister))
    {
        return "double_or_vector";
    }

    return InferTypeHintFromWidth(64, pointerLike);
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

std::string BuildStackSlotKey(const MemoryAccess& access)
{
    if (access.StackFrameRelative)
    {
        return BuildStackSlotKey("frame", access.FrameOffset);
    }

    int64_t offset = 0;

    if (!TryParseSignedValue(access.Displacement, offset))
    {
        offset = 0;
    }

    return BuildStackSlotKey(access.BaseRegister, offset);
}

std::string BuildStackSlotName(int64_t offset)
{
    const uint64_t magnitude = offset < 0 ? static_cast<uint64_t>(-(offset + 1)) + 1ULL : static_cast<uint64_t>(offset);
    return std::string(offset < 0 ? "local_" : "slot_") + FormatHexMagnitude(magnitude);
}

std::string BuildArgumentName(const std::string& canonicalRegister)
{
    if (StartsWithInsensitive(canonicalRegister, "xmm"))
    {
        uint64_t index = 0;

        if (TryParseUnsigned(canonicalRegister.substr(3), index) && index < 4)
        {
            return "fp_arg" + std::to_string(index + 1ULL);
        }

        return "fp_arg";
    }

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

    static const std::array<const char*, 8> registers = { "rcx", "rdx", "r8", "r9", "xmm0", "xmm1", "xmm2", "xmm3" };
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

        if (instruction.IsCall)
        {
            for (const char* reg : registers)
            {
                defined.insert(reg);
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
        argument.TypeHint = InferRegisterArgumentTypeHint(canonicalRegister, info.MemoryBaseUseCount != 0);
        argument.RoleHint =
            IsVectorArgumentRegister(canonicalRegister) ? "floating_or_vector"
            :
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
        std::string RawBaseRegister;
        int64_t RawOffset = 0;
        std::string Storage;
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
        if (access.Implicit)
        {
            continue;
        }

        if (!access.StackFrameRelative && access.BaseRegister != "rbp" && access.BaseRegister != "rsp")
        {
            continue;
        }

        int64_t rawOffset = 0;

        if (!TryParseSignedValue(access.Displacement, rawOffset))
        {
            rawOffset = 0;
        }

        const int64_t offset = access.StackFrameRelative ? access.FrameOffset : rawOffset;
        const std::string baseRegister = access.StackFrameRelative ? "frame" : access.BaseRegister;
        bool isCandidate = false;
        std::string storage = "stack_slot";

        if (access.StackFrameRelative)
        {
            if (offset < 0)
            {
                isCandidate = true;
                storage = "stack_local";
            }
            else if (offset > 0 && offset <= 0x60)
            {
                isCandidate = true;
                storage = "stack_home";
            }
        }
        else if (access.BaseRegister == "rbp" && offset < 0)
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

        const std::string key = BuildStackSlotKey(baseRegister, offset);
        LocalStats& stats = statsByKey[key];

        if (stats.BaseRegister.empty())
        {
            stats.BaseRegister = baseRegister;
            stats.Offset = offset;
            stats.RawBaseRegister = access.BaseRegister;
            stats.RawOffset = rawOffset;
            stats.Storage = storage;
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
        local.RawBaseRegister = stats.RawBaseRegister;
        local.RawOffset = stats.RawOffset;
        local.Storage = !stats.Storage.empty()
            ? stats.Storage
            : (stats.BaseRegister == "frame")
                ? (stats.Offset < 0 ? "stack_local" : "stack_home")
                : (((stats.BaseRegister == "rbp" && stats.Offset < 0)
                    || (stats.BaseRegister == "rsp" && stats.Offset >= 0 && (stackFrame.StackAlloc == 0 || static_cast<uint32_t>(stats.Offset) < stackFrame.StackAlloc)))
                    ? "stack_local"
                    : "stack_home");
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

        if (local.BaseRegister != "frame" && !local.RawBaseRegister.empty())
        {
            mapping[BuildStackSlotKey(local.RawBaseRegister, local.RawOffset)] = local.Name;
        }
    }

    return mapping;
}

std::string FindRecoveredLocalNameForAccess(
    const MemoryAccess& access,
    const std::unordered_map<std::string, std::string>& localKeyNameMap);

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

std::string RewriteOperandWithRecoveredNames(
    const std::string& operand,
    const std::vector<const MemoryAccess*>& accesses,
    const std::unordered_map<std::string, std::string>& argumentRegisterMap,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    if (operand.find('[') != std::string::npos)
    {
        const std::string strippedOperand = StripPointerDecorators(operand);

        for (const MemoryAccess* access : accesses)
        {
            if (access == nullptr || access->Implicit)
            {
                continue;
            }

            const std::string strippedAccess = StripPointerDecorators(access->Access);

            if (strippedOperand == strippedAccess)
            {
                const std::string localName = FindRecoveredLocalNameForAccess(*access, localKeyNameMap);

                if (!localName.empty())
                {
                    return localName;
                }
            }
        }
    }

    return RewriteOperandWithRecoveredNames(operand, argumentRegisterMap, localKeyNameMap);
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

struct ConditionalOperandPattern
{
    std::string Kind;
    std::string Left;
    std::string Right;
    std::string RawLeftKey;
    std::string RawRightKey;
    bool Valid = false;
};

bool IsConditionalMoveMnemonic(const std::string& mnemonic)
{
    const std::string lower = ToLowerAscii(TrimCopy(mnemonic));
    return StartsWithInsensitive(lower, "cmov") && lower.size() > 4;
}

std::string CmovConditionSuffixToBranch(const std::string& mnemonic)
{
    std::string suffix = ToLowerAscii(TrimCopy(mnemonic));

    if (!StartsWithInsensitive(suffix, "cmov") || suffix.size() <= 4)
    {
        return std::string();
    }

    suffix = suffix.substr(4);

    if (suffix == "e" || suffix == "z")
    {
        return "je";
    }

    if (suffix == "ne" || suffix == "nz")
    {
        return "jne";
    }

    if (suffix == "nb" || suffix == "nc" || suffix == "ae")
    {
        return "jae";
    }

    if (suffix == "b" || suffix == "c" || suffix == "nae")
    {
        return "jb";
    }

    if (suffix == "na")
    {
        return "jbe";
    }

    if (suffix == "nbe")
    {
        return "ja";
    }

    if (suffix == "nge")
    {
        return "jl";
    }

    if (suffix == "nl")
    {
        return "jge";
    }

    if (suffix == "ng")
    {
        return "jle";
    }

    if (suffix == "nle")
    {
        return "jg";
    }

    if (suffix == "o")
    {
        return "jo";
    }

    if (suffix == "no")
    {
        return "jno";
    }

    if (suffix == "p" || suffix == "pe")
    {
        return "jp";
    }

    if (suffix == "np" || suffix == "po")
    {
        return "jnp";
    }

    return "j" + suffix;
}

std::string BuildConditionExpressionForSelect(const ConditionalOperandPattern& pattern, const std::string& branchMnemonic)
{
    if (!pattern.Valid)
    {
        return std::string();
    }

    const std::string branch = ToLowerAscii(TrimCopy(branchMnemonic));

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

        if (branch == "jo")
        {
            return "overflow(" + pattern.Left + " - " + pattern.Right + ")";
        }

        if (branch == "jno")
        {
            return "!overflow(" + pattern.Left + " - " + pattern.Right + ")";
        }

        if (branch == "jp")
        {
            return "parity(" + pattern.Left + " - " + pattern.Right + ")";
        }

        if (branch == "jnp")
        {
            return "!parity(" + pattern.Left + " - " + pattern.Right + ")";
        }
    }

    if (pattern.Kind == "test")
    {
        if (branch == "je")
        {
            return pattern.RawLeftKey == pattern.RawRightKey
                ? pattern.Left + " == 0"
                : "(" + pattern.Left + " & " + pattern.Right + ") == 0";
        }

        if (branch == "jne")
        {
            return pattern.RawLeftKey == pattern.RawRightKey
                ? pattern.Left + " != 0"
                : "(" + pattern.Left + " & " + pattern.Right + ") != 0";
        }

        if (branch == "js")
        {
            return pattern.Left + " < 0";
        }

        if (branch == "jns")
        {
            return pattern.Left + " >= 0";
        }

        if (branch == "jp")
        {
            return "parity(" + pattern.Left + " & " + pattern.Right + ")";
        }

        if (branch == "jnp")
        {
            return "!parity(" + pattern.Left + " & " + pattern.Right + ")";
        }
    }

    return std::string();
}

std::string DescribeAssignmentValue(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const std::vector<const MemoryAccess*>& accesses,
    const std::unordered_map<std::string, std::string>& argumentRegisterMap,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    if (instruction.Mnemonic == "xor" && operands.size() >= 2)
    {
        const std::string left = StripPointerDecorators(operands[0]);
        const std::string right = StripPointerDecorators(operands[1]);

        if (!left.empty() && left == right)
        {
            if (!IsWholeRegisterZeroIdiomOperand(operands[0]))
            {
                const std::string destinationRegister = NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0]));
                return "merge_partial(" + destinationRegister + ", 0)";
            }

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
        const std::string left = RewriteOperandWithRecoveredNames(operands[0], accesses, argumentRegisterMap, localKeyNameMap);
        const std::string right = RewriteOperandWithRecoveredNames(operands[1], accesses, argumentRegisterMap, localKeyNameMap);

        if (instruction.Mnemonic == "mov")
        {
            if (IsPartialRegisterWriteOperand(operands[0]))
            {
                const std::string destinationRegister = NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0]));
                return "merge_partial(" + destinationRegister + ", " + right + ")";
            }

            return right;
        }

        if (instruction.Mnemonic == "movzx"
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
        const std::string operand = RewriteOperandWithRecoveredNames(operands[0], accesses, argumentRegisterMap, localKeyNameMap);

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

using StringMap = std::unordered_map<std::string, std::string>;
using MemoryAccessIndex = std::unordered_map<uint64_t, std::vector<const MemoryAccess*>>;

const std::array<const char*, 6>& VolatileIntegerRegisters()
{
    static const std::array<const char*, 6> registers = { "rcx", "rdx", "r8", "r9", "r10", "r11" };
    return registers;
}

const std::array<const char*, 6>& VolatileVectorRegisters()
{
    static const std::array<const char*, 6> registers = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5" };
    return registers;
}

bool StringMapsEqual(const StringMap& left, const StringMap& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (const auto& entry : left)
    {
        const auto found = right.find(entry.first);

        if (found == right.end() || found->second != entry.second)
        {
            return false;
        }
    }

    return true;
}

StringMap MergePredecessorStringMaps(
    const std::vector<std::string>& predecessors,
    const std::unordered_map<std::string, StringMap>& blockOut)
{
    StringMap merged;

    if (predecessors.empty())
    {
        return merged;
    }

    bool initialized = false;

    for (const std::string& predecessor : predecessors)
    {
        const auto outIt = blockOut.find(predecessor);

        if (outIt == blockOut.end())
        {
            return StringMap();
        }

        if (!initialized)
        {
            merged = outIt->second;
            initialized = true;
            continue;
        }

        for (auto it = merged.begin(); it != merged.end();)
        {
            const auto valueIt = outIt->second.find(it->first);

            if (valueIt == outIt->second.end() || valueIt->second != it->second)
            {
                it = merged.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    return merged;
}

void EraseCallClobberedValues(StringMap& ids, StringMap& canonical)
{
    for (const char* reg : VolatileIntegerRegisters())
    {
        ids.erase(reg);
        canonical.erase(reg);
    }

    for (const char* reg : VolatileVectorRegisters())
    {
        ids.erase(reg);
        canonical.erase(reg);
    }
}

MemoryAccessIndex BuildMemoryAccessIndex(const std::vector<MemoryAccess>& memoryAccesses)
{
    MemoryAccessIndex index;

    for (const MemoryAccess& access : memoryAccesses)
    {
        index[access.Site].push_back(&access);
    }

    return index;
}

const MemoryAccess* SelectPrimaryMemoryAccess(const std::vector<const MemoryAccess*>& accesses)
{
    const MemoryAccess* fallback = nullptr;

    for (const MemoryAccess* access : accesses)
    {
        if (access == nullptr)
        {
            continue;
        }

        if (fallback == nullptr)
        {
            fallback = access;
        }

        if (!access->Implicit)
        {
            return access;
        }
    }

    return fallback;
}

std::vector<const MemoryAccess*> FindMemoryAccessesAtSite(const MemoryAccessIndex& index, uint64_t site)
{
    const auto it = index.find(site);

    if (it == index.end())
    {
        return {};
    }

    return it->second;
}

std::string FindRecoveredLocalNameForAccess(
    const MemoryAccess& access,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    const auto canonicalIt = localKeyNameMap.find(BuildStackSlotKey(access));

    if (canonicalIt != localKeyNameMap.end())
    {
        return canonicalIt->second;
    }

    int64_t offset = 0;

    if (!TryParseSignedValue(access.Displacement, offset))
    {
        offset = 0;
    }

    const auto rawIt = localKeyNameMap.find(BuildStackSlotKey(access.BaseRegister, offset));
    return rawIt == localKeyNameMap.end() ? std::string() : rawIt->second;
}

StringMap BuildBlockLocalDefinitions(
    const BasicBlock& block,
    const std::unordered_map<uint64_t, const DisassembledInstruction*>& instructionByAddress,
    const MemoryAccessIndex& accessBySite,
    const std::unordered_map<std::string, std::string>& argumentRegisterMap,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    StringMap definitions;

    for (uint64_t address : block.InstructionAddresses)
    {
        const auto instructionIt = instructionByAddress.find(address);

        if (instructionIt == instructionByAddress.end())
        {
            continue;
        }

        const DisassembledInstruction& instruction = *instructionIt->second;
        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
        const std::vector<const MemoryAccess*> accesses = FindMemoryAccessesAtSite(accessBySite, address);
        const std::string value = DescribeAssignmentValue(instruction, operands, accesses, argumentRegisterMap, localKeyNameMap);

        for (const auto& argument : argumentRegisterMap)
        {
            if (InstructionWritesRegister(instruction, operands, argument.first))
            {
                definitions[argument.second] = value;
            }
        }

        for (const MemoryAccess* access : FindMemoryAccessesAtSite(accessBySite, address))
        {
            if (access == nullptr
                || access->Implicit
                || (access->Kind != "write" && access->Kind != "read_write")
                || (!access->StackFrameRelative && access->BaseRegister != "rbp" && access->BaseRegister != "rsp"))
            {
                continue;
            }

            const std::string localName = FindRecoveredLocalNameForAccess(*access, localKeyNameMap);

            if (!localName.empty())
            {
                definitions[localName] = value;
            }
        }
    }

    return definitions;
}

std::vector<std::string> CollectReadValueKeys(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const std::vector<const MemoryAccess*>& accesses,
    const std::unordered_map<std::string, std::string>& localKeyNameMap)
{
    std::vector<std::string> keys;

    auto addUnique = [&keys](const std::string& key)
    {
        if (!key.empty() && std::find(keys.begin(), keys.end(), key) == keys.end())
        {
            keys.push_back(key);
        }
    };

    for (const std::string& reg : ExtractOperandRegisterTokens(instruction.OperandText))
    {
        if (InstructionReadsRegister(instruction, operands, reg))
        {
            addUnique(reg);
        }
    }

    for (const MemoryAccess* access : accesses)
    {
        if (access == nullptr
            || access->Implicit
            || (access->Kind != "read" && access->Kind != "read_write")
            || (!access->StackFrameRelative && access->BaseRegister != "rbp" && access->BaseRegister != "rsp"))
        {
            continue;
        }

        const std::string localName = FindRecoveredLocalNameForAccess(*access, localKeyNameMap);

        if (!localName.empty())
        {
            addUnique(localName);
        }
    }

    return keys;
}

std::vector<ValueMerge> CollectValueMerges(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<MemoryAccess>& memoryAccesses,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;
    const MemoryAccessIndex accessBySite = BuildMemoryAccessIndex(memoryAccesses);
    std::unordered_map<std::string, StringMap> blockLocalDefinitions;
    std::unordered_map<std::string, StringMap> blockOut;
    const std::unordered_map<std::string, std::string> argumentRegisterMap = BuildArgumentRegisterNameMap(arguments);
    const std::unordered_map<std::string, std::string> localKeyNameMap = BuildLocalKeyNameMap(locals);

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    for (const BasicBlock& block : blocks)
    {
        blockLocalDefinitions[block.Id] = BuildBlockLocalDefinitions(
            block,
            instructionByAddress,
            accessBySite,
            argumentRegisterMap,
            localKeyNameMap);
        blockOut[block.Id] = StringMap();
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);

    bool changed = true;
    size_t iterations = 0;

    while (changed && iterations++ < blocks.size() + 1U)
    {
        changed = false;

        for (const BasicBlock& block : blocks)
        {
            StringMap out;
            const auto predecessorIt = predecessors.find(block.Id);

            if (&block != &blocks.front() && predecessorIt != predecessors.end())
            {
                out = MergePredecessorStringMaps(predecessorIt->second, blockOut);
            }

            const auto localIt = blockLocalDefinitions.find(block.Id);

            if (localIt != blockLocalDefinitions.end())
            {
                for (const auto& definition : localIt->second)
                {
                    out[definition.first] = definition.second;
                }
            }

            if (!StringMapsEqual(blockOut[block.Id], out))
            {
                blockOut[block.Id] = std::move(out);
                changed = true;
            }
        }
    }

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
            const auto definitionsIt = blockOut.find(predecessor);

            if (definitionsIt == blockOut.end())
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
        && !access->Implicit
        && (access->Kind == "write" || access->Kind == "read_write")
        && (access->StackFrameRelative || access->BaseRegister == "rbp" || access->BaseRegister == "rsp"))
    {
        const std::string localName = FindRecoveredLocalNameForAccess(*access, localKeyNameMap);

        if (!localName.empty())
        {
            return localName;
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
    const MemoryAccessIndex accessBySite = BuildMemoryAccessIndex(memoryAccesses);
    std::unordered_map<uint64_t, std::string> blockByAddress = BuildBlockIdByInstructionAddress(blocks);
    const std::unordered_map<std::string, std::string> argumentRegisterMap = BuildArgumentRegisterNameMap(arguments);
    const std::unordered_map<std::string, std::string> localKeyNameMap = BuildLocalKeyNameMap(locals);
    std::unordered_map<std::string, size_t> indexById;
    std::unordered_map<std::string, std::vector<size_t>> valueIndicesByBlock;
    std::unordered_map<std::string, StringMap> inIdsByBlock;
    std::unordered_map<std::string, StringMap> outIdsByBlock;
    std::unordered_map<std::string, StringMap> inCanonicalByBlock;
    std::unordered_map<std::string, StringMap> outCanonicalByBlock;
    std::unordered_map<std::string, ConditionalOperandPattern> lastConditionByBlock;
    std::vector<IrValue> values;

    for (const DisassembledInstruction& instruction : instructions)
    {
        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
        const std::vector<const MemoryAccess*> accesses = FindMemoryAccessesAtSite(accessBySite, instruction.Address);
        const MemoryAccess* access = SelectPrimaryMemoryAccess(accesses);
        const auto blockIt = blockByAddress.find(instruction.Address);
        const std::string blockId = blockIt == blockByAddress.end() ? std::string() : blockIt->second;

        if ((instruction.Mnemonic == "cmp" || instruction.Mnemonic == "test") && operands.size() >= 2)
        {
            ConditionalOperandPattern pattern;
            pattern.Kind = instruction.Mnemonic;
            pattern.Left = RewriteOperandWithRecoveredNames(operands[0], accesses, argumentRegisterMap, localKeyNameMap);
            pattern.Right = RewriteOperandWithRecoveredNames(operands[1], accesses, argumentRegisterMap, localKeyNameMap);
            pattern.RawLeftKey = StripPointerDecorators(operands[0]);
            pattern.RawRightKey = StripPointerDecorators(operands[1]);
            pattern.Valid = true;
            lastConditionByBlock[blockId] = std::move(pattern);
        }
        else if (InstructionWritesFlags(instruction) && !IsConditionalMoveMnemonic(instruction.Mnemonic))
        {
            lastConditionByBlock.erase(blockId);
        }

        if (!instruction.IsCall && !InstructionWritesDestinationOperand(instruction, operands))
        {
            continue;
        }

        IrValue value;
        value.Id = "v" + std::to_string(values.size() + 1U);
        value.DefSite = instruction.Address;
        value.BlockId = blockId;
        value.Target = BuildIrTarget(instruction, operands, access, argumentRegisterMap, localKeyNameMap);
        value.Expression = DescribeAssignmentValue(instruction, operands, accesses, argumentRegisterMap, localKeyNameMap);

        if (value.Target.empty())
        {
            continue;
        }

        value.Canonical = value.Expression;
        value.IsConstant = IsConstantExpression(value.Canonical);
        value.IsCopy = value.Target == value.Expression;
        value.Kind = instruction.IsCall ? "call_result"
            : value.IsConstant ? "constant"
            : value.IsCopy ? "copy"
            : (access != nullptr && (access->Kind == "write" || access->Kind == "read_write")) ? "stack_store"
            : "assignment";

        if (IsConditionalMoveMnemonic(instruction.Mnemonic) && operands.size() >= 2)
        {
            const auto patternIt = lastConditionByBlock.find(value.BlockId);
            const std::string condition = patternIt == lastConditionByBlock.end()
                ? std::string()
                : BuildConditionExpressionForSelect(patternIt->second, CmovConditionSuffixToBranch(instruction.Mnemonic));

            if (!condition.empty())
            {
                const std::string previous = RewriteOperandWithRecoveredNames(operands[0], accesses, argumentRegisterMap, localKeyNameMap);
                const std::string selected = RewriteOperandWithRecoveredNames(operands[1], accesses, argumentRegisterMap, localKeyNameMap);
                value.Expression = "select(" + condition + ", " + selected + ", " + previous + ")";
                value.Canonical = value.Expression;
                value.IsConstant = false;
                value.IsCopy = false;
                value.Kind = "conditional_select";
            }
        }

        value.Confidence = Clamp01(
            0.58
            + (value.IsConstant ? 0.12 : 0.0)
            + (value.IsCopy ? 0.06 : 0.0)
            + (value.Kind == "conditional_select" ? 0.12 : 0.0)
            + (!value.BlockId.empty() ? 0.06 : 0.0));

        indexById[value.Id] = values.size();
        valueIndicesByBlock[value.BlockId].push_back(values.size());
        values.push_back(std::move(value));
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);

    for (const BasicBlock& block : blocks)
    {
        inIdsByBlock[block.Id] = StringMap();
        outIdsByBlock[block.Id] = StringMap();
        inCanonicalByBlock[block.Id] = StringMap();
        outCanonicalByBlock[block.Id] = StringMap();
    }

    bool changed = true;
    size_t iterations = 0;

    while (changed && iterations++ < blocks.size() + 1U)
    {
        changed = false;

        for (const BasicBlock& block : blocks)
        {
            StringMap inIds;
            StringMap inCanonical;
            const auto predecessorIt = predecessors.find(block.Id);

            if (&block != &blocks.front() && predecessorIt != predecessors.end())
            {
                inIds = MergePredecessorStringMaps(predecessorIt->second, outIdsByBlock);
                inCanonical = MergePredecessorStringMaps(predecessorIt->second, outCanonicalByBlock);
            }

            StringMap outIds = inIds;
            StringMap outCanonical = inCanonical;
            const auto indicesIt = valueIndicesByBlock.find(block.Id);

            if (indicesIt != valueIndicesByBlock.end())
            {
                for (const size_t valueIndex : indicesIt->second)
                {
                    IrValue& value = values[valueIndex];
                    const auto canonicalIt = outCanonical.find(value.Expression);
                    const std::string canonical = canonicalIt == outCanonical.end() ? value.Expression : canonicalIt->second;

                    if (value.Kind == "call_result")
                    {
                        EraseCallClobberedValues(outIds, outCanonical);
                    }

                    outIds[value.Target] = value.Id;
                    outCanonical[value.Target] = canonical;
                }
            }

            if (!StringMapsEqual(inIdsByBlock[block.Id], inIds)
                || !StringMapsEqual(outIdsByBlock[block.Id], outIds)
                || !StringMapsEqual(inCanonicalByBlock[block.Id], inCanonical)
                || !StringMapsEqual(outCanonicalByBlock[block.Id], outCanonical))
            {
                inIdsByBlock[block.Id] = std::move(inIds);
                outIdsByBlock[block.Id] = std::move(outIds);
                inCanonicalByBlock[block.Id] = std::move(inCanonical);
                outCanonicalByBlock[block.Id] = std::move(outCanonical);
                changed = true;
            }
        }
    }

    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    for (IrValue& value : values)
    {
        value.Uses.clear();
        value.IsDead = false;
    }

    std::set<std::string> usedValueIds;
    std::set<std::string> overwrittenValueIds;

    for (const BasicBlock& block : blocks)
    {
        StringMap ids = inIdsByBlock[block.Id];
        StringMap canonicalByTarget = inCanonicalByBlock[block.Id];
        const auto indicesIt = valueIndicesByBlock.find(block.Id);

        if (indicesIt == valueIndicesByBlock.end())
        {
            continue;
        }

        for (const size_t valueIndex : indicesIt->second)
        {
            IrValue& value = values[valueIndex];
            const auto instructionIt = instructionByAddress.find(value.DefSite);
            const std::vector<const MemoryAccess*> accesses = FindMemoryAccessesAtSite(accessBySite, value.DefSite);

            if (instructionIt != instructionByAddress.end())
            {
                const DisassembledInstruction& instruction = *instructionIt->second;
                const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

                for (const std::string& key : CollectReadValueKeys(instruction, operands, accesses, localKeyNameMap))
                {
                    const auto latest = ids.find(key);

                    if (latest != ids.end()
                        && std::find(value.Uses.begin(), value.Uses.end(), latest->second) == value.Uses.end())
                    {
                        value.Uses.push_back(latest->second);
                        usedValueIds.insert(latest->second);

                        const auto usedIndex = indexById.find(latest->second);

                        if (usedIndex != indexById.end() && usedIndex->second < values.size())
                        {
                            values[usedIndex->second].IsDead = false;
                        }
                    }
                }
            }

            const auto canonicalIt = canonicalByTarget.find(value.Expression);
            value.Canonical = canonicalIt == canonicalByTarget.end() ? value.Expression : canonicalIt->second;
            value.IsConstant = IsConstantExpression(value.Canonical);
            value.IsCopy = canonicalIt != canonicalByTarget.end() || value.Target == value.Expression;

            if (!value.IsCopy && value.Kind == "copy")
            {
                value.Kind = value.IsConstant ? "constant" : "assignment";
            }
            else if (value.IsCopy && value.Kind == "assignment")
            {
                value.Kind = "copy";
            }

            const auto previous = ids.find(value.Target);

            if (previous != ids.end())
            {
                const auto previousIndex = indexById.find(previous->second);

                if (previousIndex != indexById.end()
                    && previousIndex->second < values.size()
                    && values[previousIndex->second].Kind != "call_result")
                {
                    overwrittenValueIds.insert(previous->second);
                }
            }

            if (value.Kind == "call_result")
            {
                for (const char* reg : VolatileIntegerRegisters())
                {
                    const auto clobbered = ids.find(reg);

                    if (clobbered != ids.end())
                    {
                        overwrittenValueIds.insert(clobbered->second);
                    }
                }

                for (const char* reg : VolatileVectorRegisters())
                {
                    const auto clobbered = ids.find(reg);

                    if (clobbered != ids.end())
                    {
                        overwrittenValueIds.insert(clobbered->second);
                    }
                }

                EraseCallClobberedValues(ids, canonicalByTarget);
            }

            ids[value.Target] = value.Id;
            canonicalByTarget[value.Target] = value.Canonical.empty() ? value.Expression : value.Canonical;
        }
    }

    for (IrValue& value : values)
    {
        value.IsDead = overwrittenValueIds.find(value.Id) != overwrittenValueIds.end()
            && usedValueIds.find(value.Id) == usedValueIds.end()
            && value.Kind != "call_result";
    }

    return values;
}

std::string ClassifyReachingValueStorage(const std::string& name)
{
    if (IsRegisterName(name) || IsVectorRegisterName(name))
    {
        return "register";
    }

    if (StartsWithInsensitive(name, "local_"))
    {
        return "stack_local";
    }

    if (name.find('[') != std::string::npos)
    {
        return "memory";
    }

    return "value";
}

std::vector<ReachingValue> BuildReachingValues(
    const StringMap& ids,
    const StringMap& canonicalByTarget,
    const std::unordered_map<std::string, const IrValue*>& valuesById,
    bool converged)
{
    std::vector<std::string> names;
    std::vector<ReachingValue> values;

    for (const auto& entry : ids)
    {
        names.push_back(entry.first);
    }

    std::sort(names.begin(), names.end());

    for (const std::string& name : names)
    {
        const auto idIt = ids.find(name);

        if (idIt == ids.end())
        {
            continue;
        }

        ReachingValue value;
        value.Name = name;
        value.ValueId = idIt->second;
        value.Storage = ClassifyReachingValueStorage(name);
        value.Confidence = converged ? 0.74 : 0.45;

        const auto canonicalIt = canonicalByTarget.find(name);

        if (canonicalIt != canonicalByTarget.end())
        {
            value.Canonical = canonicalIt->second;
        }

        const auto valueIt = valuesById.find(value.ValueId);

        if (valueIt != valuesById.end())
        {
            if (value.Canonical.empty())
            {
                value.Canonical = valueIt->second->Canonical.empty()
                    ? valueIt->second->Expression
                    : valueIt->second->Canonical;
            }

            value.Confidence = Clamp01((value.Confidence * 0.35) + (valueIt->second->Confidence * 0.65));
        }

        values.push_back(std::move(value));
    }

    return values;
}

std::vector<BlockValueState> CollectBlockValueStates(
    const std::vector<BasicBlock>& blocks,
    const std::vector<IrValue>& irValues)
{
    std::unordered_map<std::string, std::vector<const IrValue*>> valuesByBlock;
    std::unordered_map<std::string, const IrValue*> valuesById;
    std::unordered_map<std::string, StringMap> inIdsByBlock;
    std::unordered_map<std::string, StringMap> outIdsByBlock;
    std::unordered_map<std::string, StringMap> inCanonicalByBlock;
    std::unordered_map<std::string, StringMap> outCanonicalByBlock;
    std::vector<BlockValueState> states;

    for (const IrValue& value : irValues)
    {
        valuesByBlock[value.BlockId].push_back(&value);
        valuesById[value.Id] = &value;
    }

    for (const BasicBlock& block : blocks)
    {
        inIdsByBlock[block.Id] = StringMap();
        outIdsByBlock[block.Id] = StringMap();
        inCanonicalByBlock[block.Id] = StringMap();
        outCanonicalByBlock[block.Id] = StringMap();
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);
    bool changed = true;
    size_t iterations = 0;

    while (changed && iterations++ < blocks.size() + 1U)
    {
        changed = false;

        for (const BasicBlock& block : blocks)
        {
            StringMap inIds;
            StringMap inCanonical;
            const auto predecessorIt = predecessors.find(block.Id);

            if (&block != &blocks.front() && predecessorIt != predecessors.end())
            {
                inIds = MergePredecessorStringMaps(predecessorIt->second, outIdsByBlock);
                inCanonical = MergePredecessorStringMaps(predecessorIt->second, outCanonicalByBlock);
            }

            StringMap outIds = inIds;
            StringMap outCanonical = inCanonical;
            const auto valuesIt = valuesByBlock.find(block.Id);

            if (valuesIt != valuesByBlock.end())
            {
                for (const IrValue* value : valuesIt->second)
                {
                    if (value == nullptr || value->Target.empty())
                    {
                        continue;
                    }

                    if (value->Kind == "call_result")
                    {
                        EraseCallClobberedValues(outIds, outCanonical);
                    }

                    outIds[value->Target] = value->Id;
                    outCanonical[value->Target] = value->Canonical.empty() ? value->Expression : value->Canonical;
                }
            }

            if (!StringMapsEqual(inIdsByBlock[block.Id], inIds)
                || !StringMapsEqual(outIdsByBlock[block.Id], outIds)
                || !StringMapsEqual(inCanonicalByBlock[block.Id], inCanonical)
                || !StringMapsEqual(outCanonicalByBlock[block.Id], outCanonical))
            {
                inIdsByBlock[block.Id] = std::move(inIds);
                outIdsByBlock[block.Id] = std::move(outIds);
                inCanonicalByBlock[block.Id] = std::move(inCanonical);
                outCanonicalByBlock[block.Id] = std::move(outCanonical);
                changed = true;
            }
        }
    }

    const bool converged = !changed;

    for (const BasicBlock& block : blocks)
    {
        BlockValueState state;
        state.BlockId = block.Id;
        state.Converged = converged;
        state.LiveIn = BuildReachingValues(inIdsByBlock[block.Id], inCanonicalByBlock[block.Id], valuesById, converged);
        state.LiveOut = BuildReachingValues(outIdsByBlock[block.Id], outCanonicalByBlock[block.Id], valuesById, converged);
        state.Confidence = converged ? 0.76 : 0.42;
        states.push_back(std::move(state));
    }

    return states;
}

bool TryGetRawStackDisplacement(const MemoryAccess& access, int64_t& displacement)
{
    if (access.BaseRegister != "rsp")
    {
        return false;
    }

    if (!TryParseSignedValue(access.Displacement, displacement))
    {
        displacement = 0;
    }

    return true;
}

bool TryGetOutgoingStackArgumentOrdinal(const MemoryAccess& access, uint32_t& ordinal)
{
    int64_t displacement = 0;

    if (access.Implicit
        || (access.Kind != "write" && access.Kind != "read_write")
        || !TryGetRawStackDisplacement(access, displacement)
        || displacement < 0x20
        || ((displacement - 0x20) % 8) != 0)
    {
        return false;
    }

    ordinal = 5U + static_cast<uint32_t>((displacement - 0x20) / 8);
    return ordinal <= 16U;
}

struct PendingStackArgument
{
    CallArgumentFact Fact;
    size_t InstructionIndex = 0;
};

struct CallArgumentRegisterSlot
{
    const char* Register = nullptr;
    uint32_t Ordinal = 0;
};

using PendingStackArgumentMap = std::map<uint32_t, PendingStackArgument>;

struct CallArgumentFlowState
{
    StringMap Registers;
    PendingStackArgumentMap PendingStackArguments;
};

bool CallArgumentFactsEqual(const CallArgumentFact& left, const CallArgumentFact& right)
{
    return left.Site == right.Site
        && left.Ordinal == right.Ordinal
        && left.Location == right.Location
        && left.Expression == right.Expression
        && left.TypeHint == right.TypeHint
        && left.Source == right.Source
        && left.Confidence == right.Confidence;
}

bool PendingStackArgumentsEqual(const PendingStackArgument& left, const PendingStackArgument& right)
{
    return left.InstructionIndex == right.InstructionIndex
        && CallArgumentFactsEqual(left.Fact, right.Fact);
}

bool PendingStackArgumentMapsEqual(const PendingStackArgumentMap& left, const PendingStackArgumentMap& right)
{
    if (left.size() != right.size())
    {
        return false;
    }

    for (const auto& entry : left)
    {
        const auto it = right.find(entry.first);

        if (it == right.end() || !PendingStackArgumentsEqual(entry.second, it->second))
        {
            return false;
        }
    }

    return true;
}

bool CallArgumentFlowStatesEqual(const CallArgumentFlowState& left, const CallArgumentFlowState& right)
{
    return StringMapsEqual(left.Registers, right.Registers)
        && PendingStackArgumentMapsEqual(left.PendingStackArguments, right.PendingStackArguments);
}

PendingStackArgumentMap MergePendingStackArgumentMaps(const std::vector<PendingStackArgumentMap>& incoming)
{
    if (incoming.empty())
    {
        return {};
    }

    PendingStackArgumentMap merged = incoming.front();

    for (size_t index = 1; index < incoming.size(); ++index)
    {
        for (auto it = merged.begin(); it != merged.end();)
        {
            const auto nextIt = incoming[index].find(it->first);

            if (nextIt == incoming[index].end() || !PendingStackArgumentsEqual(it->second, nextIt->second))
            {
                it = merged.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    return merged;
}

CallArgumentFlowState MergeCallArgumentFlowStates(const std::vector<CallArgumentFlowState>& incoming)
{
    CallArgumentFlowState merged;

    if (incoming.empty())
    {
        return merged;
    }

    std::vector<StringMap> registers;
    std::vector<PendingStackArgumentMap> pendingStackArguments;

    for (const CallArgumentFlowState& state : incoming)
    {
        registers.push_back(state.Registers);
        pendingStackArguments.push_back(state.PendingStackArguments);
    }

    merged.Registers = registers.front();

    for (size_t index = 1; index < registers.size(); ++index)
    {
        for (auto it = merged.Registers.begin(); it != merged.Registers.end();)
        {
            const auto nextIt = registers[index].find(it->first);

            if (nextIt == registers[index].end() || nextIt->second != it->second)
            {
                it = merged.Registers.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    merged.PendingStackArguments = MergePendingStackArgumentMaps(pendingStackArguments);
    return merged;
}

std::vector<CallArgumentFact> CollectCallArgumentFacts(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<MemoryAccess>& memoryAccesses,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    constexpr size_t kMaxPendingStackArgumentInstructionDistance = 8;
    static const std::array<CallArgumentRegisterSlot, 8> argumentRegisters = {
        CallArgumentRegisterSlot{ "rcx", 1 },
        CallArgumentRegisterSlot{ "rdx", 2 },
        CallArgumentRegisterSlot{ "r8", 3 },
        CallArgumentRegisterSlot{ "r9", 4 },
        CallArgumentRegisterSlot{ "xmm0", 1 },
        CallArgumentRegisterSlot{ "xmm1", 2 },
        CallArgumentRegisterSlot{ "xmm2", 3 },
        CallArgumentRegisterSlot{ "xmm3", 4 }
    };
    const MemoryAccessIndex accessBySite = BuildMemoryAccessIndex(memoryAccesses);
    const std::unordered_map<std::string, std::string> argumentRegisterMap = BuildArgumentRegisterNameMap(arguments);
    const std::unordered_map<std::string, std::string> localKeyNameMap = BuildLocalKeyNameMap(locals);
    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;
    std::unordered_map<uint64_t, size_t> instructionIndexByAddress;
    std::set<uint64_t> instructionAddresses;
    const uint64_t entryAddress = instructions.empty() ? 0 : instructions.front().Address;
    CallArgumentFlowState entryState;

    for (size_t index = 0; index < instructions.size(); ++index)
    {
        instructionByAddress[instructions[index].Address] = &instructions[index];
        instructionIndexByAddress[instructions[index].Address] = index;
        instructionAddresses.insert(instructions[index].Address);
    }

    for (const RecoveredArgument& argument : arguments)
    {
        if (!argument.Register.empty() && !argument.Name.empty())
        {
            entryState.Registers[NormalizeRegisterAlias(argument.Register)] = argument.Name;
        }
    }

    auto mergeInputState = [&entryState](
        const BasicBlock& block,
        const BasicBlock& entryBlock,
        const std::unordered_map<std::string, std::vector<std::string>>& predecessors,
        const std::unordered_map<std::string, CallArgumentFlowState>& outStates) -> CallArgumentFlowState
    {
        std::vector<CallArgumentFlowState> incoming;

        if (block.Id == entryBlock.Id)
        {
            incoming.push_back(entryState);
        }

        const auto predecessorIt = predecessors.find(block.Id);

        if (predecessorIt != predecessors.end())
        {
            for (const std::string& predecessor : predecessorIt->second)
            {
                const auto stateIt = outStates.find(predecessor);

                if (stateIt != outStates.end())
                {
                    incoming.push_back(stateIt->second);
                }
            }
        }

        return MergeCallArgumentFlowStates(incoming);
    };

    auto transferBlock = [&](
        const BasicBlock& block,
        CallArgumentFlowState state,
        std::vector<CallArgumentFact>* emitted) -> CallArgumentFlowState
    {
        for (const uint64_t address : block.InstructionAddresses)
        {
            const auto instructionIt = instructionByAddress.find(address);

            if (instructionIt == instructionByAddress.end())
            {
                continue;
            }

            const DisassembledInstruction& instruction = *instructionIt->second;
            const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
            const std::vector<const MemoryAccess*> accesses = FindMemoryAccessesAtSite(accessBySite, instruction.Address);
            const auto indexIt = instructionIndexByAddress.find(instruction.Address);
            const size_t instructionIndex = indexIt == instructionIndexByAddress.end() ? 0 : indexIt->second;
            const bool isCallLike = instruction.IsCall || IsTailJumpCandidate(instruction, entryAddress, &instructionAddresses);

            if (isCallLike)
            {
                if (emitted != nullptr)
                {
                    for (const CallArgumentRegisterSlot& argumentSlot : argumentRegisters)
                    {
                        const std::string reg = argumentSlot.Register;
                        const auto stateIt = state.Registers.find(reg);

                        if (stateIt == state.Registers.end() || stateIt->second.empty())
                        {
                            continue;
                        }

                        CallArgumentFact fact;
                        fact.Site = instruction.Address;
                        fact.Ordinal = argumentSlot.Ordinal;
                        fact.Location = reg;
                        fact.Expression = stateIt->second;
                        fact.TypeHint = InferRegisterArgumentTypeHint(reg, false);
                        const auto incomingIt = argumentRegisterMap.find(reg);
                        fact.Source = incomingIt != argumentRegisterMap.end() && incomingIt->second == stateIt->second
                            ? "incoming_register"
                            : "register_state";
                        fact.Confidence = fact.Source == "incoming_register" ? 0.58 : 0.70;
                        emitted->push_back(std::move(fact));
                    }

                    for (const auto& entry : state.PendingStackArguments)
                    {
                        const PendingStackArgument& pending = entry.second;

                        if (instructionIndex < pending.InstructionIndex
                            || instructionIndex - pending.InstructionIndex > kMaxPendingStackArgumentInstructionDistance)
                        {
                            continue;
                        }

                        CallArgumentFact fact = pending.Fact;
                        fact.Site = instruction.Address;
                        emitted->push_back(std::move(fact));
                    }
                }

                state.PendingStackArguments.clear();

                for (const char* reg : VolatileIntegerRegisters())
                {
                    state.Registers.erase(reg);
                }

                for (const char* reg : VolatileVectorRegisters())
                {
                    state.Registers.erase(reg);
                }

                continue;
            }

            const std::string mnemonic = ToLowerAscii(instruction.Mnemonic);

            if (mnemonic == "push" || mnemonic == "pop" || mnemonic == "leave" || DestinationIsRegister(operands, "rsp"))
            {
                state.PendingStackArguments.clear();
            }

            const std::string value = DescribeAssignmentValue(instruction, operands, accesses, argumentRegisterMap, localKeyNameMap);

            for (const CallArgumentRegisterSlot& argumentSlot : argumentRegisters)
            {
                const std::string canonicalRegister = argumentSlot.Register;

                if (InstructionWritesRegister(instruction, operands, canonicalRegister))
                {
                    state.Registers[canonicalRegister] = value;
                }
            }

            for (const MemoryAccess* access : accesses)
            {
                uint32_t ordinal = 0;

                if (access == nullptr || !TryGetOutgoingStackArgumentOrdinal(*access, ordinal))
                {
                    continue;
                }

                CallArgumentFact fact;
                fact.Site = instruction.Address;
                fact.Ordinal = ordinal;
                fact.Location = access->Access;
                fact.Expression = value;
                fact.TypeHint = InferTypeHintFromWidth(access->WidthBits, false);
                fact.Source = "stack_store";
                fact.Confidence = 0.64;

                PendingStackArgument pending;
                pending.Fact = std::move(fact);
                pending.InstructionIndex = instructionIndex;
                state.PendingStackArguments[ordinal] = std::move(pending);
            }
        }

        return state;
    };

    std::vector<BasicBlock> effectiveBlocks = blocks;

    if (effectiveBlocks.empty() && !instructions.empty())
    {
        BasicBlock block;
        block.Id = "bb0";
        block.StartAddress = instructions.front().Address;
        block.EndAddress = instructions.back().EndAddress;

        for (const DisassembledInstruction& instruction : instructions)
        {
            block.InstructionAddresses.push_back(instruction.Address);
        }

        effectiveBlocks.push_back(std::move(block));
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(effectiveBlocks);
    std::unordered_map<std::string, CallArgumentFlowState> inStates;
    std::unordered_map<std::string, CallArgumentFlowState> outStates;
    bool changed = true;
    size_t iterations = 0;

    while (changed && iterations++ < effectiveBlocks.size() + 2U)
    {
        changed = false;

        for (const BasicBlock& block : effectiveBlocks)
        {
            const CallArgumentFlowState inState = mergeInputState(block, effectiveBlocks.front(), predecessors, outStates);
            const CallArgumentFlowState outState = transferBlock(block, inState, nullptr);

            if (!CallArgumentFlowStatesEqual(inStates[block.Id], inState) || !CallArgumentFlowStatesEqual(outStates[block.Id], outState))
            {
                inStates[block.Id] = inState;
                outStates[block.Id] = outState;
                changed = true;
            }
        }
    }

    std::vector<CallArgumentFact> callArguments;

    for (const BasicBlock& block : effectiveBlocks)
    {
        transferBlock(block, inStates[block.Id], &callArguments);
    }

    std::sort(
        callArguments.begin(),
        callArguments.end(),
        [](const CallArgumentFact& left, const CallArgumentFact& right)
        {
            if (left.Site != right.Site)
            {
                return left.Site < right.Site;
            }

            return left.Ordinal < right.Ordinal;
        });

    return callArguments;
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

std::unordered_map<std::string, std::set<std::string>> BuildPostDominatorSets(const std::vector<BasicBlock>& blocks)
{
    std::unordered_map<std::string, std::set<std::string>> postDominators;
    std::set<std::string> allBlocks;

    for (const BasicBlock& block : blocks)
    {
        allBlocks.insert(block.Id);
    }

    for (const BasicBlock& block : blocks)
    {
        postDominators[block.Id] = block.Successors.empty() ? std::set<std::string>{ block.Id } : allBlocks;
    }

    bool changed = true;

    while (changed)
    {
        changed = false;

        for (auto blockIt = blocks.rbegin(); blockIt != blocks.rend(); ++blockIt)
        {
            const BasicBlock& block = *blockIt;

            if (block.Successors.empty())
            {
                continue;
            }

            std::set<std::string> next = allBlocks;

            for (const std::string& successor : block.Successors)
            {
                std::set<std::string> intersection;
                const auto postDomIt = postDominators.find(successor);

                if (postDomIt == postDominators.end())
                {
                    continue;
                }

                std::set_intersection(
                    next.begin(), next.end(),
                    postDomIt->second.begin(), postDomIt->second.end(),
                    std::inserter(intersection, intersection.begin()));
                next = std::move(intersection);
            }

            next.insert(block.Id);

            if (postDominators[block.Id] != next)
            {
                postDominators[block.Id] = std::move(next);
                changed = true;
            }
        }
    }

    return postDominators;
}

std::unordered_map<std::string, size_t> BuildBlockOrder(const std::vector<BasicBlock>& blocks)
{
    std::unordered_map<std::string, size_t> order;

    for (size_t index = 0; index < blocks.size(); ++index)
    {
        order[blocks[index].Id] = index;
    }

    return order;
}

std::string FindBlockContainingAddress(const std::vector<BasicBlock>& blocks, uint64_t address)
{
    for (const BasicBlock& block : blocks)
    {
        if (address >= block.StartAddress && address < block.EndAddress)
        {
            return block.Id;
        }
    }

    return std::string();
}

bool AddRecoveredSwitchSuccessorsToBlocks(
    std::vector<BasicBlock>& blocks,
    const std::vector<SwitchInfo>& switches)
{
    bool changed = false;

    for (const SwitchInfo& switchInfo : switches)
    {
        if (switchInfo.CaseTargets.empty() && switchInfo.DefaultTarget == 0)
        {
            continue;
        }

        const std::string headerBlock = FindBlockContainingAddress(blocks, switchInfo.Site);

        if (headerBlock.empty())
        {
            continue;
        }

        for (BasicBlock& block : blocks)
        {
            if (block.Id != headerBlock)
            {
                continue;
            }

            const size_t previousSize = block.Successors.size();

            std::vector<uint64_t> targets = switchInfo.CaseTargets;

            if (switchInfo.DefaultTarget != 0)
            {
                targets.push_back(switchInfo.DefaultTarget);
            }

            for (const uint64_t target : targets)
            {
                const std::string targetBlock = FindBlockContainingAddress(blocks, target);

                if (!targetBlock.empty())
                {
                    AddUniqueSuccessor(block, targetBlock);
                }
            }

            changed = changed || block.Successors.size() != previousSize;
            break;
        }
    }

    return changed;
}

std::string FindNearestCommonPostDominator(
    const BasicBlock& block,
    const std::unordered_map<std::string, std::set<std::string>>& postDominators,
    const std::unordered_map<std::string, size_t>& blockOrder)
{
    if (block.Successors.size() < 2)
    {
        return std::string();
    }

    std::set<std::string> common;
    bool initialized = false;

    for (const std::string& successor : block.Successors)
    {
        const auto postDomIt = postDominators.find(successor);

        if (postDomIt == postDominators.end())
        {
            return std::string();
        }

        if (!initialized)
        {
            common = postDomIt->second;
            initialized = true;
            continue;
        }

        std::set<std::string> intersection;
        std::set_intersection(
            common.begin(), common.end(),
            postDomIt->second.begin(), postDomIt->second.end(),
            std::inserter(intersection, intersection.begin()));
        common = std::move(intersection);
    }

    common.erase(block.Id);

    if (common.empty())
    {
        return std::string();
    }

    std::string best;
    size_t bestOrder = static_cast<size_t>(-1);

    for (const std::string& candidate : common)
    {
        const auto orderIt = blockOrder.find(candidate);

        if (orderIt != blockOrder.end() && orderIt->second < bestOrder)
        {
            best = candidate;
            bestOrder = orderIt->second;
        }
    }

    return best;
}

std::vector<std::string> CollectBlocksUntilJoin(
    const std::vector<BasicBlock>& blocks,
    const std::string& startBlock,
    const std::string& joinBlock)
{
    std::vector<std::string> result;
    std::set<std::string> visited;
    std::vector<std::string> pending;
    std::unordered_map<std::string, const BasicBlock*> blockById;

    for (const BasicBlock& block : blocks)
    {
        blockById[block.Id] = &block;
    }

    pending.push_back(startBlock);

    while (!pending.empty() && result.size() < blocks.size())
    {
        const std::string current = pending.back();
        pending.pop_back();

        if (current.empty() || current == joinBlock || !visited.insert(current).second)
        {
            continue;
        }

        result.push_back(current);
        const auto blockIt = blockById.find(current);

        if (blockIt == blockById.end())
        {
            continue;
        }

        for (const std::string& successor : blockIt->second->Successors)
        {
            if (successor != joinBlock)
            {
                pending.push_back(successor);
            }
        }
    }

    std::sort(result.begin(), result.end());
    return result;
}

std::vector<std::string> CollectNaturalLoopBody(
    const std::string& header,
    const std::string& latch,
    const std::unordered_map<std::string, std::vector<std::string>>& predecessors,
    const std::unordered_map<std::string, std::set<std::string>>& dominators)
{
    std::set<std::string> body;
    std::vector<std::string> pending;
    body.insert(header);
    body.insert(latch);
    pending.push_back(latch);

    while (!pending.empty())
    {
        const std::string current = pending.back();
        pending.pop_back();
        const auto predecessorIt = predecessors.find(current);

        if (predecessorIt == predecessors.end())
        {
            continue;
        }

        for (const std::string& predecessor : predecessorIt->second)
        {
            const auto dominatorIt = dominators.find(predecessor);
            const bool dominatedByHeader = dominatorIt != dominators.end()
                && dominatorIt->second.find(header) != dominatorIt->second.end();

            if (!dominatedByHeader)
            {
                continue;
            }

            if (body.insert(predecessor).second && predecessor != header)
            {
                pending.push_back(predecessor);
            }
        }
    }

    return std::vector<std::string>(body.begin(), body.end());
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

const BasicBlock* FindBlockById(const std::vector<BasicBlock>& blocks, const std::string& blockId)
{
    for (const BasicBlock& block : blocks)
    {
        if (block.Id == blockId)
        {
            return &block;
        }
    }

    return nullptr;
}

const DisassembledInstruction* FindInstructionByAddress(const std::vector<DisassembledInstruction>& instructions, uint64_t address)
{
    for (const DisassembledInstruction& instruction : instructions)
    {
        if (instruction.Address == address)
        {
            return &instruction;
        }
    }

    return nullptr;
}

bool OperandMatchesObfuscationVariable(const std::string& operand, const std::string& variable)
{
    const std::string strippedOperand = StripPointerDecorators(operand);
    const std::string strippedVariable = StripPointerDecorators(variable);
    const std::string operandRegister = NormalizeRegisterAlias(strippedOperand);
    const std::string variableRegister = NormalizeRegisterAlias(strippedVariable);

    if (!operandRegister.empty() && !variableRegister.empty())
    {
        return operandRegister == variableRegister;
    }

    if (strippedOperand == strippedVariable)
    {
        return true;
    }

    if (IsRegisterName(strippedVariable))
    {
        const std::vector<std::string> registers = ExtractOperandRegisterTokens(strippedOperand);
        return registers.size() == 1 && registers.front() == strippedVariable;
    }

    return false;
}

bool TryNormalizeStateValue(const std::string& expression, std::string& normalized)
{
    int64_t signedValue = 0;

    if (!TryParseSignedValue(StripPointerDecorators(expression), signedValue))
    {
        return false;
    }

    normalized = signedValue < 0
        ? HexS64(signedValue)
        : HexU64(static_cast<uint64_t>(signedValue));
    return true;
}

std::string FormatStateValue(uint64_t value)
{
    return HexU64(value);
}

std::string FormatStateValue(int64_t value)
{
    return value < 0
        ? HexS64(value)
        : HexU64(static_cast<uint64_t>(value));
}

std::string NormalizeObfuscationBranchMnemonic(const std::string& mnemonic)
{
    const std::string lower = ToLowerAscii(TrimCopy(mnemonic));

    if (lower == "jz")
    {
        return "je";
    }

    if (lower == "jnz")
    {
        return "jne";
    }

    if (lower == "jnbe")
    {
        return "ja";
    }

    if (lower == "jnb" || lower == "jnc")
    {
        return "jae";
    }

    if (lower == "jnae" || lower == "jc")
    {
        return "jb";
    }

    if (lower == "jna")
    {
        return "jbe";
    }

    if (lower == "jnle")
    {
        return "jg";
    }

    if (lower == "jnl")
    {
        return "jge";
    }

    if (lower == "jnge")
    {
        return "jl";
    }

    if (lower == "jng")
    {
        return "jle";
    }

    return lower;
}

bool IsEqualityBranchMnemonic(const std::string& mnemonic)
{
    const std::string lower = ToLowerAscii(TrimCopy(mnemonic));
    return lower == "je" || lower == "jz";
}

bool IsInequalityBranchMnemonic(const std::string& mnemonic)
{
    const std::string lower = ToLowerAscii(TrimCopy(mnemonic));
    return lower == "jne" || lower == "jnz";
}

std::string NormalizeStateVariableExpression(const std::string& expression)
{
    const std::vector<std::string> registers = ExtractOperandRegisterTokens(expression);

    if (registers.size() == 1)
    {
        return registers.front();
    }

    const std::string stripped = StripPointerDecorators(expression);
    const std::string canonical = NormalizeRegisterAlias(stripped);
    return canonical.empty() ? stripped : canonical;
}

std::string FormatConditionOperand(const std::string& operand)
{
    const std::string stripped = StripPointerDecorators(operand);
    const std::string canonical = NormalizeRegisterAlias(stripped);
    return canonical.empty() ? stripped : canonical;
}

std::vector<const DisassembledInstruction*> GetBlockInstructions(
    const BasicBlock& block,
    const std::vector<DisassembledInstruction>& instructions)
{
    std::vector<const DisassembledInstruction*> blockInstructions;

    for (const uint64_t address : block.InstructionAddresses)
    {
        const DisassembledInstruction* instruction = FindInstructionByAddress(instructions, address);

        if (instruction != nullptr)
        {
            blockInstructions.push_back(instruction);
        }
    }

    return blockInstructions;
}

std::vector<std::string> CollectStateCompareVariables(
    const BasicBlock& block,
    const std::vector<DisassembledInstruction>& instructions)
{
    std::vector<std::string> variables;

    for (const DisassembledInstruction* instruction : GetBlockInstructions(block, instructions))
    {
        if (instruction == nullptr || instruction->Mnemonic != "cmp")
        {
            continue;
        }

        const std::vector<std::string> operands = SplitOperands(instruction->OperandText);

        if (operands.size() < 2)
        {
            continue;
        }

        std::string ignored;

        if (TryNormalizeStateValue(operands[1], ignored))
        {
            const std::string operand = StripPointerDecorators(operands[0]);
            const std::string canonical = NormalizeRegisterAlias(operand);
            variables.push_back(canonical.empty() ? operand : canonical);
        }
        else if (TryNormalizeStateValue(operands[0], ignored))
        {
            const std::string operand = StripPointerDecorators(operands[1]);
            const std::string canonical = NormalizeRegisterAlias(operand);
            variables.push_back(canonical.empty() ? operand : canonical);
        }
    }

    std::sort(variables.begin(), variables.end());
    variables.erase(std::unique(variables.begin(), variables.end()), variables.end());
    return variables;
}

bool SwitchInfoBelongsToBlock(const SwitchInfo& switchInfo, const BasicBlock& block)
{
    return switchInfo.Site >= block.StartAddress && switchInfo.Site < block.EndAddress;
}

std::vector<const SwitchInfo*> CollectSwitchesForDispatcherHeader(
    const std::vector<BasicBlock>& blocks,
    const std::vector<SwitchInfo>& switches,
    const BasicBlock& header)
{
    std::vector<const SwitchInfo*> results;

    for (const SwitchInfo& switchInfo : switches)
    {
        if (SwitchInfoBelongsToBlock(switchInfo, header))
        {
            results.push_back(&switchInfo);
            continue;
        }

        for (const std::string& successor : header.Successors)
        {
            const BasicBlock* successorBlock = FindBlockById(blocks, successor);

            if (successorBlock != nullptr && SwitchInfoBelongsToBlock(switchInfo, *successorBlock))
            {
                results.push_back(&switchInfo);
                break;
            }
        }
    }

    return results;
}

std::vector<std::string> CollectStateSwitchVariables(
    const std::vector<BasicBlock>& blocks,
    const std::vector<SwitchInfo>& switches,
    const BasicBlock& header)
{
    std::vector<std::string> variables;
    const std::vector<const SwitchInfo*> headerSwitches = CollectSwitchesForDispatcherHeader(blocks, switches, header);

    for (const SwitchInfo* switchInfo : headerSwitches)
    {
        if (switchInfo == nullptr || switchInfo->IndexExpression.empty())
        {
            continue;
        }

        const std::string variable = NormalizeStateVariableExpression(switchInfo->IndexExpression);

        if (!variable.empty())
        {
            variables.push_back(variable);
        }
    }

    std::sort(variables.begin(), variables.end());
    variables.erase(std::unique(variables.begin(), variables.end()), variables.end());
    return variables;
}

void AppendUniqueStrings(std::vector<std::string>& destination, const std::vector<std::string>& source)
{
    for (const std::string& value : source)
    {
        if (!value.empty() && std::find(destination.begin(), destination.end(), value) == destination.end())
        {
            destination.push_back(value);
        }
    }
}

bool TryExtractStateCompareConstant(
    const BasicBlock& block,
    const std::vector<DisassembledInstruction>& instructions,
    const std::string& stateVariable,
    std::string& stateValue)
{
    for (const DisassembledInstruction* instruction : GetBlockInstructions(block, instructions))
    {
        if (instruction == nullptr || instruction->Mnemonic != "cmp")
        {
            continue;
        }

        const std::vector<std::string> operands = SplitOperands(instruction->OperandText);

        if (operands.size() < 2)
        {
            continue;
        }

        if (OperandMatchesObfuscationVariable(operands[0], stateVariable)
            && TryNormalizeStateValue(operands[1], stateValue))
        {
            return true;
        }

        if (OperandMatchesObfuscationVariable(operands[1], stateVariable)
            && TryNormalizeStateValue(operands[0], stateValue))
        {
            return true;
        }
    }

    return false;
}

bool BlockContainsStateCompare(
    const std::vector<BasicBlock>& blocks,
    const std::vector<DisassembledInstruction>& instructions,
    const std::string& blockId,
    const std::string& stateVariable)
{
    const BasicBlock* block = FindBlockById(blocks, blockId);
    std::string ignored;
    return block != nullptr && TryExtractStateCompareConstant(*block, instructions, stateVariable, ignored);
}

uint64_t FindFirstAssignmentSite(
    const std::vector<IrValue>& values,
    const std::string& target)
{
    uint64_t firstSite = 0;

    for (const IrValue& value : values)
    {
        if (!OperandMatchesObfuscationVariable(value.Target, target))
        {
            continue;
        }

        if (firstSite == 0 || value.DefSite < firstSite)
        {
            firstSite = value.DefSite;
        }
    }

    return firstSite;
}

uint32_t CountAssignmentsToTargetInDistinctBlocks(
    const std::vector<IrValue>& values,
    const std::string& target)
{
    std::set<std::string> blockIds;

    for (const IrValue& value : values)
    {
        if (OperandMatchesObfuscationVariable(value.Target, target) && !value.BlockId.empty())
        {
            blockIds.insert(value.BlockId);
        }
    }

    return static_cast<uint32_t>(blockIds.size());
}

uint32_t CountReadsOfTargetInBlocks(
    const std::vector<BasicBlock>& blocks,
    const std::vector<DisassembledInstruction>& instructions,
    const std::set<std::string>& blockIds,
    const std::string& target)
{
    uint32_t reads = 0;

    for (const std::string& blockId : blockIds)
    {
        const BasicBlock* block = FindBlockById(blocks, blockId);

        if (block == nullptr)
        {
            continue;
        }

        for (const DisassembledInstruction* instruction : GetBlockInstructions(*block, instructions))
        {
            if (instruction == nullptr)
            {
                continue;
            }

            const std::vector<std::string> operands = SplitOperands(instruction->OperandText);

            for (const std::string& operand : operands)
            {
                if (OperandMatchesObfuscationVariable(operand, target))
                {
                    ++reads;
                    break;
                }
            }
        }
    }

    return reads;
}

struct ObfuscationStateTarget
{
    std::string TargetBlock;
    std::string Condition;
    std::string Evidence;
    double Confidence = 0.0;
};

std::unordered_map<std::string, ObfuscationStateTarget> BuildStateTargetMapForDispatcher(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<NormalizedCondition>& conditions,
    const std::string& headerBlockId,
    const std::string& stateVariable,
    std::set<std::string>& dispatcherBlocks)
{
    std::unordered_map<std::string, ObfuscationStateTarget> targets;
    std::string currentBlockId = headerBlockId;

    for (size_t depth = 0; depth < 12 && !currentBlockId.empty(); ++depth)
    {
        if (!dispatcherBlocks.insert(currentBlockId).second)
        {
            break;
        }

        const BasicBlock* block = FindBlockById(blocks, currentBlockId);

        if (block == nullptr)
        {
            break;
        }

        std::string stateValue;

        if (!TryExtractStateCompareConstant(*block, instructions, stateVariable, stateValue))
        {
            break;
        }

        const NormalizedCondition* condition = FindConditionForBlock(conditions, currentBlockId);

        if (condition == nullptr)
        {
            break;
        }

        std::string caseTarget;
        std::string nextDispatcher;

        if (IsEqualityBranchMnemonic(condition->BranchMnemonic))
        {
            caseTarget = condition->TrueTargetBlock;
            nextDispatcher = condition->FalseTargetBlock;
        }
        else if (IsInequalityBranchMnemonic(condition->BranchMnemonic))
        {
            caseTarget = condition->FalseTargetBlock;
            nextDispatcher = condition->TrueTargetBlock;
        }
        else
        {
            break;
        }

        if (!caseTarget.empty())
        {
            ObfuscationStateTarget target;
            target.TargetBlock = caseTarget;
            target.Condition = condition->Expression;
            target.Evidence = currentBlockId + " compares " + stateVariable + " with " + stateValue;
            target.Confidence = 0.78;
            targets[stateValue] = target;
        }

        if (nextDispatcher.empty()
            || dispatcherBlocks.find(nextDispatcher) != dispatcherBlocks.end()
            || !BlockContainsStateCompare(blocks, instructions, nextDispatcher, stateVariable))
        {
            break;
        }

        currentBlockId = nextDispatcher;
    }

    return targets;
}

bool MergeSwitchStateTargetMapForDispatcher(
    const std::vector<BasicBlock>& blocks,
    const std::vector<SwitchInfo>& switches,
    const BasicBlock& header,
    const std::string& stateVariable,
    std::set<std::string>& dispatcherBlocks,
    std::unordered_map<std::string, ObfuscationStateTarget>& targets)
{
    bool matched = false;
    const std::vector<const SwitchInfo*> headerSwitches = CollectSwitchesForDispatcherHeader(blocks, switches, header);

    for (const SwitchInfo* switchInfo : headerSwitches)
    {
        if (switchInfo == nullptr || switchInfo->CaseTargets.empty())
        {
            continue;
        }

        const std::string switchStateVariable = NormalizeStateVariableExpression(switchInfo->IndexExpression);

        if (!OperandMatchesObfuscationVariable(switchStateVariable, stateVariable))
        {
            continue;
        }

        const std::string switchBlockId = FindBlockContainingAddress(blocks, switchInfo->Site);

        if (!switchBlockId.empty())
        {
            dispatcherBlocks.insert(switchBlockId);
        }

        matched = true;

        for (size_t index = 0; index < switchInfo->CaseTargets.size(); ++index)
        {
            const std::string targetBlock = FindBlockContainingAddress(blocks, switchInfo->CaseTargets[index]);

            if (targetBlock.empty())
            {
                continue;
            }

            const int64_t stateValueInt = switchInfo->RangeKnown
                ? switchInfo->RangeMin + static_cast<int64_t>(index)
                : static_cast<int64_t>(index);
            const std::string stateValue = FormatStateValue(stateValueInt);

            if (targets.find(stateValue) != targets.end())
            {
                continue;
            }

            ObfuscationStateTarget target;
            target.TargetBlock = targetBlock;
            target.Condition = stateVariable + " == " + stateValue;
            target.Evidence = switchBlockId + " switches " + stateVariable + " case " + stateValue;
            target.Confidence = 0.82;
            targets[stateValue] = target;
        }
    }

    return matched;
}

double ComputeDominatorCoverage(
    const std::unordered_map<std::string, std::set<std::string>>& dominators,
    const std::vector<BasicBlock>& blocks,
    const std::string& dominatorBlock)
{
    if (blocks.empty() || dominatorBlock.empty())
    {
        return 0.0;
    }

    size_t dominated = 0;

    for (const BasicBlock& block : blocks)
    {
        const auto domIt = dominators.find(block.Id);

        if (domIt != dominators.end() && domIt->second.find(dominatorBlock) != domIt->second.end())
        {
            ++dominated;
        }
    }

    return static_cast<double>(dominated) / static_cast<double>(blocks.size());
}

bool HasBackEdgeToBlock(
    const std::vector<BasicBlock>& blocks,
    const std::unordered_map<std::string, size_t>& blockOrder,
    const std::vector<std::string>& predecessors,
    const std::string& targetBlock)
{
    const auto targetOrderIt = blockOrder.find(targetBlock);

    if (targetOrderIt == blockOrder.end())
    {
        return false;
    }

    for (const std::string& predecessor : predecessors)
    {
        const auto predecessorOrderIt = blockOrder.find(predecessor);

        if (predecessorOrderIt == blockOrder.end() || predecessorOrderIt->second <= targetOrderIt->second)
        {
            continue;
        }

        const BasicBlock* block = FindBlockById(blocks, predecessor);

        if (block != nullptr && std::find(block->Successors.begin(), block->Successors.end(), targetBlock) != block->Successors.end())
        {
            return true;
        }
    }

    return false;
}

struct StateEvalValue
{
    bool Known = false;
    uint64_t Value = 0;
};

struct EvaluatedStateTransition
{
    std::string StateValue;
    std::string Condition;
    std::string Evidence;
    bool Conditional = false;
    double Confidence = 0.0;
};

std::string BuildStateEvalTargetName(const std::string& operand)
{
    if (operand.find('[') != std::string::npos)
    {
        return StripPointerDecorators(operand);
    }

    return NormalizeStateVariableExpression(operand);
}

bool TryGetStateEvalValue(
    const std::string& operand,
    const std::unordered_map<std::string, uint64_t>& values,
    uint64_t& value)
{
    int64_t immediate = 0;

    if (TryParseSignedValue(StripPointerDecorators(operand), immediate))
    {
        value = static_cast<uint64_t>(immediate);
        return true;
    }

    const std::string key = BuildStateEvalTargetName(operand);
    const auto it = values.find(key);

    if (it == values.end())
    {
        return false;
    }

    value = it->second;
    return true;
}

bool TryEvaluateLeaStateValue(
    const std::string& operand,
    const std::unordered_map<std::string, uint64_t>& values,
    uint64_t& value)
{
    std::string expression;

    if (!TryExtractBracketExpression(operand, expression))
    {
        return false;
    }

    MemoryAccess access;
    ParseMemoryExpression(expression, access);

    uint64_t result = 0;

    if (!access.BaseRegister.empty())
    {
        const auto baseIt = values.find(access.BaseRegister);

        if (baseIt == values.end())
        {
            return false;
        }

        result += baseIt->second;
    }

    if (!access.IndexRegister.empty())
    {
        const auto indexIt = values.find(access.IndexRegister);

        if (indexIt == values.end())
        {
            return false;
        }

        result += indexIt->second * static_cast<uint64_t>((std::max)(access.Scale, 1U));
    }

    if (!access.Displacement.empty())
    {
        int64_t displacement = 0;

        if (!TryParseSignedValue(access.Displacement, displacement))
        {
            return false;
        }

        result += static_cast<uint64_t>(displacement);
    }

    value = result;
    return true;
}

StateEvalValue EvaluateStateAssignment(
    const DisassembledInstruction& instruction,
    const std::vector<std::string>& operands,
    const std::unordered_map<std::string, uint64_t>& values)
{
    StateEvalValue result;
    const std::string mnemonic = ToLowerAscii(TrimCopy(instruction.Mnemonic));

    if (operands.empty())
    {
        return result;
    }

    uint64_t left = 0;
    uint64_t right = 0;

    if (mnemonic == "mov" || mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd")
    {
        if (operands.size() >= 2 && TryGetStateEvalValue(operands[1], values, result.Value))
        {
            result.Known = true;
        }

        return result;
    }

    if (mnemonic == "lea")
    {
        if (operands.size() >= 2 && TryEvaluateLeaStateValue(operands[1], values, result.Value))
        {
            result.Known = true;
        }

        return result;
    }

    if (mnemonic == "xor" && operands.size() >= 2)
    {
        const std::string leftOperand = StripPointerDecorators(operands[0]);
        const std::string rightOperand = StripPointerDecorators(operands[1]);

        if (!leftOperand.empty() && leftOperand == rightOperand && IsWholeRegisterZeroIdiomOperand(operands[0]))
        {
            result.Known = true;
            result.Value = 0;
            return result;
        }
    }

    if (operands.size() >= 2
        && TryGetStateEvalValue(operands[0], values, left)
        && TryGetStateEvalValue(operands[1], values, right))
    {
        if (mnemonic == "add")
        {
            result.Value = left + right;
            result.Known = true;
        }
        else if (mnemonic == "sub")
        {
            result.Value = left - right;
            result.Known = true;
        }
        else if (mnemonic == "xor")
        {
            result.Value = left ^ right;
            result.Known = true;
        }
        else if (mnemonic == "or")
        {
            result.Value = left | right;
            result.Known = true;
        }
        else if (mnemonic == "and")
        {
            result.Value = left & right;
            result.Known = true;
        }
        else if (mnemonic == "shl" && right < 64)
        {
            result.Value = left << right;
            result.Known = true;
        }
        else if (mnemonic == "shr" && right < 64)
        {
            result.Value = left >> right;
            result.Known = true;
        }
        else if (mnemonic == "sar" && right < 64)
        {
            result.Value = static_cast<uint64_t>(static_cast<int64_t>(left) >> right);
            result.Known = true;
        }
    }

    if (operands.size() == 1 && TryGetStateEvalValue(operands[0], values, left))
    {
        if (mnemonic == "inc")
        {
            result.Value = left + 1ULL;
            result.Known = true;
        }
        else if (mnemonic == "dec")
        {
            result.Value = left - 1ULL;
            result.Known = true;
        }
        else if (mnemonic == "not")
        {
            result.Value = ~left;
            result.Known = true;
        }
        else if (mnemonic == "neg")
        {
            result.Value = static_cast<uint64_t>(-static_cast<int64_t>(left));
            result.Known = true;
        }
    }

    return result;
}

std::vector<EvaluatedStateTransition> EvaluateStateTransitionsInBlock(
    const BasicBlock& block,
    const std::vector<DisassembledInstruction>& instructions,
    const std::string& stateVariable)
{
    std::unordered_map<std::string, uint64_t> values;
    std::vector<EvaluatedStateTransition> pendingConditionalTransitions;
    ConditionalOperandPattern lastCondition;
    bool finalStateKnown = false;
    uint64_t finalStateValue = 0;

    for (const DisassembledInstruction* instruction : GetBlockInstructions(block, instructions))
    {
        if (instruction == nullptr)
        {
            continue;
        }

        const std::vector<std::string> operands = SplitOperands(instruction->OperandText);
        const std::string mnemonic = ToLowerAscii(TrimCopy(instruction->Mnemonic));

        if ((mnemonic == "cmp" || mnemonic == "test") && operands.size() >= 2)
        {
            lastCondition.Kind = mnemonic;
            lastCondition.Left = FormatConditionOperand(operands[0]);
            lastCondition.Right = FormatConditionOperand(operands[1]);
            lastCondition.RawLeftKey = StripPointerDecorators(operands[0]);
            lastCondition.RawRightKey = StripPointerDecorators(operands[1]);
            lastCondition.Valid = true;
        }
        else if (InstructionWritesFlags(*instruction) && !IsConditionalMoveMnemonic(mnemonic))
        {
            lastCondition.Valid = false;
        }

        if (instruction->IsCall)
        {
            values.clear();
            pendingConditionalTransitions.clear();
            finalStateKnown = false;
            lastCondition.Valid = false;
            continue;
        }

        if (!InstructionWritesDestinationOperand(*instruction, operands))
        {
            continue;
        }

        const std::string destination = BuildStateEvalTargetName(operands[0]);
        const bool writesState = OperandMatchesObfuscationVariable(destination, stateVariable);

        if (destination.empty())
        {
            continue;
        }

        if (IsConditionalMoveMnemonic(mnemonic))
        {
            uint64_t selectedValue = 0;
            const auto currentIt = values.find(destination);
            const std::string condition = BuildConditionExpressionForSelect(lastCondition, CmovConditionSuffixToBranch(mnemonic));

            if (writesState
                && operands.size() >= 2
                && currentIt != values.end()
                && TryGetStateEvalValue(operands[1], values, selectedValue)
                && !condition.empty())
            {
                EvaluatedStateTransition selected;
                selected.StateValue = FormatStateValue(selectedValue);
                selected.Condition = condition;
                selected.Evidence = HexU64(instruction->Address) + " selects state " + selected.StateValue;
                selected.Conditional = true;
                selected.Confidence = 0.82;

                EvaluatedStateTransition retained;
                retained.StateValue = FormatStateValue(currentIt->second);
                retained.Condition = "!(" + condition + ")";
                retained.Evidence = HexU64(instruction->Address) + " retains state " + retained.StateValue;
                retained.Conditional = true;
                retained.Confidence = 0.78;

                pendingConditionalTransitions.clear();
                pendingConditionalTransitions.push_back(std::move(selected));
                pendingConditionalTransitions.push_back(std::move(retained));
                finalStateKnown = false;
                values.erase(destination);
                continue;
            }

            values.erase(destination);

            if (writesState)
            {
                pendingConditionalTransitions.clear();
                finalStateKnown = false;
            }

            continue;
        }

        const StateEvalValue value = EvaluateStateAssignment(*instruction, operands, values);

        if (value.Known)
        {
            values[destination] = value.Value;
        }
        else
        {
            values.erase(destination);
        }

        if (writesState)
        {
            pendingConditionalTransitions.clear();
            finalStateKnown = value.Known;
            finalStateValue = value.Value;
        }
    }

    if (!pendingConditionalTransitions.empty())
    {
        return pendingConditionalTransitions;
    }

    if (finalStateKnown)
    {
        EvaluatedStateTransition transition;
        transition.StateValue = FormatStateValue(finalStateValue);
        transition.Evidence = block.Id + " evaluates state " + transition.StateValue;
        transition.Conditional = false;
        transition.Confidence = 0.82;
        return { transition };
    }

    return {};
}

struct OpaqueBranchProof
{
    bool Proven = false;
    bool BranchTaken = false;
    uint64_t Site = 0;
    std::string Predicate;
    std::string Evidence;
};

bool TryEvaluateCompareBranch(
    const std::string& branchMnemonic,
    int64_t signedLeft,
    int64_t signedRight,
    uint64_t unsignedLeft,
    uint64_t unsignedRight,
    bool& branchTaken)
{
    const std::string branch = NormalizeObfuscationBranchMnemonic(branchMnemonic);

    if (branch == "je")
    {
        branchTaken = unsignedLeft == unsignedRight;
        return true;
    }

    if (branch == "jne")
    {
        branchTaken = unsignedLeft != unsignedRight;
        return true;
    }

    if (branch == "ja")
    {
        branchTaken = unsignedLeft > unsignedRight;
        return true;
    }

    if (branch == "jae")
    {
        branchTaken = unsignedLeft >= unsignedRight;
        return true;
    }

    if (branch == "jb")
    {
        branchTaken = unsignedLeft < unsignedRight;
        return true;
    }

    if (branch == "jbe")
    {
        branchTaken = unsignedLeft <= unsignedRight;
        return true;
    }

    if (branch == "jg")
    {
        branchTaken = signedLeft > signedRight;
        return true;
    }

    if (branch == "jge")
    {
        branchTaken = signedLeft >= signedRight;
        return true;
    }

    if (branch == "jl")
    {
        branchTaken = signedLeft < signedRight;
        return true;
    }

    if (branch == "jle")
    {
        branchTaken = signedLeft <= signedRight;
        return true;
    }

    return false;
}

bool TryBuildOpaqueBranchProof(
    const DisassembledInstruction& compareInstruction,
    const DisassembledInstruction& branchInstruction,
    OpaqueBranchProof& proof)
{
    const std::vector<std::string> operands = SplitOperands(compareInstruction.OperandText);

    if (operands.size() < 2)
    {
        return false;
    }

    const std::string mnemonic = ToLowerAscii(TrimCopy(compareInstruction.Mnemonic));
    const std::string left = StripPointerDecorators(operands[0]);
    const std::string right = StripPointerDecorators(operands[1]);
    bool branchTaken = false;

    if (mnemonic == "cmp")
    {
        int64_t signedLeft = 0;
        int64_t signedRight = 0;
        bool evaluated = false;

        if (left.find('[') == std::string::npos
            && right.find('[') == std::string::npos
            && !left.empty()
            && left == right)
        {
            evaluated = true;
            proof.Evidence = HexU64(compareInstruction.Address) + " compares identical operands";
        }
        else if (TryParseSignedValue(left, signedLeft) && TryParseSignedValue(right, signedRight))
        {
            evaluated = true;
            proof.Evidence = HexU64(compareInstruction.Address) + " compares constants";
        }

        if (!evaluated
            || !TryEvaluateCompareBranch(
                branchInstruction.Mnemonic,
                signedLeft,
                signedRight,
                static_cast<uint64_t>(signedLeft),
                static_cast<uint64_t>(signedRight),
                branchTaken))
        {
            return false;
        }

        proof.Proven = true;
        proof.BranchTaken = branchTaken;
        proof.Site = branchInstruction.Address;
        proof.Predicate = FormatConditionOperand(operands[0]) + " cmp " + FormatConditionOperand(operands[1]);
        return true;
    }

    if (mnemonic == "test")
    {
        int64_t signedLeft = 0;
        int64_t signedRight = 0;

        if ((!TryParseSignedValue(left, signedLeft) || signedLeft != 0)
            && (!TryParseSignedValue(right, signedRight) || signedRight != 0))
        {
            return false;
        }

        if (!TryEvaluateCompareBranch(branchInstruction.Mnemonic, 0, 0, 0, 0, branchTaken))
        {
            return false;
        }

        proof.Proven = true;
        proof.BranchTaken = branchTaken;
        proof.Site = branchInstruction.Address;
        proof.Predicate = FormatConditionOperand(operands[0]) + " test " + FormatConditionOperand(operands[1]);
        proof.Evidence = HexU64(compareInstruction.Address) + " tests against zero";
        return true;
    }

    return false;
}

std::vector<OpaquePredicateFact> AnalyzeOpaquePredicateFacts(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<NormalizedCondition>& conditions)
{
    std::vector<OpaquePredicateFact> facts;
    std::set<std::string> seen;

    for (const BasicBlock& block : blocks)
    {
        const NormalizedCondition* condition = FindConditionForBlock(conditions, block.Id);

        if (condition == nullptr)
        {
            continue;
        }

        const DisassembledInstruction* pendingCompare = nullptr;

        for (const DisassembledInstruction* instruction : GetBlockInstructions(block, instructions))
        {
            if (instruction == nullptr)
            {
                continue;
            }

            const std::string mnemonic = ToLowerAscii(TrimCopy(instruction->Mnemonic));

            if (mnemonic == "cmp" || mnemonic == "test")
            {
                pendingCompare = instruction;
                continue;
            }

            if (instruction->IsConditionalBranch)
            {
                if (pendingCompare == nullptr || instruction->Address != condition->Site)
                {
                    continue;
                }

                OpaqueBranchProof proof;

                if (!TryBuildOpaqueBranchProof(*pendingCompare, *instruction, proof))
                {
                    continue;
                }

                OpaquePredicateFact fact;
                fact.Site = proof.Site;
                fact.BlockId = block.Id;
                fact.Predicate = condition->Expression.empty() ? proof.Predicate : condition->Expression;
                fact.ConstantResult = proof.BranchTaken ? "true" : "false";
                fact.LiveTargetBlock = proof.BranchTaken ? condition->TrueTargetBlock : condition->FalseTargetBlock;
                fact.DeadTargetBlock = proof.BranchTaken ? condition->FalseTargetBlock : condition->TrueTargetBlock;
                fact.Evidence = proof.Evidence;
                fact.Confidence = 0.90;

                const std::string key = fact.BlockId + "\n" + fact.LiveTargetBlock + "\n" + fact.DeadTargetBlock;

                if (!fact.LiveTargetBlock.empty() && !fact.DeadTargetBlock.empty() && seen.insert(key).second)
                {
                    facts.push_back(std::move(fact));
                }

                continue;
            }

            if (InstructionWritesFlags(*instruction))
            {
                pendingCompare = nullptr;
            }
        }
    }

    return facts;
}

std::vector<RecoveredControlFlowEdge> RecoverObfuscationEdges(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<std::string>& predecessors,
    const std::set<std::string>& dispatcherBlocks,
    const std::string& stateVariable,
    const std::unordered_map<std::string, ObfuscationStateTarget>& stateTargets)
{
    std::vector<RecoveredControlFlowEdge> edges;
    std::set<std::string> seen;

    for (const std::string& predecessor : predecessors)
    {
        if (dispatcherBlocks.find(predecessor) != dispatcherBlocks.end())
        {
            continue;
        }

        const BasicBlock* predecessorBlock = FindBlockById(blocks, predecessor);

        if (predecessorBlock == nullptr)
        {
            continue;
        }

        const std::vector<EvaluatedStateTransition> transitions = EvaluateStateTransitionsInBlock(*predecessorBlock, instructions, stateVariable);

        for (const EvaluatedStateTransition& transition : transitions)
        {
            if (transition.StateValue.empty())
            {
                continue;
            }

            const auto targetIt = stateTargets.find(transition.StateValue);

            if (targetIt == stateTargets.end() || targetIt->second.TargetBlock.empty())
            {
                continue;
            }

            const std::string seenKey = predecessor
                + "\n"
                + targetIt->second.TargetBlock
                + "\n"
                + transition.StateValue
                + "\n"
                + transition.Condition;

            if (!seen.insert(seenKey).second)
            {
                continue;
            }

            RecoveredControlFlowEdge edge;
            edge.SourceBlock = predecessor;
            edge.TargetBlock = targetIt->second.TargetBlock;
            edge.Condition = transition.Condition.empty() ? targetIt->second.Condition : transition.Condition;
            edge.StateValue = transition.StateValue;
            edge.Evidence = "state "
                + stateVariable
                + "="
                + transition.StateValue
                + "; "
                + transition.Evidence
                + "; "
                + targetIt->second.Evidence;
            edge.Conditional = transition.Conditional;
            edge.Confidence = Clamp01(0.64 + (transition.Confidence * 0.18) + (targetIt->second.Confidence * 0.18));
            edges.push_back(std::move(edge));
        }
    }

    return edges;
}

ObfuscationFacts AnalyzeObfuscationFacts(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<BasicBlock>& blocks,
    const std::vector<IrValue>& irValues,
    const std::vector<BlockValueState>& blockValueStates,
    const std::vector<NormalizedCondition>& conditions,
    const std::vector<SwitchInfo>& switches)
{
    (void)blockValueStates;
    ObfuscationFacts facts;
    facts.OpaquePredicates = AnalyzeOpaquePredicateFacts(instructions, blocks, conditions);

    if (blocks.size() < 5)
    {
        for (const OpaquePredicateFact& predicate : facts.OpaquePredicates)
        {
            facts.Confidence = (std::max)(facts.Confidence, predicate.Confidence);
        }

        return facts;
    }

    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);
    const std::unordered_map<std::string, std::set<std::string>> dominators = BuildDominatorSets(blocks);
    const std::unordered_map<std::string, size_t> blockOrder = BuildBlockOrder(blocks);
    double bestConfidence = 0.0;

    for (const BasicBlock& header : blocks)
    {
        const auto predecessorIt = predecessors.find(header.Id);

        if (predecessorIt == predecessors.end() || predecessorIt->second.size() < 3)
        {
            continue;
        }

        std::vector<std::string> stateVariables = CollectStateCompareVariables(header, instructions);
        AppendUniqueStrings(stateVariables, CollectStateSwitchVariables(blocks, switches, header));

        if (stateVariables.empty())
        {
            continue;
        }

        for (const std::string& stateVariable : stateVariables)
        {
            std::set<std::string> dispatcherBlockSet;
            std::unordered_map<std::string, ObfuscationStateTarget> stateTargets = BuildStateTargetMapForDispatcher(
                instructions,
                blocks,
                conditions,
                header.Id,
                stateVariable,
                dispatcherBlockSet);
            const bool hasSwitchDispatcher = MergeSwitchStateTargetMapForDispatcher(
                blocks,
                switches,
                header,
                stateVariable,
                dispatcherBlockSet,
                stateTargets);

            if (stateTargets.size() < 2)
            {
                facts.Notes.push_back("possible dispatcher " + header.Id + " did not expose enough state targets");
                continue;
            }

            const uint32_t writeBlocks = CountAssignmentsToTargetInDistinctBlocks(irValues, stateVariable);
            const bool hasBackEdge = HasBackEdgeToBlock(blocks, blockOrder, predecessorIt->second, header.Id);
            const double dominatorCoverage = ComputeDominatorCoverage(dominators, blocks, header.Id);
            std::vector<RecoveredControlFlowEdge> recoveredEdges = RecoverObfuscationEdges(
                instructions,
                blocks,
                predecessorIt->second,
                dispatcherBlockSet,
                stateVariable,
                stateTargets);

            if (writeBlocks < 3 || recoveredEdges.size() < 2)
            {
                facts.Notes.push_back("possible dispatcher " + header.Id + " lacked enough state writes or recovered edges");
                continue;
            }

            double confidence = 0.0;
            confidence += predecessorIt->second.size() >= 3 ? 0.20 : 0.0;
            confidence += !stateTargets.empty() ? 0.20 : 0.0;
            confidence += dominatorCoverage >= 0.50 ? 0.15 : 0.0;
            confidence += writeBlocks >= 3 ? 0.15 : 0.0;
            confidence += hasBackEdge ? 0.10 : 0.0;
            confidence += recoveredEdges.size() >= 2 ? 0.10 : 0.0;
            confidence += dispatcherBlockSet.size() >= 2 ? 0.05 : 0.0;
            confidence += hasSwitchDispatcher ? 0.10 : 0.0;
            confidence = Clamp01(confidence);

            if (confidence < 0.55)
            {
                facts.Notes.push_back("low-confidence flattening candidate at " + header.Id);
                continue;
            }

            ObfuscationDispatcher dispatcher;
            dispatcher.HeaderBlock = header.Id;
            dispatcher.Kind = hasSwitchDispatcher
                ? "control_flow_flattening_switch_dispatcher"
                : "control_flow_flattening_dispatcher";
            dispatcher.StateVariable = stateVariable;
            dispatcher.DispatcherBlocks.assign(dispatcherBlockSet.begin(), dispatcherBlockSet.end());
            dispatcher.OriginalBlockCandidates = predecessorIt->second;
            dispatcher.RecoveredEdges = std::move(recoveredEdges);
            dispatcher.Evidence =
                "fan_in="
                + std::to_string(predecessorIt->second.size())
                + "; state_targets="
                + std::to_string(stateTargets.size())
                + "; write_blocks="
                + std::to_string(writeBlocks)
                + "; dominated_ratio="
                + std::to_string(dominatorCoverage)
                + (hasSwitchDispatcher ? "; switch_dispatcher" : "")
                + (hasBackEdge ? "; back_edge" : "");
            dispatcher.Confidence = confidence;

            ObfuscationStateVariable variable;
            variable.Name = stateVariable;
            variable.Storage = IsRegisterName(stateVariable) ? "register" : "local_or_memory";
            variable.FirstSite = FindFirstAssignmentSite(irValues, stateVariable);
            variable.ReadCount = CountReadsOfTargetInBlocks(blocks, instructions, dispatcherBlockSet, stateVariable);
            variable.WriteCount = writeBlocks;
            variable.Confidence = Clamp01(confidence - 0.05);

            if (std::find_if(
                    facts.StateVariables.begin(),
                    facts.StateVariables.end(),
                    [&variable](const ObfuscationStateVariable& existing)
                    {
                        return existing.Name == variable.Name;
                    })
                == facts.StateVariables.end())
            {
                facts.StateVariables.push_back(std::move(variable));
            }

            bestConfidence = (std::max)(bestConfidence, dispatcher.Confidence);
            facts.Dispatchers.push_back(std::move(dispatcher));
        }
    }

    if (!switches.empty() && facts.Dispatchers.empty())
    {
        facts.Notes.push_back("switch-like control flow exists but no conservative flattening dispatcher was proven");
    }

    for (const OpaquePredicateFact& predicate : facts.OpaquePredicates)
    {
        bestConfidence = (std::max)(bestConfidence, predicate.Confidence);
    }

    facts.Confidence = bestConfidence;
    return facts;
}

bool SplitLastBinaryExpression(
    const std::string& expression,
    const std::string& op,
    std::string& left,
    std::string& right)
{
    const std::string delimiter = " " + op + " ";
    const size_t position = expression.rfind(delimiter);

    if (position == std::string::npos)
    {
        return false;
    }

    left = TrimCopy(expression.substr(0, position));
    right = TrimCopy(expression.substr(position + delimiter.size()));
    return !left.empty() && !right.empty();
}

bool TryParseExpressionImmediate(const std::string& expression, int64_t& value)
{
    return TryParseSignedValue(StripPointerDecorators(expression), value);
}

bool SimplifySubstitutionExpression(
    const std::string& expression,
    std::string& simplified,
    std::string& pattern)
{
    std::string left;
    std::string right;
    int64_t immediate = 0;

    if (SplitLastBinaryExpression(expression, "+", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == 0)
    {
        simplified = left;
        pattern = "identity_add_zero";
        return true;
    }

    if (SplitLastBinaryExpression(expression, "-", left, right)
        && TryParseExpressionImmediate(right, immediate))
    {
        if (immediate == 0)
        {
            simplified = left;
            pattern = "identity_sub_zero";
            return true;
        }

        if (immediate < 0)
        {
            simplified = left + " + " + FormatStateValue(static_cast<uint64_t>(-immediate));
            pattern = "subtract_negative";
            return true;
        }
    }

    if (SplitLastBinaryExpression(expression, "^", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == 0)
    {
        simplified = left;
        pattern = "identity_xor_zero";
        return true;
    }

    if (SplitLastBinaryExpression(expression, "|", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == 0)
    {
        simplified = left;
        pattern = "identity_or_zero";
        return true;
    }

    if (SplitLastBinaryExpression(expression, "&", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == -1)
    {
        simplified = left;
        pattern = "identity_and_all_ones";
        return true;
    }

    if (SplitLastBinaryExpression(expression, "*", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == 1)
    {
        simplified = left;
        pattern = "identity_mul_one";
        return true;
    }

    if (SplitLastBinaryExpression(expression, "<<", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == 0)
    {
        simplified = left;
        pattern = "identity_shl_zero";
        return true;
    }

    if (SplitLastBinaryExpression(expression, ">>", left, right)
        && TryParseExpressionImmediate(right, immediate)
        && immediate == 0)
    {
        simplified = left;
        pattern = "identity_shr_zero";
        return true;
    }

    if (SplitLastBinaryExpression(expression, "^", left, right))
    {
        std::string base;
        std::string innerRight;
        int64_t outerImmediate = 0;
        int64_t innerImmediate = 0;

        if (SplitLastBinaryExpression(left, "^", base, innerRight)
            && TryParseExpressionImmediate(right, outerImmediate)
            && TryParseExpressionImmediate(innerRight, innerImmediate)
            && outerImmediate == innerImmediate)
        {
            simplified = base;
            pattern = "xor_same_constant_twice";
            return true;
        }
    }

    if (SplitLastBinaryExpression(expression, "-", left, right))
    {
        std::string base;
        std::string innerRight;
        int64_t outerImmediate = 0;
        int64_t innerImmediate = 0;

        if (SplitLastBinaryExpression(left, "+", base, innerRight)
            && TryParseExpressionImmediate(right, outerImmediate)
            && TryParseExpressionImmediate(innerRight, innerImmediate)
            && outerImmediate == innerImmediate)
        {
            simplified = base;
            pattern = "add_then_sub_same_constant";
            return true;
        }
    }

    if (SplitLastBinaryExpression(expression, "+", left, right))
    {
        std::string base;
        std::string innerRight;
        int64_t outerImmediate = 0;
        int64_t innerImmediate = 0;

        if (SplitLastBinaryExpression(left, "-", base, innerRight)
            && TryParseExpressionImmediate(right, outerImmediate)
            && TryParseExpressionImmediate(innerRight, innerImmediate)
            && outerImmediate == innerImmediate)
        {
            simplified = base;
            pattern = "sub_then_add_same_constant";
            return true;
        }
    }

    return false;
}

std::vector<SubstitutionIdiomFact> CanonicalizeSubstitutionIdioms(std::vector<IrValue>& values)
{
    std::vector<SubstitutionIdiomFact> facts;

    for (IrValue& value : values)
    {
        std::string current = value.Canonical.empty() ? value.Expression : value.Canonical;
        std::string simplified;
        std::string pattern;

        for (size_t depth = 0; depth < 4; ++depth)
        {
            if (!SimplifySubstitutionExpression(current, simplified, pattern) || simplified == current)
            {
                break;
            }

            SubstitutionIdiomFact fact;
            fact.Site = value.DefSite;
            fact.BlockId = value.BlockId;
            fact.OriginalExpression = current;
            fact.SimplifiedExpression = simplified;
            fact.Pattern = pattern;
            fact.Evidence = "local integer identity in " + value.Id;
            fact.Confidence = 0.88;
            facts.push_back(std::move(fact));
            current = simplified;
        }

        value.Canonical = current;
        value.IsConstant = IsConstantExpression(value.Canonical);
        value.IsCopy = value.Target == value.Canonical;

        if (value.IsConstant)
        {
            value.Kind = "constant";
        }
    }

    return facts;
}

void AppendSubstitutionIdioms(ObfuscationFacts& obfuscation, const std::vector<SubstitutionIdiomFact>& idioms)
{
    for (const SubstitutionIdiomFact& idiom : idioms)
    {
        obfuscation.SubstitutionIdioms.push_back(idiom);
        obfuscation.Confidence = (std::max)(obfuscation.Confidence, idiom.Confidence);
    }
}

constexpr double kSemanticControlFlowApplyConfidence = 0.75;

bool IsApplicableSemanticControlFlowEdge(const SemanticControlFlowEdge& edge)
{
    return edge.Confidence >= kSemanticControlFlowApplyConfidence
        && !edge.SourceBlock.empty()
        && !edge.TargetBlock.empty();
}

std::string BuildSemanticControlFlowEdgeKey(const SemanticControlFlowEdge& edge)
{
    return edge.SourceBlock
        + "\n"
        + edge.TargetBlock
        + "\n"
        + edge.Source
        + "\n"
        + edge.StateValue
        + "\n"
        + edge.Condition
        + "\n"
        + (edge.Dead ? "dead" : "live");
}

void AppendSemanticControlFlowEdge(
    SemanticControlFlowOverlay& overlay,
    std::set<std::string>& seen,
    SemanticControlFlowEdge edge)
{
    if (edge.SourceBlock.empty() || edge.TargetBlock.empty())
    {
        return;
    }

    const std::string key = BuildSemanticControlFlowEdgeKey(edge);

    if (!seen.insert(key).second)
    {
        return;
    }

    edge.Confidence = Clamp01(edge.Confidence);
    overlay.Confidence = (std::max)(overlay.Confidence, edge.Confidence);
    overlay.Edges.push_back(std::move(edge));
}

SemanticControlFlowOverlay BuildSemanticControlFlowOverlay(const ObfuscationFacts& obfuscation)
{
    SemanticControlFlowOverlay overlay;
    std::set<std::string> seen;
    bool hasApplicableEdge = false;

    for (const ObfuscationDispatcher& dispatcher : obfuscation.Dispatchers)
    {
        for (const RecoveredControlFlowEdge& recoveredEdge : dispatcher.RecoveredEdges)
        {
            SemanticControlFlowEdge edge;
            edge.SourceBlock = recoveredEdge.SourceBlock;
            edge.TargetBlock = recoveredEdge.TargetBlock;
            edge.Condition = recoveredEdge.Condition;
            edge.StateValue = recoveredEdge.StateValue;
            edge.Evidence = recoveredEdge.Evidence;
            edge.Source = "obfuscation.recovered_edge";
            edge.Conditional = recoveredEdge.Conditional;
            edge.Dead = false;
            edge.Confidence = Clamp01((recoveredEdge.Confidence * 0.70) + (dispatcher.Confidence * 0.30));
            hasApplicableEdge = hasApplicableEdge || IsApplicableSemanticControlFlowEdge(edge);
            AppendSemanticControlFlowEdge(overlay, seen, std::move(edge));
        }
    }

    for (const OpaquePredicateFact& predicate : obfuscation.OpaquePredicates)
    {
        const std::string condition = predicate.Predicate.empty()
            ? ("constant predicate " + predicate.ConstantResult)
            : (predicate.Predicate + " == " + predicate.ConstantResult);

        if (!predicate.LiveTargetBlock.empty())
        {
            SemanticControlFlowEdge edge;
            edge.SourceBlock = predicate.BlockId;
            edge.TargetBlock = predicate.LiveTargetBlock;
            edge.Condition = condition;
            edge.Evidence = predicate.Evidence;
            edge.Source = "obfuscation.opaque_predicate.live";
            edge.Conditional = true;
            edge.Dead = false;
            edge.Confidence = predicate.Confidence;
            hasApplicableEdge = hasApplicableEdge || IsApplicableSemanticControlFlowEdge(edge);
            AppendSemanticControlFlowEdge(overlay, seen, std::move(edge));
        }

        if (!predicate.DeadTargetBlock.empty())
        {
            SemanticControlFlowEdge edge;
            edge.SourceBlock = predicate.BlockId;
            edge.TargetBlock = predicate.DeadTargetBlock;
            edge.Condition = condition;
            edge.Evidence = predicate.Evidence;
            edge.Source = "obfuscation.opaque_predicate.dead";
            edge.Conditional = true;
            edge.Dead = true;
            edge.Confidence = predicate.Confidence;
            hasApplicableEdge = hasApplicableEdge || IsApplicableSemanticControlFlowEdge(edge);
            AppendSemanticControlFlowEdge(overlay, seen, std::move(edge));
        }
    }

    if (hasApplicableEdge)
    {
        overlay.Notes.push_back("high-confidence semantic edges are used for structural recovery; raw CFG remains authoritative elsewhere");
    }

    return overlay;
}

void AppendUniqueString(std::vector<std::string>& values, const std::string& value)
{
    if (!value.empty() && std::find(values.begin(), values.end(), value) == values.end())
    {
        values.push_back(value);
    }
}

std::vector<BasicBlock> BuildBlocksWithSemanticControlFlow(
    const std::vector<BasicBlock>& blocks,
    const SemanticControlFlowOverlay& overlay)
{
    std::vector<BasicBlock> semanticBlocks = blocks;
    std::set<std::string> knownBlocks;
    std::unordered_map<std::string, std::vector<std::string>> liveTargetsBySource;
    std::unordered_map<std::string, std::set<std::string>> deadTargetsBySource;

    for (const BasicBlock& block : blocks)
    {
        knownBlocks.insert(block.Id);
    }

    for (const SemanticControlFlowEdge& edge : overlay.Edges)
    {
        if (!IsApplicableSemanticControlFlowEdge(edge)
            || knownBlocks.find(edge.SourceBlock) == knownBlocks.end()
            || knownBlocks.find(edge.TargetBlock) == knownBlocks.end())
        {
            continue;
        }

        if (edge.Dead)
        {
            deadTargetsBySource[edge.SourceBlock].insert(edge.TargetBlock);
        }
        else
        {
            AppendUniqueString(liveTargetsBySource[edge.SourceBlock], edge.TargetBlock);
        }
    }

    if (liveTargetsBySource.empty() && deadTargetsBySource.empty())
    {
        return semanticBlocks;
    }

    for (BasicBlock& block : semanticBlocks)
    {
        const auto liveIt = liveTargetsBySource.find(block.Id);

        if (liveIt != liveTargetsBySource.end() && !liveIt->second.empty())
        {
            block.Successors.clear();
            AppendUniqueStrings(block.Successors, liveIt->second);
            continue;
        }

        const auto deadIt = deadTargetsBySource.find(block.Id);

        if (deadIt == deadTargetsBySource.end() || deadIt->second.empty())
        {
            continue;
        }

        block.Successors.erase(
            std::remove_if(
                block.Successors.begin(),
                block.Successors.end(),
                [&deadIt](const std::string& successor)
                {
                    return deadIt->second.find(successor) != deadIt->second.end();
                }),
            block.Successors.end());
    }

    return semanticBlocks;
}

bool TryExtractInductionStep(
    const DisassembledInstruction& instruction,
    std::string& variable,
    int64_t& step)
{
    const std::vector<std::string> operands = SplitOperands(instruction.OperandText);
    const std::string mnemonic = ToLowerAscii(instruction.Mnemonic);

    if ((mnemonic == "inc" || mnemonic == "dec") && operands.size() >= 1)
    {
        const std::string reg = NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0]));

        if (reg.empty())
        {
            return false;
        }

        variable = reg;
        step = mnemonic == "inc" ? 1 : -1;
        return true;
    }

    if ((mnemonic == "add" || mnemonic == "sub") && operands.size() >= 2)
    {
        const std::string reg = NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0]));
        int64_t immediate = 0;

        if (reg.empty() || !TryParseSignedValue(StripPointerDecorators(operands[1]), immediate))
        {
            return false;
        }

        variable = reg;
        step = mnemonic == "add" ? immediate : -immediate;
        return step != 0;
    }

    return false;
}

bool TryExtractInitialValue(
    const std::vector<DisassembledInstruction>& instructions,
    uint64_t headerStart,
    const std::string& variable,
    std::string& initialValue)
{
    size_t scanned = 0;

    for (auto it = instructions.rbegin(); it != instructions.rend(); ++it)
    {
        const DisassembledInstruction& instruction = *it;

        if (instruction.Address >= headerStart)
        {
            continue;
        }

        if (++scanned > 24U)
        {
            break;
        }

        const std::vector<std::string> operands = SplitOperands(instruction.OperandText);

        if (instruction.Mnemonic == "mov"
            && operands.size() >= 2
            && NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0])) == variable)
        {
            initialValue = StripPointerDecorators(operands[1]);
            return !initialValue.empty();
        }

        if (instruction.Mnemonic == "xor"
            && operands.size() >= 2
            && NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[0])) == variable
            && NormalizeRegisterAlias(FirstRegisterTokenRaw(operands[1])) == variable)
        {
            initialValue = "0";
            return true;
        }
    }

    return false;
}

bool ConditionSideReferencesVariable(const std::string& expression, const std::string& variable)
{
    if (expression.find(variable) != std::string::npos)
    {
        return true;
    }

    const std::vector<std::string> registers = ExtractOperandRegisterTokens(expression);
    return std::find(registers.begin(), registers.end(), variable) != registers.end();
}

bool TryExtractLoopBound(
    const std::string& condition,
    const std::string& variable,
    std::string& bound)
{
    static const std::array<const char*, 6> operators = { "<=", ">=", "!=", "==", "<", ">" };

    for (const char* op : operators)
    {
        const size_t position = condition.find(op);

        if (position == std::string::npos)
        {
            continue;
        }

        const std::string left = TrimCopy(condition.substr(0, position));
        const std::string right = TrimCopy(condition.substr(position + std::strlen(op)));

        if (ConditionSideReferencesVariable(left, variable) && !right.empty())
        {
            bound = right;
            return true;
        }

        if (ConditionSideReferencesVariable(right, variable) && !left.empty())
        {
            bound = left;
            return true;
        }
    }

    return false;
}

void AnnotateLoopInduction(
    ControlFlowRegion& loop,
    const std::vector<BasicBlock>& blocks,
    const std::vector<DisassembledInstruction>& instructions)
{
    std::unordered_map<std::string, const BasicBlock*> blockById;
    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;

    for (const BasicBlock& block : blocks)
    {
        blockById[block.Id] = &block;
    }

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionByAddress[instruction.Address] = &instruction;
    }

    std::set<std::string> loopBlocks(loop.BodyBlocks.begin(), loop.BodyBlocks.end());
    loopBlocks.insert(loop.HeaderBlock);
    loopBlocks.insert(loop.LatchBlocks.begin(), loop.LatchBlocks.end());

    std::map<std::string, int64_t> stepsByVariable;

    for (const std::string& blockId : loopBlocks)
    {
        const auto blockIt = blockById.find(blockId);

        if (blockIt == blockById.end() || blockIt->second == nullptr)
        {
            continue;
        }

        for (const uint64_t address : blockIt->second->InstructionAddresses)
        {
            const auto instructionIt = instructionByAddress.find(address);

            if (instructionIt == instructionByAddress.end())
            {
                continue;
            }

            std::string variable;
            int64_t step = 0;

            if (TryExtractInductionStep(*instructionIt->second, variable, step))
            {
                stepsByVariable[variable] += step;
            }
        }
    }

    if (stepsByVariable.empty())
    {
        return;
    }

    std::string bestVariable;
    int64_t bestStep = 0;
    bool bestAppearsInCondition = false;

    for (const auto& entry : stepsByVariable)
    {
        const bool appearsInCondition = ConditionSideReferencesVariable(loop.Condition, entry.first);

        if (bestVariable.empty()
            || (appearsInCondition && !bestAppearsInCondition)
            || (appearsInCondition == bestAppearsInCondition && std::llabs(entry.second) > std::llabs(bestStep)))
        {
            bestVariable = entry.first;
            bestStep = entry.second;
            bestAppearsInCondition = appearsInCondition;
        }
    }

    if (bestVariable.empty() || bestStep == 0)
    {
        return;
    }

    loop.InductionVariable = bestVariable;
    loop.Step = bestStep > 0 ? ("+" + std::to_string(bestStep)) : std::to_string(bestStep);
    loop.Direction = bestStep > 0 ? "increasing" : "decreasing";

    const auto headerIt = blockById.find(loop.HeaderBlock);

    if (headerIt != blockById.end() && headerIt->second != nullptr)
    {
        TryExtractInitialValue(instructions, headerIt->second->StartAddress, bestVariable, loop.InitialValue);
    }

    TryExtractLoopBound(loop.Condition, bestVariable, loop.Bound);

    if (!loop.Evidence.empty())
    {
        loop.Evidence += "; ";
    }

    loop.Evidence += "induction=" + loop.InductionVariable + " step=" + loop.Step;

    if (!loop.Bound.empty())
    {
        loop.Evidence += " bound=" + loop.Bound;
    }

    loop.Confidence = Clamp01(loop.Confidence + 0.06);
}

std::vector<ControlFlowRegion> AnalyzeControlFlow(
    const std::vector<DisassembledInstruction>& instructions,
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
    const std::unordered_map<std::string, std::set<std::string>> postDominators = BuildPostDominatorSets(blocks);
    const std::unordered_map<std::string, std::vector<std::string>> predecessors = BuildBlockPredecessors(blocks);
    const std::unordered_map<std::string, size_t> blockOrder = BuildBlockOrder(blocks);

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
                loop.BodyBlocks = CollectNaturalLoopBody(successor, block.Id, predecessors, dominators);

                const NormalizedCondition* condition = FindConditionForBlock(conditions, successor);
                loop.Condition = condition != nullptr ? condition->Expression : std::string();
                loop.Evidence = block.Id + " -> " + successor + " back-edge";
                loop.Confidence = Clamp01(0.70 + (!loop.Condition.empty() ? 0.10 : 0.0) + (loop.BodyBlocks.size() > 2 ? 0.04 : 0.0));
                AnnotateLoopInduction(loop, blocks, instructions);
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
        const std::string joinBlock = FindNearestCommonPostDominator(block, postDominators, blockOrder);

        if (!joinBlock.empty())
        {
            for (const std::string& successor : block.Successors)
            {
                std::vector<std::string> pathBlocks = CollectBlocksUntilJoin(blocks, successor, joinBlock);
                branch.BodyBlocks.insert(branch.BodyBlocks.end(), pathBlocks.begin(), pathBlocks.end());
            }

            std::sort(branch.BodyBlocks.begin(), branch.BodyBlocks.end());
            branch.BodyBlocks.erase(std::unique(branch.BodyBlocks.begin(), branch.BodyBlocks.end()), branch.BodyBlocks.end());
            branch.ExitBlocks.push_back(joinBlock);
        }
        else
        {
            branch.BodyBlocks = block.Successors;
            branch.ExitBlocks = block.Successors;
        }

        const NormalizedCondition* condition = FindConditionForBlock(conditions, block.Id);
        branch.Condition = condition != nullptr ? condition->Expression : std::string();
        branch.Evidence = "conditional block with " + std::to_string(block.Successors.size()) + " successors";

        if (!joinBlock.empty())
        {
            branch.Evidence += "; postdominator join " + joinBlock;
        }

        branch.Confidence = Clamp01(0.60 + (!branch.Condition.empty() ? 0.12 : 0.0) + (!joinBlock.empty() ? 0.10 : 0.0));
        regions.push_back(std::move(branch));
    }

    for (const SwitchInfo& switchInfo : switches)
    {
        ControlFlowRegion region;
        region.Kind = "switch_candidate";
        region.Evidence = switchInfo.Detail;
        region.Confidence = Clamp01(
            0.52
            + (switchInfo.CaseCount != 0 ? 0.18 : 0.0)
            + (!switchInfo.CaseTargets.empty() ? 0.12 : 0.0));

        for (const BasicBlock& block : blocks)
        {
            if (switchInfo.Site >= block.StartAddress && switchInfo.Site < block.EndAddress)
            {
                region.HeaderBlock = block.Id;
                region.BodyBlocks = block.Successors;
                break;
            }
        }

        for (const uint64_t target : switchInfo.CaseTargets)
        {
            const std::string targetBlock = FindBlockContainingAddress(blocks, target);

            if (!targetBlock.empty() && std::find(region.BodyBlocks.begin(), region.BodyBlocks.end(), targetBlock) == region.BodyBlocks.end())
            {
                region.BodyBlocks.push_back(targetBlock);
            }
        }

        if (switchInfo.DefaultTarget != 0)
        {
            const std::string targetBlock = FindBlockContainingAddress(blocks, switchInfo.DefaultTarget);

            if (!targetBlock.empty() && std::find(region.BodyBlocks.begin(), region.BodyBlocks.end(), targetBlock) == region.BodyBlocks.end())
            {
                region.BodyBlocks.push_back(targetBlock);
            }

            region.Evidence += "; default=" + HexU64(switchInfo.DefaultTarget);
        }

        if (switchInfo.RangeKnown)
        {
            region.Evidence += "; range=" + std::to_string(switchInfo.RangeMin) + ".." + std::to_string(switchInfo.RangeMax);
        }

        if (!switchInfo.CaseTargets.empty())
        {
            region.Evidence += "; recovered_targets=" + std::to_string(switchInfo.CaseTargets.size());
        }

        regions.push_back(std::move(region));
    }

    return regions;
}

bool IsTailJumpCandidate(
    const DisassembledInstruction& instruction,
    uint64_t entryAddress,
    const std::set<uint64_t>* instructionAddresses)
{
    if (!instruction.IsUnconditionalBranch
        || instruction.IsIndirect
        || !instruction.HasBranchTarget
        || instruction.BranchTarget == instruction.EndAddress)
    {
        return false;
    }

    if (instructionAddresses != nullptr
        && instructionAddresses->find(instruction.BranchTarget) != instructionAddresses->end())
    {
        return false;
    }

    const uint64_t upperBound = entryAddress > UINT64_MAX - 0x100000ULL
        ? UINT64_MAX
        : entryAddress + 0x100000ULL;

    return instruction.BranchTarget < entryAddress
        || instruction.BranchTarget > upperBound
        || instructionAddresses != nullptr;
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
    std::set<uint64_t> instructionAddresses;

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionAddresses.insert(instruction.Address);
    }

    for (const MemoryAccess& access : memoryAccesses)
    {
        if (access.Implicit)
        {
            continue;
        }

        int64_t offset = 0;
        std::string baseRegister = access.BaseRegister;

        if (access.StackFrameRelative)
        {
            baseRegister = "frame";
            offset = access.FrameOffset;
        }
        else if (access.BaseRegister == "rsp" || access.BaseRegister == "rbp")
        {
            if (!TryParseSignedValue(access.Displacement, offset))
            {
                offset = 0;
            }
        }
        else
        {
            continue;
        }

        if (access.IndexRegister.empty() && offset >= 0 && offset < 0x40)
        {
            std::string slot = baseRegister + HexS64(offset) + " at " + HexU64(access.Site);

            if (access.StackFrameRelative && access.BaseRegister != "rsp" && access.BaseRegister != "rbp")
            {
                slot += " via " + access.BaseRegister;
            }

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

        if (IsTailJumpCandidate(instruction, entryAddress, &instructionAddresses))
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
    if (access.StackFrameRelative)
    {
        return "[frame" + HexS64(access.FrameOffset) + "]";
    }

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

        if (!access.Implicit && access.StackFrameRelative)
        {
            TypeRecoveryHint hint;
            hint.Site = access.Site;
            hint.Expression = BuildMemoryExpression(access);
            hint.Type = InferTypeHintFromWidth(access.WidthBits, false);
            hint.Source = (access.BaseRegister != "rsp" && access.BaseRegister != "rbp") ? "stack_frame_alias" : "stack_frame_memory";
            hint.Kind = access.FrameOffset < 0 ? "stack_local_slot" : "stack_home_slot";
            hint.Evidence = access.Access + " normalized to frame" + HexS64(access.FrameOffset);
            hint.PointerLike = hint.Type.find('*') != std::string::npos;
            hint.Confidence = Clamp01(0.52 + (access.BaseRegister != "rsp" && access.BaseRegister != "rbp" ? 0.10 : 0.04));
            addHint(std::move(hint));
        }

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

std::string SimplifyCalleeNameKey(std::string name)
{
    name = ToLowerAscii(TrimCopy(name));
    const size_t bang = name.rfind('!');

    if (bang != std::string::npos && bang + 1 < name.size())
    {
        name = name.substr(bang + 1);
    }

    if (StartsWithInsensitive(name, "__imp_"))
    {
        name = name.substr(6);
    }

    return name;
}

PrototypeParameter MakeKnownApiParameter(
    uint32_t ordinal,
    const std::string& name,
    const std::string& type)
{
    PrototypeParameter parameter;
    parameter.Ordinal = ordinal;
    parameter.Name = name;
    parameter.Type = type;

    switch (ordinal)
    {
    case 1:
        parameter.Location = "rcx";
        break;
    case 2:
        parameter.Location = "rdx";
        break;
    case 3:
        parameter.Location = "r8";
        break;
    case 4:
        parameter.Location = "r9";
        break;
    default:
        parameter.Location = "stack+" + HexS64(0x20 + static_cast<int64_t>(ordinal - 5U) * 8);
        break;
    }

    parameter.Confidence = 0.74;
    return parameter;
}

std::vector<PrototypeParameter> BuildKnownApiParameters(const std::string& callee)
{
    const std::string key = SimplifyCalleeNameKey(callee);

    if (key.find("memcpy") != std::string::npos
        || key.find("memmove") != std::string::npos
        || key.find("rtlcopymemory") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "dst", "void *"),
            MakeKnownApiParameter(2, "src", "const void *"),
            MakeKnownApiParameter(3, "size", "size_t")
        };
    }

    if (key.find("memset") != std::string::npos
        || key.find("rtlfillmemory") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "dst", "void *"),
            MakeKnownApiParameter(2, "value", "int"),
            MakeKnownApiParameter(3, "size", "size_t")
        };
    }

    if (key.find("rtlzeromemory") != std::string::npos
        || key.find("zeromemory") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "dst", "void *"),
            MakeKnownApiParameter(2, "size", "size_t")
        };
    }

    if (key.find("heapalloc") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "heap", "HANDLE"),
            MakeKnownApiParameter(2, "flags", "DWORD"),
            MakeKnownApiParameter(3, "size", "SIZE_T")
        };
    }

    if (key.find("exallocatepool") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "pool_type", "POOL_TYPE"),
            MakeKnownApiParameter(2, "size", "SIZE_T")
        };
    }

    if (key.find("malloc") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "size", "size_t")
        };
    }

    if (key.find("heapfree") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "heap", "HANDLE"),
            MakeKnownApiParameter(2, "flags", "DWORD"),
            MakeKnownApiParameter(3, "ptr", "void *")
        };
    }

    if (key.find("exfreepool") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "ptr", "void *")
        };
    }

    if (key.find("closehandle") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "handle", "HANDLE")
        };
    }

    if (key.find("free") != std::string::npos)
    {
        return {
            MakeKnownApiParameter(1, "ptr", "void *")
        };
    }

    return {};
}

void ApplyKnownApiSemantics(CalleeSummary& summary)
{
    const std::string key = SimplifyCalleeNameKey(summary.Callee);
    bool recognized = false;

    if (key.find("memcpy") != std::string::npos
        || key.find("memmove") != std::string::npos
        || key.find("rtlcopymemory") != std::string::npos)
    {
        summary.ReturnType = key.find("rtlcopymemory") != std::string::npos ? "void" : "void *";
        summary.ParameterModel = "known_api: memory_copy(dst, src, size)";
        summary.SideEffects = "copies bytes between caller-provided buffers";
        summary.MemoryEffects = "writes dst[0..size) and reads src[0..size)";
        summary.Ownership = "no_transfer";
        recognized = true;
    }
    else if (key.find("memset") != std::string::npos
        || key.find("rtlfillmemory") != std::string::npos)
    {
        summary.ReturnType = key.find("rtlfillmemory") != std::string::npos ? "void" : "void *";
        summary.ParameterModel = "known_api: memory_fill(dst, value, size)";
        summary.SideEffects = "fills caller-provided buffer";
        summary.MemoryEffects = "writes dst[0..size)";
        summary.Ownership = "no_transfer";
        recognized = true;
    }
    else if (key.find("rtlzeromemory") != std::string::npos
        || key.find("zeromemory") != std::string::npos)
    {
        summary.ReturnType = "void";
        summary.ParameterModel = "known_api: zero_memory(dst, size)";
        summary.SideEffects = "zeros caller-provided buffer";
        summary.MemoryEffects = "writes dst[0..size)";
        summary.Ownership = "no_transfer";
        recognized = true;
    }
    else if (key.find("malloc") != std::string::npos
        || key.find("heapalloc") != std::string::npos
        || key.find("exallocatepool") != std::string::npos)
    {
        summary.ReturnType = "void *";
        summary.ParameterModel = "known_api: allocation";
        summary.SideEffects = "allocates memory";
        summary.MemoryEffects = "returns newly allocated storage on success";
        summary.Ownership = "returns_owned_resource";
        recognized = true;
    }
    else if (key.find("free") != std::string::npos
        || key.find("heapfree") != std::string::npos
        || key.find("exfreepool") != std::string::npos
        || key.find("closehandle") != std::string::npos)
    {
        summary.ReturnType = key.find("heapfree") != std::string::npos || key.find("closehandle") != std::string::npos ? "BOOL" : "void";
        summary.ParameterModel = "known_api: release";
        summary.SideEffects = "releases caller-owned resource";
        summary.MemoryEffects = "invalidates released handle or pointer on success";
        summary.Ownership = "releases_resource";
        recognized = true;
    }
    else if (StartsWithInsensitive(key, "nt") || StartsWithInsensitive(key, "zw"))
    {
        summary.ReturnType = "NTSTATUS";
        summary.ParameterModel = "known_api: ntstatus_service";
        summary.SideEffects = "may update out parameters and returns NTSTATUS";
        summary.MemoryEffects = "may read input buffers and write output buffers";
        summary.Ownership = "api_contract";
        recognized = true;
    }
    else if (StartsWithInsensitive(key, "rtl"))
    {
        summary.ParameterModel = "known_api: rtl_helper";
        summary.SideEffects = summary.SideEffects.empty() || summary.SideEffects == "unknown"
            ? "runtime library helper with contract-defined side effects"
            : summary.SideEffects;
        summary.MemoryEffects = summary.MemoryEffects.empty() || summary.MemoryEffects == "unknown"
            ? "depends on documented Rtl contract"
            : summary.MemoryEffects;
        summary.Ownership = summary.Ownership.empty() || summary.Ownership == "unknown" ? "api_contract" : summary.Ownership;
        recognized = true;
    }

    if (recognized)
    {
        const std::vector<PrototypeParameter> parameters = BuildKnownApiParameters(summary.Callee);

        if (!parameters.empty())
        {
            summary.Parameters = parameters;
        }

        summary.Source = summary.Source.empty() || summary.Source == "call_site" ? "known_api_model" : summary.Source;
        summary.Confidence = Clamp01(summary.Confidence + 0.18);
    }
}

void ApplyKnownApiSemantics(CallTargetInfo& target)
{
    CalleeSummary summary;
    summary.Site = target.Site;
    summary.Callee = target.DisplayName;
    summary.ReturnType = target.ReturnType.empty() ? "UNKNOWN_TYPE" : target.ReturnType;
    summary.ParameterModel = target.Prototype.empty() ? std::string() : target.Prototype;
    summary.SideEffects = target.SideEffects;
    summary.MemoryEffects = target.MemoryEffects;
    summary.Ownership = target.Ownership;
    summary.Parameters = target.Parameters;
    summary.Confidence = target.Confidence;

    ApplyKnownApiSemantics(summary);

    target.ReturnType = summary.ReturnType;
    target.SideEffects = summary.SideEffects;
    target.MemoryEffects = summary.MemoryEffects;
    target.Ownership = summary.Ownership;

    if (!summary.Parameters.empty())
    {
        target.Parameters = summary.Parameters;
    }

    if (target.Prototype.empty() || ContainsInsensitive(target.Prototype, "UNKNOWN_TYPE"))
    {
        target.Prototype = summary.ParameterModel;
    }

    target.Confidence = summary.Confidence;
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
        ApplyKnownApiSemantics(summary);
        summaries.push_back(std::move(summary));
    }

    return summaries;
}

std::vector<CallTargetInfo> CollectTailCallTargets(
    const std::vector<DisassembledInstruction>& instructions,
    uint64_t entryAddress)
{
    std::vector<CallTargetInfo> targets;
    std::set<uint64_t> instructionAddresses;

    for (const DisassembledInstruction& instruction : instructions)
    {
        instructionAddresses.insert(instruction.Address);
    }

    for (const DisassembledInstruction& instruction : instructions)
    {
        if (!IsTailJumpCandidate(instruction, entryAddress, &instructionAddresses))
        {
            continue;
        }

        CallTargetInfo target;
        target.Site = instruction.Address;
        target.TargetAddress = instruction.BranchTarget;
        target.DisplayName = HexU64(instruction.BranchTarget);
        target.TargetKind = "tail_call_direct";
        target.Prototype = "UNKNOWN_TYPE " + target.DisplayName + "(...)";
        target.ReturnType = "UNKNOWN_TYPE";
        target.SideEffects = "tail-calls target and does not return to this function";
        target.Indirect = instruction.IsIndirect;
        target.TailCall = true;
        target.Confidence = 0.62;
        targets.push_back(std::move(target));
    }

    return targets;
}

std::vector<CallTargetInfo> CollectIndirectCallTargets(
    const std::vector<DisassembledInstruction>& instructions,
    const std::vector<MemoryAccess>& memoryAccesses)
{
    std::vector<CallTargetInfo> targets;
    const MemoryAccessIndex accessBySite = BuildMemoryAccessIndex(memoryAccesses);

    for (const DisassembledInstruction& instruction : instructions)
    {
        if (!instruction.IsCall || !instruction.IsIndirect)
        {
            continue;
        }

        CallTargetInfo target;
        target.Site = instruction.Address;
        target.DisplayName = instruction.OperandText.empty() ? "<indirect>" : StripPointerDecorators(instruction.OperandText);
        target.TargetKind = "indirect_register";
        target.Prototype = "UNKNOWN_TYPE " + target.DisplayName + "(...)";
        target.ReturnType = "UNKNOWN_TYPE";
        target.SideEffects = "indirect call through register or memory target";
        target.MemoryEffects = "unknown";
        target.Ownership = "unknown";
        target.Indirect = true;
        target.Confidence = 0.48;

        const std::vector<const MemoryAccess*> accesses = FindMemoryAccessesAtSite(accessBySite, instruction.Address);
        const MemoryAccess* access = SelectPrimaryMemoryAccess(accesses);

        if (access != nullptr)
        {
            int64_t displacement = 0;
            target.TargetExpression = BuildMemoryExpression(*access);
            target.DisplayName = target.TargetExpression;
            target.TargetKind = "indirect_memory";

            const bool hasParsedDisplacement = access->Displacement.empty()
                || TryParseSignedValue(access->Displacement, displacement);

            if (access->WidthBits == 64
                && !access->StackFrameRelative
                && !access->BaseRegister.empty()
                && access->BaseRegister != "rip"
                && access->BaseRegister != "rsp"
                && access->BaseRegister != "rbp"
                && hasParsedDisplacement
                && displacement >= 0)
            {
                target.VirtualCall = true;
                target.VtableOffset = static_cast<uint32_t>(displacement);
                target.TargetKind = "virtual_call_candidate";
                target.DisplayName = "virtual_call_" + access->BaseRegister + HexS64(displacement);
                target.SideEffects = "virtual or function-pointer call through object table";
                target.Confidence = 0.56;
            }
        }

        targets.push_back(std::move(target));
    }

    return targets;
}

void AppendCalleeSummariesFromCallTargets(
    const std::vector<CallTargetInfo>& targets,
    std::vector<CalleeSummary>& summaries)
{
    for (const CallTargetInfo& target : targets)
    {
        const auto existing = std::find_if(
            summaries.begin(),
            summaries.end(),
            [&target](const CalleeSummary& summary)
            {
                return summary.Site == target.Site;
            });

        CalleeSummary summary;
        summary.Site = target.Site;
        summary.Callee = target.DisplayName;
        summary.ReturnType = !target.ReturnType.empty() ? target.ReturnType : "UNKNOWN_TYPE";
        summary.ParameterModel = !target.Prototype.empty() ? target.Prototype : "UNKNOWN_TYPE " + target.DisplayName + "(...)";
        summary.SideEffects = target.SideEffects.empty() ? "unknown" : target.SideEffects;
        summary.MemoryEffects = target.TailCall ? "delegates to tail-call target" : InferMemoryEffectsFromCalleeName(target.DisplayName, summary.SideEffects);
        summary.Ownership = InferOwnershipFromCalleeName(target.DisplayName);
        summary.Source = target.TailCall ? "tail_call_target" : "call_target";
        summary.Parameters = target.Parameters;
        summary.TailCall = target.TailCall;
        summary.Confidence = Clamp01(target.Confidence + (target.TailCall ? 0.04 : 0.0));
        ApplyKnownApiSemantics(summary);

        if (existing == summaries.end())
        {
            summaries.push_back(std::move(summary));
        }
        else
        {
            *existing = std::move(summary);
        }
    }
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
    const std::vector<MemoryAccess>& memoryAccesses,
    const std::vector<RecoveredArgument>& arguments,
    const std::vector<RecoveredLocal>& locals)
{
    std::unordered_map<uint64_t, const DisassembledInstruction*> instructionByAddress;
    const MemoryAccessIndex memoryAccessBySite = BuildMemoryAccessIndex(memoryAccesses);
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
                const std::vector<const MemoryAccess*> accesses = FindMemoryAccessesAtSite(memoryAccessBySite, instruction.Address);
                lastPattern.Kind = instruction.Mnemonic;
                lastPattern.Left = RewriteOperandWithRecoveredNames(operands[0], accesses, argumentRegisterMap, localKeyNameMap);
                lastPattern.Right = RewriteOperandWithRecoveredNames(operands[1], accesses, argumentRegisterMap, localKeyNameMap);
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
                continue;
            }

            if (InstructionWritesFlags(instruction))
            {
                lastPattern = ComparePattern();
            }
        }
    }

    return conditions;
}

std::string BuildEvidenceBlockNodeId(const std::string& blockId)
{
    return "block:" + blockId;
}

std::string BuildEvidenceInstructionNodeId(uint64_t site)
{
    return "insn:" + HexU64(site);
}

std::string BuildEvidenceIndexedNodeId(const std::string& prefix, size_t index)
{
    return prefix + ":" + std::to_string(index);
}

struct EvidenceGraphBuilder
{
    EvidenceGraphFacts Graph;
    std::unordered_set<std::string> NodeIds;
    std::unordered_set<std::string> EdgeIds;
    std::unordered_map<uint64_t, const DisassembledInstruction*> InstructionByAddress;
    std::unordered_map<uint64_t, std::string> BlockByAddress;

    explicit EvidenceGraphBuilder(const AnalysisFacts& facts)
    {
        BlockByAddress = BuildBlockIdByInstructionAddress(facts.Blocks);

        for (const DisassembledInstruction& instruction : facts.Instructions)
        {
            InstructionByAddress[instruction.Address] = &instruction;
        }
    }

    void AddNode(EvidenceNode node)
    {
        if (node.Id.empty())
        {
            return;
        }

        if (!NodeIds.insert(node.Id).second)
        {
            return;
        }

        Graph.Nodes.push_back(std::move(node));
    }

    void AddEdge(const std::string& sourceId, const std::string& targetId, const std::string& relation, double confidence)
    {
        if (sourceId.empty() || targetId.empty() || relation.empty())
        {
            return;
        }

        const std::string edgeId = sourceId + "\n" + relation + "\n" + targetId;

        if (!EdgeIds.insert(edgeId).second)
        {
            return;
        }

        EvidenceEdge edge;
        edge.SourceId = sourceId;
        edge.TargetId = targetId;
        edge.Relation = relation;
        edge.Confidence = Clamp01(confidence);
        Graph.Edges.push_back(std::move(edge));
    }

    void AddBlock(const BasicBlock& block)
    {
        EvidenceNode node;
        node.Id = BuildEvidenceBlockNodeId(block.Id);
        node.Kind = "basic_block";
        node.Label = HexU64(block.StartAddress) + "-" + HexU64(block.EndAddress);
        node.Site = block.StartAddress;
        node.BlockId = block.Id;
        node.Confidence = block.HasTerminal ? 0.90 : 0.72;
        AddNode(std::move(node));
    }

    void AddInstruction(uint64_t site)
    {
        if (site == 0)
        {
            return;
        }

        const auto instructionIt = InstructionByAddress.find(site);
        const auto blockIt = BlockByAddress.find(site);

        EvidenceNode node;
        node.Id = BuildEvidenceInstructionNodeId(site);
        node.Kind = "instruction";
        node.Site = site;
        node.BlockId = blockIt == BlockByAddress.end() ? std::string() : blockIt->second;
        node.Confidence = instructionIt == InstructionByAddress.end() ? 0.55 : 1.0;

        if (instructionIt != InstructionByAddress.end())
        {
            node.Label = instructionIt->second->OperationText.empty()
                ? instructionIt->second->Text
                : instructionIt->second->OperationText;
        }
        else
        {
            node.Label = HexU64(site);
        }

        AddNode(std::move(node));

        if (blockIt != BlockByAddress.end())
        {
            AddEdge(BuildEvidenceInstructionNodeId(site), BuildEvidenceBlockNodeId(blockIt->second), "in_block", 0.95);
        }
    }

    std::string AddSiteFact(
        const std::string& id,
        const std::string& kind,
        const std::string& label,
        uint64_t site,
        const std::string& blockId,
        double confidence)
    {
        std::string effectiveBlock = blockId;

        if (effectiveBlock.empty() && site != 0)
        {
            const auto blockIt = BlockByAddress.find(site);

            if (blockIt != BlockByAddress.end())
            {
                effectiveBlock = blockIt->second;
            }
        }

        EvidenceNode node;
        node.Id = id;
        node.Kind = kind;
        node.Label = label;
        node.Site = site;
        node.BlockId = effectiveBlock;
        node.Confidence = Clamp01(confidence);
        AddNode(std::move(node));

        if (site != 0)
        {
            AddInstruction(site);
            AddEdge(id, BuildEvidenceInstructionNodeId(site), "at_instruction", confidence);
        }

        if (!effectiveBlock.empty())
        {
            AddEdge(id, BuildEvidenceBlockNodeId(effectiveBlock), "in_block", confidence);
        }

        return id;
    }

    void FinalizeCoverage()
    {
        size_t semanticNodes = 0;
        size_t groundedNodes = 0;

        for (const EvidenceNode& node : Graph.Nodes)
        {
            if (node.Kind == "basic_block" || node.Kind == "instruction")
            {
                continue;
            }

            ++semanticNodes;

            if (node.Site != 0 || !node.BlockId.empty())
            {
                ++groundedNodes;
            }
        }

        Graph.Coverage = semanticNodes == 0
            ? 0.0
            : static_cast<double>(groundedNodes) / static_cast<double>(semanticNodes);
    }
};

EvidenceGraphFacts BuildEvidenceGraphFacts(const AnalysisFacts& facts)
{
    EvidenceGraphBuilder builder(facts);

    for (const BasicBlock& block : facts.Blocks)
    {
        builder.AddBlock(block);

        for (const std::string& successor : block.Successors)
        {
            if (!successor.empty())
            {
                builder.AddEdge(BuildEvidenceBlockNodeId(block.Id), BuildEvidenceBlockNodeId(successor), "cfg_successor", 0.90);
            }
        }
    }

    for (size_t index = 0; index < facts.MemoryAccesses.size(); ++index)
    {
        const MemoryAccess& access = facts.MemoryAccesses[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("memory", index),
            "memory_access",
            access.Kind + " " + access.Access,
            access.Site,
            std::string(),
            access.Implicit ? 0.70 : 0.86);
    }

    for (size_t index = 0; index < facts.RecoveredArguments.size(); ++index)
    {
        const RecoveredArgument& argument = facts.RecoveredArguments[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("argument", index),
            "recovered_argument",
            argument.Name + ":" + argument.Register,
            argument.FirstUseSite,
            std::string(),
            argument.Confidence);
    }

    for (size_t index = 0; index < facts.RecoveredLocals.size(); ++index)
    {
        const RecoveredLocal& local = facts.RecoveredLocals[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("local", index),
            "recovered_local",
            local.Name + " " + local.Storage,
            local.FirstSite,
            std::string(),
            local.Confidence);
    }

    for (size_t index = 0; index < facts.CallArguments.size(); ++index)
    {
        const CallArgumentFact& argument = facts.CallArguments[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("call_arg", index),
            "call_argument",
            "arg" + std::to_string(argument.Ordinal) + " " + argument.Location + "=" + argument.Expression,
            argument.Site,
            std::string(),
            argument.Confidence);
    }

    for (size_t index = 0; index < facts.ValueMerges.size(); ++index)
    {
        const ValueMerge& merge = facts.ValueMerges[index];
        const std::string nodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("merge", index),
            "value_merge",
            merge.Variable + " <- " + JoinStrings(merge.IncomingValues, ","),
            0,
            merge.BlockId,
            merge.Confidence);

        for (const std::string& predecessor : merge.Predecessors)
        {
            if (!predecessor.empty())
            {
                builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(predecessor), "merge_predecessor", merge.Confidence);
            }
        }
    }

    for (size_t index = 0; index < facts.IrValues.size(); ++index)
    {
        const IrValue& value = facts.IrValues[index];
        const std::string nodeId = builder.AddSiteFact(
            "ir:" + value.Id,
            "ir_value",
            value.Target + "=" + value.Canonical,
            value.DefSite,
            value.BlockId,
            value.Confidence);

        for (const std::string& use : value.Uses)
        {
            builder.AddEdge(nodeId, "ir:" + use, "uses_value", value.Confidence);
        }
    }

    for (const BlockValueState& state : facts.BlockValueStates)
    {
        const std::string nodeId = builder.AddSiteFact(
            "block_state:" + state.BlockId,
            "block_value_state",
            "live_in=" + std::to_string(state.LiveIn.size()) + " live_out=" + std::to_string(state.LiveOut.size()),
            0,
            state.BlockId,
            state.Confidence);

        for (const ReachingValue& value : state.LiveIn)
        {
            if (!value.ValueId.empty())
            {
                builder.AddEdge("ir:" + value.ValueId, nodeId, "live_in", value.Confidence);
            }
        }

        for (const ReachingValue& value : state.LiveOut)
        {
            if (!value.ValueId.empty())
            {
                builder.AddEdge(nodeId, "ir:" + value.ValueId, "live_out", value.Confidence);
            }
        }
    }

    for (size_t index = 0; index < facts.Obfuscation.StateVariables.size(); ++index)
    {
        const ObfuscationStateVariable& variable = facts.Obfuscation.StateVariables[index];
        const std::string stateNodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("obf_state", index),
            "obfuscation.state_variable",
            variable.Name + " " + variable.Storage,
            variable.FirstSite,
            std::string(),
            variable.Confidence);

        for (const IrValue& value : facts.IrValues)
        {
            if (value.Target == variable.Name && !value.BlockId.empty())
            {
                builder.AddEdge(
                    BuildEvidenceBlockNodeId(value.BlockId),
                    stateNodeId,
                    "writes_state",
                    (std::min)(variable.Confidence, value.Confidence));
            }
        }
    }

    for (size_t index = 0; index < facts.Obfuscation.Dispatchers.size(); ++index)
    {
        const ObfuscationDispatcher& dispatcher = facts.Obfuscation.Dispatchers[index];
        const std::string dispatcherNodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("obf_dispatcher", index),
            "obfuscation.dispatcher",
            dispatcher.Kind + " state=" + dispatcher.StateVariable,
            0,
            dispatcher.HeaderBlock,
            dispatcher.Confidence);

        for (size_t stateIndex = 0; stateIndex < facts.Obfuscation.StateVariables.size(); ++stateIndex)
        {
            if (facts.Obfuscation.StateVariables[stateIndex].Name == dispatcher.StateVariable)
            {
                builder.AddEdge(BuildEvidenceIndexedNodeId("obf_state", stateIndex), dispatcherNodeId, "read_by", dispatcher.Confidence);
                break;
            }
        }

        for (const std::string& block : dispatcher.DispatcherBlocks)
        {
            if (!block.empty())
            {
                builder.AddEdge(dispatcherNodeId, BuildEvidenceBlockNodeId(block), "dispatcher_block", dispatcher.Confidence);
            }
        }

        for (const std::string& block : dispatcher.OriginalBlockCandidates)
        {
            if (!block.empty())
            {
                builder.AddEdge(dispatcherNodeId, BuildEvidenceBlockNodeId(block), "original_block_candidate", dispatcher.Confidence);
            }
        }

        for (size_t edgeIndex = 0; edgeIndex < dispatcher.RecoveredEdges.size(); ++edgeIndex)
        {
            const RecoveredControlFlowEdge& recoveredEdge = dispatcher.RecoveredEdges[edgeIndex];
            const std::string edgeNodeId = builder.AddSiteFact(
                BuildEvidenceIndexedNodeId("obf_edge_" + std::to_string(index), edgeIndex),
                "obfuscation.recovered_edge",
                recoveredEdge.SourceBlock + "->" + recoveredEdge.TargetBlock + " state=" + recoveredEdge.StateValue,
                0,
                recoveredEdge.SourceBlock,
                recoveredEdge.Confidence);

            builder.AddEdge(dispatcherNodeId, edgeNodeId, "recovers_edge", recoveredEdge.Confidence);

            if (!recoveredEdge.SourceBlock.empty())
            {
                builder.AddEdge(edgeNodeId, BuildEvidenceBlockNodeId(recoveredEdge.SourceBlock), "from_block", recoveredEdge.Confidence);
            }

            if (!recoveredEdge.TargetBlock.empty())
            {
                builder.AddEdge(edgeNodeId, BuildEvidenceBlockNodeId(recoveredEdge.TargetBlock), "to_block", recoveredEdge.Confidence);
            }
        }
    }

    for (size_t index = 0; index < facts.Obfuscation.OpaquePredicates.size(); ++index)
    {
        const OpaquePredicateFact& predicate = facts.Obfuscation.OpaquePredicates[index];
        const std::string nodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("obf_opaque", index),
            "obfuscation.opaque_predicate",
            predicate.Predicate + "=" + predicate.ConstantResult,
            predicate.Site,
            predicate.BlockId,
            predicate.Confidence);

        if (!predicate.DeadTargetBlock.empty())
        {
            builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(predicate.DeadTargetBlock), "prunes", predicate.Confidence);
        }

        if (!predicate.LiveTargetBlock.empty())
        {
            builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(predicate.LiveTargetBlock), "keeps", predicate.Confidence);
        }
    }

    for (size_t index = 0; index < facts.Obfuscation.SubstitutionIdioms.size(); ++index)
    {
        const SubstitutionIdiomFact& idiom = facts.Obfuscation.SubstitutionIdioms[index];
        const std::string nodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("obf_substitution", index),
            "obfuscation.substitution_idiom",
            idiom.Pattern + " " + idiom.SimplifiedExpression,
            idiom.Site,
            idiom.BlockId,
            idiom.Confidence);

        for (const IrValue& value : facts.IrValues)
        {
            if (value.DefSite == idiom.Site)
            {
                builder.AddEdge(nodeId, "ir:" + value.Id, "simplifies", idiom.Confidence);
                break;
            }
        }
    }

    for (size_t index = 0; index < facts.SemanticControlFlow.Edges.size(); ++index)
    {
        const SemanticControlFlowEdge& edge = facts.SemanticControlFlow.Edges[index];
        const std::string nodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("semantic_cfg", index),
            edge.Dead ? "semantic_cfg.dead_edge" : "semantic_cfg.edge",
            edge.SourceBlock + "->" + edge.TargetBlock + " " + edge.Source,
            0,
            edge.SourceBlock,
            edge.Confidence);

        if (!edge.SourceBlock.empty())
        {
            builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(edge.SourceBlock), "from_block", edge.Confidence);
        }

        if (!edge.TargetBlock.empty())
        {
            builder.AddEdge(
                nodeId,
                BuildEvidenceBlockNodeId(edge.TargetBlock),
                edge.Dead ? "prunes_edge" : "semantic_successor",
                edge.Confidence);
        }
    }

    for (size_t index = 0; index < facts.ControlFlow.size(); ++index)
    {
        const ControlFlowRegion& region = facts.ControlFlow[index];
        const std::string nodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("control_flow", index),
            "control_flow_region",
            region.Kind + " " + region.Condition,
            0,
            region.HeaderBlock,
            region.Confidence);

        for (const std::string& block : region.BodyBlocks)
        {
            if (!block.empty())
            {
                builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(block), "region_body", region.Confidence);
            }
        }

        for (const std::string& block : region.LatchBlocks)
        {
            if (!block.empty())
            {
                builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(block), "region_latch", region.Confidence);
            }
        }

        for (const std::string& block : region.ExitBlocks)
        {
            if (!block.empty())
            {
                builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(block), "region_exit", region.Confidence);
            }
        }
    }

    for (size_t index = 0; index < facts.TypeHints.size(); ++index)
    {
        const TypeRecoveryHint& hint = facts.TypeHints[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("type_hint", index),
            "type_hint",
            hint.Expression + ":" + hint.Type,
            hint.Site,
            std::string(),
            hint.Confidence);
    }

    for (size_t index = 0; index < facts.Idioms.size(); ++index)
    {
        const IdiomPattern& idiom = facts.Idioms[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("idiom", index),
            "idiom",
            idiom.Kind + " " + idiom.Name,
            idiom.Site,
            std::string(),
            idiom.Confidence);
    }

    for (size_t index = 0; index < facts.CalleeSummaries.size(); ++index)
    {
        const CalleeSummary& summary = facts.CalleeSummaries[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("callee", index),
            "callee_summary",
            summary.Callee + " " + summary.MemoryEffects,
            summary.Site,
            std::string(),
            summary.Confidence);
    }

    for (size_t index = 0; index < facts.DataReferences.size(); ++index)
    {
        const DataReference& reference = facts.DataReferences[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("data_ref", index),
            "data_reference",
            reference.Display.empty() ? reference.Symbol : reference.Display,
            reference.Site,
            std::string(),
            reference.Dereferenced ? 0.82 : 0.74);
    }

    for (size_t index = 0; index < facts.CallTargets.size(); ++index)
    {
        const CallTargetInfo& target = facts.CallTargets[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("call_target", index),
            "call_target",
            target.DisplayName.empty() ? target.TargetExpression : target.DisplayName,
            target.Site,
            std::string(),
            target.Confidence);
    }

    for (size_t index = 0; index < facts.NormalizedConditions.size(); ++index)
    {
        const NormalizedCondition& condition = facts.NormalizedConditions[index];
        const std::string nodeId = builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("condition", index),
            "normalized_condition",
            condition.Expression,
            condition.Site,
            condition.BlockId,
            condition.Confidence);

        if (!condition.TrueTargetBlock.empty())
        {
            builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(condition.TrueTargetBlock), "true_target", condition.Confidence);
        }

        if (!condition.FalseTargetBlock.empty())
        {
            builder.AddEdge(nodeId, BuildEvidenceBlockNodeId(condition.FalseTargetBlock), "false_target", condition.Confidence);
        }
    }

    if (!facts.Pdb.FunctionName.empty())
    {
        builder.AddSiteFact(
            "pdb:function",
            "pdb_function",
            facts.Pdb.FunctionName,
            facts.EntryAddress,
            std::string(),
            facts.Pdb.Confidence);
    }

    for (size_t index = 0; index < facts.Pdb.Params.size(); ++index)
    {
        const PdbScopedSymbol& symbol = facts.Pdb.Params[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("pdb_param", index),
            "pdb_param",
            symbol.Name + ":" + symbol.Type,
            symbol.Site,
            std::string(),
            symbol.Confidence);
    }

    for (size_t index = 0; index < facts.Pdb.Locals.size(); ++index)
    {
        const PdbScopedSymbol& symbol = facts.Pdb.Locals[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("pdb_local", index),
            "pdb_local",
            symbol.Name + ":" + symbol.Type,
            symbol.Site,
            std::string(),
            symbol.Confidence);
    }

    for (size_t index = 0; index < facts.Pdb.FieldHints.size(); ++index)
    {
        const PdbFieldHint& hint = facts.Pdb.FieldHints[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("pdb_field", index),
            "pdb_field",
            hint.BaseName + "->" + hint.FieldName,
            hint.Site,
            std::string(),
            hint.Confidence);
    }

    for (size_t index = 0; index < facts.Pdb.EnumHints.size(); ++index)
    {
        const PdbEnumHint& hint = facts.Pdb.EnumHints[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("pdb_enum", index),
            "pdb_enum",
            hint.Expression + "=" + hint.ConstantName,
            hint.Site,
            std::string(),
            hint.Confidence);
    }

    for (size_t index = 0; index < facts.Pdb.SourceLocations.size(); ++index)
    {
        const PdbSourceLocation& source = facts.Pdb.SourceLocations[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("pdb_source", index),
            "pdb_source_location",
            source.File + ":" + std::to_string(source.Line),
            source.Site,
            std::string(),
            source.Confidence);
    }

    for (size_t index = 0; index < facts.ObservedBehavior.ArgumentSamples.size(); ++index)
    {
        const ObservedArgumentValue& argument = facts.ObservedBehavior.ArgumentSamples[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("observed_arg", index),
            "observed_argument",
            argument.Name + ":" + HexU64(argument.Value),
            facts.ObservedBehavior.CurrentInstructionInFunction ? facts.ObservedBehavior.InstructionPointer : 0,
            std::string(),
            argument.Confidence);
    }

    for (size_t index = 0; index < facts.ObservedBehavior.MemoryHotspots.size(); ++index)
    {
        const ObservedMemoryHotspot& hotspot = facts.ObservedBehavior.MemoryHotspots[index];
        builder.AddSiteFact(
            BuildEvidenceIndexedNodeId("observed_hotspot", index),
            "observed_memory_hotspot",
            hotspot.Kind + " " + hotspot.Expression,
            hotspot.Sites.empty() ? 0 : hotspot.Sites.front(),
            std::string(),
            hotspot.Confidence);
    }

    builder.Graph.Notes.push_back("Evidence graph links high-signal facts to instruction and block evidence.");
    builder.Graph.Notes.push_back("PDB and observed nodes are included when the graph is refreshed after debug enrichment.");
    builder.FinalizeCoverage();
    return builder.Graph;
}

void UpdateEvidenceGraphSummaryFact(AnalysisFacts& facts)
{
    facts.Facts.erase(
        std::remove_if(
            facts.Facts.begin(),
            facts.Facts.end(),
            [](const std::string& fact)
            {
                return StartsWithInsensitive(fact, "evidence graph:");
            }),
        facts.Facts.end());

    if (!facts.EvidenceGraph.Nodes.empty() || !facts.EvidenceGraph.Edges.empty())
    {
        facts.Facts.push_back(
            "evidence graph: nodes="
            + std::to_string(facts.EvidenceGraph.Nodes.size())
            + ", edges="
            + std::to_string(facts.EvidenceGraph.Edges.size()));
    }
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

void RefreshDerivedAnalysisFacts(AnalysisFacts& facts)
{
    facts.CallArguments = CollectCallArgumentFacts(
        facts.Instructions,
        facts.Blocks,
        facts.MemoryAccesses,
        facts.RecoveredArguments,
        facts.RecoveredLocals);
    facts.ValueMerges = CollectValueMerges(
        facts.Instructions,
        facts.Blocks,
        facts.MemoryAccesses,
        facts.RecoveredArguments,
        facts.RecoveredLocals);
    facts.IrValues = CollectIrValues(
        facts.Instructions,
        facts.Blocks,
        facts.MemoryAccesses,
        facts.RecoveredArguments,
        facts.RecoveredLocals);
    const std::vector<SubstitutionIdiomFact> substitutionIdioms = CanonicalizeSubstitutionIdioms(facts.IrValues);
    facts.BlockValueStates = CollectBlockValueStates(facts.Blocks, facts.IrValues);
    facts.NormalizedConditions = CollectNormalizedConditions(
        facts.Instructions,
        facts.Blocks,
        facts.MemoryAccesses,
        facts.RecoveredArguments,
        facts.RecoveredLocals);
    facts.Obfuscation = AnalyzeObfuscationFacts(
        facts.Instructions,
        facts.Blocks,
        facts.IrValues,
        facts.BlockValueStates,
        facts.NormalizedConditions,
        facts.Switches);
    AppendSubstitutionIdioms(facts.Obfuscation, substitutionIdioms);
    facts.SemanticControlFlow = BuildSemanticControlFlowOverlay(facts.Obfuscation);
    const std::vector<BasicBlock> semanticBlocks = BuildBlocksWithSemanticControlFlow(facts.Blocks, facts.SemanticControlFlow);
    facts.ControlFlow = AnalyzeControlFlow(facts.Instructions, semanticBlocks, facts.NormalizedConditions, facts.Switches);
    RefreshEvidenceGraph(facts);
}

void RefreshEvidenceGraph(AnalysisFacts& facts)
{
    facts.EvidenceGraph = BuildEvidenceGraphFacts(facts);
    UpdateEvidenceGraphSummaryFact(facts);
}

void ApplyRecoveredSwitchTargets(AnalysisFacts& facts)
{
    std::set<uint64_t> instructionAddresses;
    std::set<uint64_t> switchTargetLeaders;

    for (const DisassembledInstruction& instruction : facts.Instructions)
    {
        instructionAddresses.insert(instruction.Address);
    }

    for (const SwitchInfo& switchInfo : facts.Switches)
    {
        if (switchInfo.DefaultTarget != 0
            && instructionAddresses.find(switchInfo.DefaultTarget) != instructionAddresses.end())
        {
            switchTargetLeaders.insert(switchInfo.DefaultTarget);
        }

        for (const uint64_t target : switchInfo.CaseTargets)
        {
            if (instructionAddresses.find(target) != instructionAddresses.end())
            {
                switchTargetLeaders.insert(target);
            }
        }
    }

    if (!switchTargetLeaders.empty())
    {
        facts.Blocks = BuildBasicBlocksWithExtraLeaders(facts.Instructions, switchTargetLeaders);
    }

    AddRecoveredSwitchSuccessorsToBlocks(facts.Blocks, facts.Switches);
    facts.StackPointer = CollectStackPointerFacts(facts.Instructions, facts.Blocks);
    facts.MemoryAccesses = CollectMemoryAccesses(facts.Instructions, facts.Blocks, facts.StackPointer);
    facts.RecoveredLocals = RecoverLocals(facts.MemoryAccesses, facts.StackFrame);
    RefreshDerivedAnalysisFacts(facts);
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
    facts.StackPointer = CollectStackPointerFacts(instructions, facts.Blocks);
    facts.MemoryAccesses = CollectMemoryAccesses(instructions, facts.Blocks, facts.StackPointer);
    facts.RecoveredArguments = RecoverArguments(instructions);
    facts.RecoveredLocals = RecoverLocals(facts.MemoryAccesses, facts.StackFrame);
    facts.CallArguments = CollectCallArgumentFacts(instructions, facts.Blocks, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.ValueMerges = CollectValueMerges(instructions, facts.Blocks, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.IrValues = CollectIrValues(instructions, facts.Blocks, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    const std::vector<SubstitutionIdiomFact> substitutionIdioms = CanonicalizeSubstitutionIdioms(facts.IrValues);
    facts.BlockValueStates = CollectBlockValueStates(facts.Blocks, facts.IrValues);
    facts.NormalizedConditions = CollectNormalizedConditions(instructions, facts.Blocks, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.Obfuscation = AnalyzeObfuscationFacts(
        facts.Instructions,
        facts.Blocks,
        facts.IrValues,
        facts.BlockValueStates,
        facts.NormalizedConditions,
        facts.Switches);
    AppendSubstitutionIdioms(facts.Obfuscation, substitutionIdioms);
    facts.SemanticControlFlow = BuildSemanticControlFlowOverlay(facts.Obfuscation);
    const std::vector<BasicBlock> semanticBlocks = BuildBlocksWithSemanticControlFlow(facts.Blocks, facts.SemanticControlFlow);
    facts.ControlFlow = AnalyzeControlFlow(facts.Instructions, semanticBlocks, facts.NormalizedConditions, facts.Switches);
    facts.Abi = AnalyzeAbiFacts(instructions, facts.MemoryAccesses, facts.StackFrame, entryAddress);
    facts.TypeHints = CollectTypeRecoveryHints(instructions, facts.MemoryAccesses, facts.RecoveredArguments, facts.RecoveredLocals);
    facts.Idioms = CollectIdiomPatterns(instructions, facts.Calls, facts.MemoryAccesses, facts.Abi);
    facts.CallTargets = CollectTailCallTargets(instructions, entryAddress);
    {
        std::vector<CallTargetInfo> indirectTargets = CollectIndirectCallTargets(instructions, facts.MemoryAccesses);
        facts.CallTargets.insert(
            facts.CallTargets.end(),
            std::make_move_iterator(indirectTargets.begin()),
            std::make_move_iterator(indirectTargets.end()));
    }
    facts.CalleeSummaries = CollectCalleeSummaries(facts.Calls);
    AppendCalleeSummariesFromCallTargets(facts.CallTargets, facts.CalleeSummaries);
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

    if (!facts.StackPointer.empty())
    {
        size_t known = 0;

        for (const auto& fact : facts.StackPointer)
        {
            known += fact.Known ? 1U : 0U;
        }

        facts.Facts.push_back(
            "stack pointer deltas tracked: "
            + std::to_string(known)
            + "/"
            + std::to_string(facts.StackPointer.size()));
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

    if (!facts.CallArguments.empty())
    {
        facts.Facts.push_back("call-site arguments recovered: " + std::to_string(facts.CallArguments.size()));
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

    if (!facts.BlockValueStates.empty())
    {
        size_t liveInEntries = 0;
        size_t liveOutEntries = 0;
        size_t unconvergedBlocks = 0;

        for (const BlockValueState& state : facts.BlockValueStates)
        {
            liveInEntries += state.LiveIn.size();
            liveOutEntries += state.LiveOut.size();
            unconvergedBlocks += state.Converged ? 0U : 1U;
        }

        facts.Facts.push_back(
            "block value states: "
            + std::to_string(facts.BlockValueStates.size())
            + " (live_in="
            + std::to_string(liveInEntries)
            + ", live_out="
            + std::to_string(liveOutEntries)
            + ", unconverged="
            + std::to_string(unconvergedBlocks)
            + ")");
    }

    if (!facts.Obfuscation.Dispatchers.empty()
        || !facts.Obfuscation.StateVariables.empty()
        || !facts.Obfuscation.OpaquePredicates.empty()
        || !facts.Obfuscation.SubstitutionIdioms.empty())
    {
        size_t recoveredEdges = 0;

        for (const ObfuscationDispatcher& dispatcher : facts.Obfuscation.Dispatchers)
        {
            recoveredEdges += dispatcher.RecoveredEdges.size();
        }

        facts.Facts.push_back(
            "obfuscation facts: dispatchers="
            + std::to_string(facts.Obfuscation.Dispatchers.size())
            + ", state_variables="
            + std::to_string(facts.Obfuscation.StateVariables.size())
            + ", recovered_edges="
            + std::to_string(recoveredEdges)
            + ", opaque_predicates="
            + std::to_string(facts.Obfuscation.OpaquePredicates.size())
            + ", substitution_idioms="
            + std::to_string(facts.Obfuscation.SubstitutionIdioms.size()));
    }

    if (!facts.SemanticControlFlow.Edges.empty())
    {
        size_t liveEdges = 0;
        size_t deadEdges = 0;

        for (const SemanticControlFlowEdge& edge : facts.SemanticControlFlow.Edges)
        {
            if (edge.Dead)
            {
                ++deadEdges;
            }
            else
            {
                ++liveEdges;
            }
        }

        facts.Facts.push_back(
            "semantic control-flow overlay: live_edges="
            + std::to_string(liveEdges)
            + ", dead_edges="
            + std::to_string(deadEdges));
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
    RefreshEvidenceGraph(facts);

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
