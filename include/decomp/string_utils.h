#pragma once

#include <algorithm>
#include <chrono>
#include <cctype>
#include <exception>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace decomp
{
inline std::string TrimCopy(const std::string& value)
{
    size_t start = 0;
    size_t end = value.size();

    while (start < end && std::isspace(static_cast<unsigned char>(value[start])) != 0)
    {
        ++start;
    }

    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0)
    {
        --end;
    }

    return value.substr(start, end - start);
}

inline std::string ToLowerAscii(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char ch)
        {
            return static_cast<char>(std::tolower(ch));
        });

    return value;
}

inline bool StartsWithInsensitive(const std::string& value, const std::string& prefix)
{
    if (value.size() < prefix.size())
    {
        return false;
    }

    return ToLowerAscii(value.substr(0, prefix.size())) == ToLowerAscii(prefix);
}

inline bool ContainsInsensitive(const std::string& value, const std::string& needle)
{
    return ToLowerAscii(value).find(ToLowerAscii(needle)) != std::string::npos;
}

inline std::string HexU64(uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << value;
    return stream.str();
}

inline std::string HexS64(int64_t value)
{
    std::ostringstream stream;

    if (value < 0)
    {
        const uint64_t magnitude = static_cast<uint64_t>(-(value + 1)) + 1ULL;
        stream << "-0x" << std::hex << std::uppercase << magnitude;
    }
    else
    {
        stream << "0x" << std::hex << std::uppercase << static_cast<uint64_t>(value);
    }

    return stream.str();
}

inline double Clamp01(double value)
{
    if (value < 0.0)
    {
        return 0.0;
    }

    if (value > 1.0)
    {
        return 1.0;
    }

    return value;
}

inline std::string JoinStrings(const std::vector<std::string>& values, const std::string& separator)
{
    std::ostringstream stream;

    for (size_t index = 0; index < values.size(); ++index)
    {
        if (index != 0)
        {
            stream << separator;
        }

        stream << values[index];
    }

    return stream.str();
}

inline std::vector<std::string> TokenizeCommandLine(const std::string& input)
{
    std::vector<std::string> tokens;
    std::string current;
    bool inQuote = false;

    for (const char ch : input)
    {
        if (ch == '"')
        {
            inQuote = !inQuote;
            continue;
        }

        if (!inQuote && std::isspace(static_cast<unsigned char>(ch)) != 0)
        {
            if (!current.empty())
            {
                tokens.push_back(current);
                current.clear();
            }

            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty())
    {
        tokens.push_back(current);
    }

    return tokens;
}

inline bool TryParseUnsigned(const std::string& text, uint64_t& value)
{
    bool success = false;
    std::string clean = TrimCopy(text);

    do
    {
        if (clean.empty())
        {
            break;
        }

        clean.erase(
            std::remove(clean.begin(), clean.end(), '`'),
            clean.end());

        int base = 10;

        if (StartsWithInsensitive(clean, "0x"))
        {
            base = 16;
            clean = clean.substr(2);
        }
        else if (!clean.empty() && (clean.back() == 'h' || clean.back() == 'H'))
        {
            base = 16;
            clean.pop_back();
        }
        else
        {
            const bool looksHex = std::all_of(
                clean.begin(),
                clean.end(),
                [](const unsigned char ch)
                {
                    return std::isxdigit(ch) != 0;
                });

            if (looksHex && clean.size() > 8)
            {
                base = 16;
            }
        }

        if (clean.empty())
        {
            break;
        }

        try
        {
            size_t consumed = 0;
            value = std::stoull(clean, &consumed, base);
            success = (consumed == clean.size());
        }
        catch (const std::exception&)
        {
            success = false;
        }
    }
    while (false);

    return success;
}

inline std::string StripCodeFences(const std::string& input)
{
    const std::string trimmed = TrimCopy(input);

    if (!StartsWithInsensitive(trimmed, "```"))
    {
        return trimmed;
    }

    const size_t firstNewLine = trimmed.find('\n');
    const size_t lastFence = trimmed.rfind("```");

    if (firstNewLine == std::string::npos || lastFence == std::string::npos || lastFence <= firstNewLine)
    {
        return trimmed;
    }

    return TrimCopy(trimmed.substr(firstNewLine + 1, lastFence - firstNewLine - 1));
}

inline std::string MakeRequestId()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::ostringstream stream;
    stream << std::hex << std::uppercase << static_cast<uint64_t>(now);
    return stream.str();
}
}


