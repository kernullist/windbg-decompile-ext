#include "decomp/pseudo_tokens.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>
#include <utility>

#include "decomp/string_utils.h"

namespace decomp
{
namespace
{
bool IsHorizontalWhitespace(const char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\f' || ch == '\v';
}

bool IsIdentifierStart(const char ch)
{
    return std::isalpha(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

bool IsIdentifierContinue(const char ch)
{
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

bool StartsWithAt(const std::string& text, size_t offset, std::string_view prefix)
{
    return offset + prefix.size() <= text.size()
        && std::equal(prefix.begin(), prefix.end(), text.begin() + static_cast<std::ptrdiff_t>(offset));
}

bool ContainsWord(std::string_view value, const std::array<const char*, 33>& words)
{
    return std::find_if(
               words.begin(),
               words.end(),
               [value](const char* entry)
               {
                   return value == entry;
               })
        != words.end();
}

bool ContainsWord(std::string_view value, const std::array<const char*, 23>& words)
{
    return std::find_if(
               words.begin(),
               words.end(),
               [value](const char* entry)
               {
                   return value == entry;
               })
        != words.end();
}

std::string ClassifyIdentifier(std::string_view identifier)
{
    static const std::array<const char*, 33> kKeywords = {
        "if", "else", "switch", "case", "default", "for", "while", "do", "break",
        "continue", "return", "goto", "sizeof", "alignof", "try", "catch", "throw",
        "class", "namespace", "template", "typename", "using", "public", "private",
        "protected", "virtual", "override", "final", "static_assert", "true", "false",
        "nullptr", "NULL"
    };
    static const std::array<const char*, 23> kTypes = {
        "void", "char", "short", "int", "long", "float", "double", "signed",
        "unsigned", "bool", "size_t", "ssize_t", "uintptr_t", "intptr_t",
        "ptrdiff_t", "wchar_t", "struct", "union", "enum", "const", "volatile",
        "UNKNOWN_TYPE", "decltype"
    };

    if (ContainsWord(identifier, kKeywords))
    {
        return "keyword";
    }

    if (ContainsWord(identifier, kTypes))
    {
        return "type";
    }

    return "identifier";
}

size_t SkipHorizontalWhitespace(const std::string& source, size_t offset)
{
    while (offset < source.size() && IsHorizontalWhitespace(source[offset]))
    {
        ++offset;
    }

    return offset;
}

bool IsFunctionLikeIdentifier(const std::string& source, size_t identifierEnd)
{
    const size_t next = SkipHorizontalWhitespace(source, identifierEnd);
    return next < source.size() && source[next] == '(';
}

void PushToken(
    const std::string& source,
    size_t start,
    size_t end,
    const char* kind,
    std::vector<PseudoCodeToken>& tokens)
{
    if (end <= start)
    {
        return;
    }

    PseudoCodeToken token;
    token.Kind = kind;
    token.Text = source.substr(start, end - start);
    tokens.push_back(std::move(token));
}

size_t ConsumeNewline(const std::string& source, size_t offset)
{
    if (source[offset] == '\r' && offset + 1 < source.size() && source[offset + 1] == '\n')
    {
        return offset + 2;
    }

    return offset + 1;
}

size_t ConsumeLineComment(const std::string& source, size_t offset)
{
    size_t end = offset + 2;

    while (end < source.size() && source[end] != '\r' && source[end] != '\n')
    {
        ++end;
    }

    return end;
}

size_t ConsumeBlockComment(const std::string& source, size_t offset)
{
    size_t end = offset + 2;

    while (end + 1 < source.size())
    {
        if (source[end] == '*' && source[end + 1] == '/')
        {
            return end + 2;
        }

        ++end;
    }

    return source.size();
}

size_t ConsumeQuotedLiteral(const std::string& source, size_t offset, char delimiter)
{
    size_t end = offset + 1;
    bool escaping = false;

    while (end < source.size())
    {
        const char ch = source[end];

        if (escaping)
        {
            escaping = false;
            ++end;
            continue;
        }

        if (ch == '\\')
        {
            escaping = true;
            ++end;
            continue;
        }

        ++end;

        if (ch == delimiter)
        {
            break;
        }

        if (ch == '\r' || ch == '\n')
        {
            break;
        }
    }

    return end;
}

size_t ConsumePreprocessorLine(const std::string& source, size_t offset)
{
    size_t end = offset;

    for (;;)
    {
        while (end < source.size() && source[end] != '\r' && source[end] != '\n')
        {
            ++end;
        }

        if (end == source.size() || end == offset)
        {
            return end;
        }

        size_t slash = end;

        while (slash > offset && (source[slash - 1] == ' ' || source[slash - 1] == '\t'))
        {
            --slash;
        }

        if (slash == offset || source[slash - 1] != '\\')
        {
            return end;
        }

        end = ConsumeNewline(source, end);
    }
}

size_t ConsumeIdentifier(const std::string& source, size_t offset)
{
    size_t end = offset + 1;

    while (end < source.size() && IsIdentifierContinue(source[end]))
    {
        ++end;
    }

    return end;
}

size_t ConsumeNumber(const std::string& source, size_t offset)
{
    size_t end = offset;

    if (source[end] == '0'
        && end + 1 < source.size()
        && (source[end + 1] == 'x' || source[end + 1] == 'X'))
    {
        end += 2;

        while (end < source.size() && std::isxdigit(static_cast<unsigned char>(source[end])) != 0)
        {
            ++end;
        }

        if (end < source.size() && source[end] == '.')
        {
            ++end;

            while (end < source.size() && std::isxdigit(static_cast<unsigned char>(source[end])) != 0)
            {
                ++end;
            }
        }

        if (end < source.size() && (source[end] == 'p' || source[end] == 'P'))
        {
            ++end;

            if (end < source.size() && (source[end] == '+' || source[end] == '-'))
            {
                ++end;
            }

            while (end < source.size() && std::isdigit(static_cast<unsigned char>(source[end])) != 0)
            {
                ++end;
            }
        }
    }
    else
    {
        while (end < source.size() && std::isdigit(static_cast<unsigned char>(source[end])) != 0)
        {
            ++end;
        }

        if (end < source.size() && source[end] == '.')
        {
            ++end;

            while (end < source.size() && std::isdigit(static_cast<unsigned char>(source[end])) != 0)
            {
                ++end;
            }
        }

        if (end < source.size() && (source[end] == 'e' || source[end] == 'E'))
        {
            const size_t exponentStart = end;
            ++end;

            if (end < source.size() && (source[end] == '+' || source[end] == '-'))
            {
                ++end;
            }

            const size_t exponentDigits = end;

            while (end < source.size() && std::isdigit(static_cast<unsigned char>(source[end])) != 0)
            {
                ++end;
            }

            if (end == exponentDigits)
            {
                end = exponentStart;
            }
        }
    }

    while (end < source.size() && std::isalpha(static_cast<unsigned char>(source[end])) != 0)
    {
        ++end;
    }

    return end;
}

size_t MatchOperatorLength(const std::string& source, size_t offset)
{
    static const std::array<std::string_view, 24> kOperators = {
        "<<=", ">>=", "->*", "->", "++", "--", "==", "!=", "<=", ">=",
        "&&", "||", "<<", ">>", "+=", "-=", "*=", "/=", "%=", "&=",
        "|=", "^=", "::", ".*"
    };

    for (const std::string_view value : kOperators)
    {
        if (StartsWithAt(source, offset, value))
        {
            return value.size();
        }
    }

    return 0;
}

bool IsPunctuation(const char ch)
{
    return ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == '[' || ch == ']'
        || ch == ';' || ch == ',' || ch == '.';
}

bool IsOperatorChar(const char ch)
{
    return ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '%'
        || ch == '=' || ch == '&' || ch == '|' || ch == '^' || ch == '~'
        || ch == '!' || ch == '<' || ch == '>' || ch == '?' || ch == ':';
}
}

std::vector<PseudoCodeToken> TokenizePseudoCode(const std::string& pseudoCode)
{
    std::vector<PseudoCodeToken> tokens;
    bool onlyIndentationSinceLineStart = true;

    for (size_t index = 0; index < pseudoCode.size();)
    {
        const char ch = pseudoCode[index];

        if (ch == '\r' || ch == '\n')
        {
            const size_t next = ConsumeNewline(pseudoCode, index);
            PushToken(pseudoCode, index, next, "newline", tokens);
            onlyIndentationSinceLineStart = true;
            index = next;
            continue;
        }

        if (IsHorizontalWhitespace(ch))
        {
            size_t next = index + 1;

            while (next < pseudoCode.size() && IsHorizontalWhitespace(pseudoCode[next]))
            {
                ++next;
            }

            PushToken(pseudoCode, index, next, "whitespace", tokens);
            index = next;
            continue;
        }

        if (ch == '#' && onlyIndentationSinceLineStart)
        {
            const size_t next = ConsumePreprocessorLine(pseudoCode, index);
            PushToken(pseudoCode, index, next, "preprocessor", tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        if (StartsWithAt(pseudoCode, index, "//"))
        {
            const size_t next = ConsumeLineComment(pseudoCode, index);
            PushToken(pseudoCode, index, next, "comment", tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        if (StartsWithAt(pseudoCode, index, "/*"))
        {
            const size_t next = ConsumeBlockComment(pseudoCode, index);
            PushToken(pseudoCode, index, next, "comment", tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        if (ch == '"')
        {
            const size_t next = ConsumeQuotedLiteral(pseudoCode, index, '"');
            PushToken(pseudoCode, index, next, "string", tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        if (ch == '\'')
        {
            const size_t next = ConsumeQuotedLiteral(pseudoCode, index, '\'');
            PushToken(pseudoCode, index, next, "char", tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        if (IsIdentifierStart(ch))
        {
            const size_t next = ConsumeIdentifier(pseudoCode, index);
            const std::string_view identifier(pseudoCode.data() + index, next - index);
            std::string kind = ClassifyIdentifier(identifier);

            if (kind == "identifier" && IsFunctionLikeIdentifier(pseudoCode, next))
            {
                kind = "function_name";
            }

            PushToken(pseudoCode, index, next, kind.c_str(), tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        if (std::isdigit(static_cast<unsigned char>(ch)) != 0
            || (ch == '.' && index + 1 < pseudoCode.size() && std::isdigit(static_cast<unsigned char>(pseudoCode[index + 1])) != 0))
        {
            const size_t next = ConsumeNumber(pseudoCode, index);
            PushToken(pseudoCode, index, next, "number", tokens);
            onlyIndentationSinceLineStart = false;
            index = next;
            continue;
        }

        const size_t operatorLength = MatchOperatorLength(pseudoCode, index);

        if (operatorLength != 0)
        {
            PushToken(pseudoCode, index, index + operatorLength, "operator", tokens);
            onlyIndentationSinceLineStart = false;
            index += operatorLength;
            continue;
        }

        if (IsPunctuation(ch))
        {
            PushToken(pseudoCode, index, index + 1, "punctuation", tokens);
            onlyIndentationSinceLineStart = false;
            ++index;
            continue;
        }

        if (IsOperatorChar(ch))
        {
            PushToken(pseudoCode, index, index + 1, "operator", tokens);
            onlyIndentationSinceLineStart = false;
            ++index;
            continue;
        }

        PushToken(pseudoCode, index, index + 1, "unknown", tokens);
        onlyIndentationSinceLineStart = false;
        ++index;
    }

    return tokens;
}

void EnsurePseudoCodeTokens(AnalyzeResponse& response)
{
    if (!response.PseudoC.empty() && response.PseudoCTokens.empty())
    {
        response.PseudoCTokens = TokenizePseudoCode(response.PseudoC);
    }
}
}
