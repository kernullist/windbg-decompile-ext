#include "decomp/json.h"

#include <cctype>
#include <cmath>
#include <exception>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace decomp
{
namespace
{
class JsonParser
{
public:
    explicit JsonParser(const std::string& text)
        : Text_(text)
    {
    }

    JsonParseResult Parse()
    {
        JsonParseResult result;

        do
        {
            SkipWhitespace();
            result.Value = ParseValue();
            SkipWhitespace();

            if (!Error_.empty())
            {
                break;
            }

            if (Position_ != Text_.size())
            {
                Error_ = "unexpected trailing input";
                break;
            }

            result.Success = true;
        }
        while (false);

        result.Error = Error_;
        return result;
    }

private:
    JsonValue ParseValue()
    {
        SkipWhitespace();

        if (Position_ >= Text_.size())
        {
            Error_ = "unexpected end of input";
            return JsonValue::MakeNull();
        }

        const char ch = Text_[Position_];

        if (ch == 'n')
        {
            return ParseNull();
        }

        if (ch == 't' || ch == 'f')
        {
            return ParseBoolean();
        }

        if (ch == '"')
        {
            return JsonValue::MakeString(ParseString());
        }

        if (ch == '[')
        {
            return ParseArray();
        }

        if (ch == '{')
        {
            return ParseObject();
        }

        if (ch == '-' || std::isdigit(static_cast<unsigned char>(ch)) != 0)
        {
            return ParseNumber();
        }

        Error_ = "unexpected token";
        return JsonValue::MakeNull();
    }

    JsonValue ParseNull()
    {
        if (Text_.compare(Position_, 4, "null") != 0)
        {
            Error_ = "invalid null literal";
            return JsonValue::MakeNull();
        }

        Position_ += 4;
        return JsonValue::MakeNull();
    }

    JsonValue ParseBoolean()
    {
        if (Text_.compare(Position_, 4, "true") == 0)
        {
            Position_ += 4;
            return JsonValue::MakeBoolean(true);
        }

        if (Text_.compare(Position_, 5, "false") == 0)
        {
            Position_ += 5;
            return JsonValue::MakeBoolean(false);
        }

        Error_ = "invalid boolean literal";
        return JsonValue::MakeNull();
    }

    JsonValue ParseNumber()
    {
        const size_t start = Position_;

        if (Text_[Position_] == '-')
        {
            ++Position_;
        }

        while (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_])) != 0)
        {
            ++Position_;
        }

        if (Position_ < Text_.size() && Text_[Position_] == '.')
        {
            ++Position_;

            while (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_])) != 0)
            {
                ++Position_;
            }
        }

        if (Position_ < Text_.size() && (Text_[Position_] == 'e' || Text_[Position_] == 'E'))
        {
            ++Position_;

            if (Position_ < Text_.size() && (Text_[Position_] == '+' || Text_[Position_] == '-'))
            {
                ++Position_;
            }

            while (Position_ < Text_.size() && std::isdigit(static_cast<unsigned char>(Text_[Position_])) != 0)
            {
                ++Position_;
            }
        }

        try
        {
            return JsonValue::MakeNumber(std::stod(Text_.substr(start, Position_ - start)));
        }
        catch (const std::exception&)
        {
            Error_ = "invalid number literal";
            return JsonValue::MakeNull();
        }
    }

    std::string ParseString()
    {
        std::ostringstream stream;

        if (Text_[Position_] != '"')
        {
            Error_ = "expected string";
            return std::string();
        }

        ++Position_;

        while (Position_ < Text_.size())
        {
            const char ch = Text_[Position_++];

            if (ch == '"')
            {
                return stream.str();
            }

            if (ch != '\\')
            {
                stream << ch;
                continue;
            }

            if (Position_ >= Text_.size())
            {
                Error_ = "invalid string escape";
                return std::string();
            }

            const char escaped = Text_[Position_++];

            switch (escaped)
            {
            case '"':
                stream << '"';
                break;
            case '\\':
                stream << '\\';
                break;
            case '/':
                stream << '/';
                break;
            case 'b':
                stream << '\b';
                break;
            case 'f':
                stream << '\f';
                break;
            case 'n':
                stream << '\n';
                break;
            case 'r':
                stream << '\r';
                break;
            case 't':
                stream << '\t';
                break;
            case 'u':
                if (Position_ + 4 > Text_.size())
                {
                    Error_ = "invalid unicode escape";
                    return std::string();
                }
                Position_ += 4;
                stream << '?';
                break;
            default:
                Error_ = "invalid string escape";
                return std::string();
            }
        }

        Error_ = "unterminated string";
        return std::string();
    }

    JsonValue ParseArray()
    {
        JsonValue array = JsonValue::MakeArray();
        ++Position_;
        SkipWhitespace();

        if (Position_ < Text_.size() && Text_[Position_] == ']')
        {
            ++Position_;
            return array;
        }

        while (Position_ < Text_.size())
        {
            array.PushBack(ParseValue());
            SkipWhitespace();

            if (!Error_.empty())
            {
                return JsonValue::MakeNull();
            }

            if (Position_ < Text_.size() && Text_[Position_] == ',')
            {
                ++Position_;
                SkipWhitespace();
                continue;
            }

            if (Position_ < Text_.size() && Text_[Position_] == ']')
            {
                ++Position_;
                return array;
            }

            Error_ = "expected array delimiter";
            return JsonValue::MakeNull();
        }

        Error_ = "unterminated array";
        return JsonValue::MakeNull();
    }

    JsonValue ParseObject()
    {
        JsonValue object = JsonValue::MakeObject();
        ++Position_;
        SkipWhitespace();

        if (Position_ < Text_.size() && Text_[Position_] == '}')
        {
            ++Position_;
            return object;
        }

        while (Position_ < Text_.size())
        {
            if (Text_[Position_] != '"')
            {
                Error_ = "expected object key";
                return JsonValue::MakeNull();
            }

            const std::string key = ParseString();
            SkipWhitespace();

            if (!Error_.empty())
            {
                return JsonValue::MakeNull();
            }

            if (Position_ >= Text_.size() || Text_[Position_] != ':')
            {
                Error_ = "expected key separator";
                return JsonValue::MakeNull();
            }

            ++Position_;
            SkipWhitespace();
            object.Set(key, ParseValue());
            SkipWhitespace();

            if (!Error_.empty())
            {
                return JsonValue::MakeNull();
            }

            if (Position_ < Text_.size() && Text_[Position_] == ',')
            {
                ++Position_;
                SkipWhitespace();
                continue;
            }

            if (Position_ < Text_.size() && Text_[Position_] == '}')
            {
                ++Position_;
                return object;
            }

            Error_ = "expected object delimiter";
            return JsonValue::MakeNull();
        }

        Error_ = "unterminated object";
        return JsonValue::MakeNull();
    }

    void SkipWhitespace()
    {
        while (Position_ < Text_.size() && std::isspace(static_cast<unsigned char>(Text_[Position_])) != 0)
        {
            ++Position_;
        }
    }

    const std::string& Text_;
    size_t Position_ = 0;
    std::string Error_;
};

std::string MakeIndent(size_t indent)
{
    return std::string(indent, ' ');
}
}

JsonValue::JsonValue() = default;

JsonValue JsonValue::MakeNull()
{
    return JsonValue();
}

JsonValue JsonValue::MakeBoolean(bool value)
{
    JsonValue json;
    json.Type_ = Type::Boolean;
    json.BooleanValue_ = value;
    return json;
}

JsonValue JsonValue::MakeNumber(double value)
{
    JsonValue json;
    json.Type_ = Type::Number;
    json.NumberValue_ = value;
    return json;
}

JsonValue JsonValue::MakeString(const std::string& value)
{
    JsonValue json;
    json.Type_ = Type::String;
    json.StringValue_ = value;
    return json;
}

JsonValue JsonValue::MakeArray()
{
    JsonValue json;
    json.Type_ = Type::Array;
    return json;
}

JsonValue JsonValue::MakeObject()
{
    JsonValue json;
    json.Type_ = Type::Object;
    return json;
}

JsonValue::Type JsonValue::GetType() const
{
    return Type_;
}

bool JsonValue::IsNull() const
{
    return Type_ == Type::Null;
}

bool JsonValue::IsBoolean() const
{
    return Type_ == Type::Boolean;
}

bool JsonValue::IsNumber() const
{
    return Type_ == Type::Number;
}

bool JsonValue::IsString() const
{
    return Type_ == Type::String;
}

bool JsonValue::IsArray() const
{
    return Type_ == Type::Array;
}

bool JsonValue::IsObject() const
{
    return Type_ == Type::Object;
}

bool JsonValue::GetBoolean() const
{
    return BooleanValue_;
}

double JsonValue::GetNumber() const
{
    return NumberValue_;
}

const std::string& JsonValue::GetString() const
{
    return StringValue_;
}

const std::vector<JsonValue>& JsonValue::GetArray() const
{
    return ArrayValue_;
}

const std::map<std::string, JsonValue>& JsonValue::GetObject() const
{
    return ObjectValue_;
}

std::vector<JsonValue>& JsonValue::GetArray()
{
    return ArrayValue_;
}

std::map<std::string, JsonValue>& JsonValue::GetObject()
{
    return ObjectValue_;
}

void JsonValue::PushBack(const JsonValue& value)
{
    if (Type_ != Type::Array)
    {
        Type_ = Type::Array;
        ArrayValue_.clear();
    }

    ArrayValue_.push_back(value);
}

void JsonValue::Set(const std::string& key, const JsonValue& value)
{
    if (Type_ != Type::Object)
    {
        Type_ = Type::Object;
        ObjectValue_.clear();
    }

    ObjectValue_[key] = value;
}

const JsonValue* JsonValue::Find(const std::string& key) const
{
    const auto iterator = ObjectValue_.find(key);

    if (iterator == ObjectValue_.end())
    {
        return nullptr;
    }

    return &iterator->second;
}

JsonParseResult ParseJson(const std::string& text)
{
    JsonParser parser(text);
    return parser.Parse();
}

std::string EscapeJsonString(const std::string& value)
{
    std::ostringstream stream;

    for (const char ch : value)
    {
        switch (ch)
        {
        case '"':
            stream << "\\\"";
            break;
        case '\\':
            stream << "\\\\";
            break;
        case '\b':
            stream << "\\b";
            break;
        case '\f':
            stream << "\\f";
            break;
        case '\n':
            stream << "\\n";
            break;
        case '\r':
            stream << "\\r";
            break;
        case '\t':
            stream << "\\t";
            break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20)
            {
                stream << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(ch));
            }
            else
            {
                stream << ch;
            }
            break;
        }
    }

    return stream.str();
}

std::string SerializeJson(const JsonValue& value, bool pretty, size_t indent)
{
    std::ostringstream stream;

    switch (value.GetType())
    {
    case JsonValue::Type::Null:
        stream << "null";
        break;
    case JsonValue::Type::Boolean:
        stream << (value.GetBoolean() ? "true" : "false");
        break;
    case JsonValue::Type::Number:
        if (std::isfinite(value.GetNumber()) != 0)
        {
            stream << std::setprecision(15) << value.GetNumber();
        }
        else
        {
            stream << "0";
        }
        break;
    case JsonValue::Type::String:
        stream << '"' << EscapeJsonString(value.GetString()) << '"';
        break;
    case JsonValue::Type::Array:
        {
            stream << '[';
            const auto& array = value.GetArray();

            for (size_t index = 0; index < array.size(); ++index)
            {
                if (index != 0)
                {
                    stream << ',';
                }

                if (pretty)
                {
                    stream << '\n' << MakeIndent(indent + 2);
                }

                stream << SerializeJson(array[index], pretty, indent + 2);
            }

            if (pretty && !array.empty())
            {
                stream << '\n' << MakeIndent(indent);
            }

            stream << ']';
        }
        break;
    case JsonValue::Type::Object:
        {
            stream << '{';
            const auto& object = value.GetObject();
            size_t index = 0;

            for (const auto& entry : object)
            {
                if (index != 0)
                {
                    stream << ',';
                }

                if (pretty)
                {
                    stream << '\n' << MakeIndent(indent + 2);
                }

                stream << '"' << EscapeJsonString(entry.first) << '"' << ':';

                if (pretty)
                {
                    stream << ' ';
                }

                stream << SerializeJson(entry.second, pretty, indent + 2);
                ++index;
            }

            if (pretty && !object.empty())
            {
                stream << '\n' << MakeIndent(indent);
            }

            stream << '}';
        }
        break;
    }

    return stream.str();
}
}

