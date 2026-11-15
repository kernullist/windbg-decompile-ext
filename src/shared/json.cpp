#include "decomp/json.h"

#include <cmath>
#include <iomanip>
#include <sstream>

#define LLM_JSON_IMPLEMENTATION
#include "llm_json.hpp"

namespace decomp
{
namespace
{
// llm_json decodes a \uD83D\uDE00 escape pair as two separate 3-byte sequences.
// Join such pairs into the 4-byte UTF-8 encoding of the real code point.
std::string JoinUtf8SurrogatePairs(const std::string& text)
{
    if (text.find('\xED') == std::string::npos)
    {
        return text;
    }

    std::string result;
    result.reserve(text.size());

    for (size_t index = 0; index < text.size();)
    {
        const auto byteAt = [&text](size_t offset)
        {
            return static_cast<unsigned char>(text[offset]);
        };

        if (index + 6 <= text.size()
            && byteAt(index) == 0xED && (byteAt(index + 1) & 0xF0) == 0xA0
            && byteAt(index + 3) == 0xED && (byteAt(index + 4) & 0xF0) == 0xB0)
        {
            const unsigned high = ((byteAt(index + 1) & 0x0F) << 6) | (byteAt(index + 2) & 0x3F);
            const unsigned low = ((byteAt(index + 4) & 0x0F) << 6) | (byteAt(index + 5) & 0x3F);
            const unsigned codePoint = 0x10000 + (high << 10) + low;

            result += static_cast<char>(0xF0 | (codePoint >> 18));
            result += static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F));
            result += static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (codePoint & 0x3F));
            index += 6;
            continue;
        }

        result += text[index++];
    }

    return result;
}

JsonValue ConvertValue(const llm::json::Value& value)
{
    switch (value.type())
    {
    case llm::json::Value::Type::Bool:
        return JsonValue::MakeBoolean(value.as_bool());
    case llm::json::Value::Type::Int:
    case llm::json::Value::Type::Float:
        return JsonValue::MakeNumber(value.as_number());
    case llm::json::Value::Type::String:
        return JsonValue::MakeString(JoinUtf8SurrogatePairs(value.as_string()));
    case llm::json::Value::Type::Array:
        {
            JsonValue array = JsonValue::MakeArray();

            for (const llm::json::Value& item : value)
            {
                array.PushBack(ConvertValue(item));
            }

            return array;
        }
    case llm::json::Value::Type::Object:
        {
            JsonValue object = JsonValue::MakeObject();

            for (const std::string& key : value.keys())
            {
                object.Set(JoinUtf8SurrogatePairs(key), ConvertValue(value[key]));
            }

            return object;
        }
    default:
        return JsonValue::MakeNull();
    }
}

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
    JsonParseResult result;
    const llm::json::ParseResult parsed = llm::json::try_parse(text);

    if (!parsed.ok)
    {
        result.Error = parsed.error;
        return result;
    }

    result.Value = ConvertValue(parsed.value);
    result.Success = true;
    return result;
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

