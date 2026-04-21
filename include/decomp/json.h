#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace decomp
{
class JsonValue
{
public:
    enum class Type
    {
        Null,
        Boolean,
        Number,
        String,
        Array,
        Object
    };

    JsonValue();

    static JsonValue MakeNull();
    static JsonValue MakeBoolean(bool value);
    static JsonValue MakeNumber(double value);
    static JsonValue MakeString(const std::string& value);
    static JsonValue MakeArray();
    static JsonValue MakeObject();

    Type GetType() const;
    bool IsNull() const;
    bool IsBoolean() const;
    bool IsNumber() const;
    bool IsString() const;
    bool IsArray() const;
    bool IsObject() const;

    bool GetBoolean() const;
    double GetNumber() const;
    const std::string& GetString() const;
    const std::vector<JsonValue>& GetArray() const;
    const std::map<std::string, JsonValue>& GetObject() const;
    std::vector<JsonValue>& GetArray();
    std::map<std::string, JsonValue>& GetObject();

    void PushBack(const JsonValue& value);
    void Set(const std::string& key, const JsonValue& value);
    const JsonValue* Find(const std::string& key) const;

private:
    Type Type_ = Type::Null;
    bool BooleanValue_ = false;
    double NumberValue_ = 0.0;
    std::string StringValue_;
    std::vector<JsonValue> ArrayValue_;
    std::map<std::string, JsonValue> ObjectValue_;
};

struct JsonParseResult
{
    bool Success = false;
    JsonValue Value;
    std::string Error;
};

JsonParseResult ParseJson(const std::string& text);
std::string SerializeJson(const JsonValue& value, bool pretty = false, size_t indent = 0);
std::string EscapeJsonString(const std::string& value);
}
