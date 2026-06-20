#pragma once

#include "decomp/json.h"
#include "decomp/types.h"

#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <string>
#include <vector>

namespace
{
int g_failures = 0;

void Expect(bool condition, const std::string& message)
{
    if (!condition)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << "\n";
    }
}

bool ContainsString(const std::vector<std::string>& values, const std::string& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

const decomp::JsonValue* FindJsonPath(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path)
{
    const decomp::JsonValue* value = &root;

    for (const std::string& segment : path)
    {
        if (value == nullptr || !value->IsObject())
        {
            return nullptr;
        }

        value = value->Find(segment);
    }

    return value;
}

const decomp::JsonValue* ExpectJsonObjectPath(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    const std::string& message)
{
    const decomp::JsonValue* value = FindJsonPath(root, path);
    Expect(value != nullptr && value->IsObject(), message);

    if (value == nullptr || !value->IsObject())
    {
        return nullptr;
    }

    return value;
}

const decomp::JsonValue* ExpectJsonArrayPath(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    const std::string& message)
{
    const decomp::JsonValue* value = FindJsonPath(root, path);
    Expect(value != nullptr && value->IsArray(), message);

    if (value == nullptr || !value->IsArray())
    {
        return nullptr;
    }

    return value;
}

const decomp::JsonValue* ExpectJsonBooleanPath(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    const std::string& message)
{
    const decomp::JsonValue* value = FindJsonPath(root, path);
    Expect(value != nullptr && value->IsBoolean(), message);

    if (value == nullptr || !value->IsBoolean())
    {
        return nullptr;
    }

    return value;
}

const decomp::JsonValue* ExpectJsonNumberPath(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    const std::string& message)
{
    const decomp::JsonValue* value = FindJsonPath(root, path);
    Expect(value != nullptr && value->IsNumber(), message);

    if (value == nullptr || !value->IsNumber())
    {
        return nullptr;
    }

    return value;
}

bool JsonStringArrayContains(const decomp::JsonValue* value, const std::string& expected)
{
    if (value == nullptr || !value->IsArray())
    {
        return false;
    }

    for (const decomp::JsonValue& item : value->GetArray())
    {
        if (item.IsString() && item.GetString() == expected)
        {
            return true;
        }
    }

    return false;
}

void ExpectJsonBooleanValue(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    bool expected,
    const std::string& message)
{
    const decomp::JsonValue* value = ExpectJsonBooleanPath(root, path, message + " should be boolean");
    Expect(value != nullptr && value->GetBoolean() == expected, message);
}

void ExpectJsonNumberAtMost(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    double maximum,
    const std::string& message)
{
    const decomp::JsonValue* value = ExpectJsonNumberPath(root, path, message + " should be numeric");
    Expect(value != nullptr && value->GetNumber() <= maximum, message);
}

void ExpectJsonStringArrayContains(
    const decomp::JsonValue& root,
    std::initializer_list<std::string> path,
    const std::string& expected,
    const std::string& message)
{
    const decomp::JsonValue* value = ExpectJsonArrayPath(root, path, message + " should be an array");
    Expect(JsonStringArrayContains(value, expected), message);
}

decomp::JsonValue ParseDebugMergeFactsJson(const std::string& mergePromptDump)
{
    const std::string marker = "merge_facts_json:\n";
    const size_t markerOffset = mergePromptDump.find(marker);
    Expect(markerOffset != std::string::npos, "debug merge prompt dump should include merge facts JSON marker");

    if (markerOffset == std::string::npos)
    {
        return decomp::JsonValue::MakeObject();
    }

    const std::string factsJson = mergePromptDump.substr(markerOffset + marker.size());
    const decomp::JsonParseResult parsed = decomp::ParseJson(factsJson);
    Expect(parsed.Success, "debug merge facts JSON should parse: " + parsed.Error);
    Expect(parsed.Value.IsObject(), "debug merge facts JSON should be an object");

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        return decomp::JsonValue::MakeObject();
    }

    return parsed.Value;
}

bool ContainsFactSubstring(const decomp::AnalysisFacts& facts, const std::string& needle)
{
    for (const std::string& fact : facts.Facts)
    {
        if (fact.find(needle) != std::string::npos)
        {
            return true;
        }
    }

    return false;
}

bool HasIssueCode(const decomp::VerifyReport& report, const std::string& code)
{
    for (const decomp::VerificationIssue& issue : report.Issues)
    {
        if (issue.Code == code)
        {
            return true;
        }
    }

    return false;
}

bool IssueEvidenceContains(
    const decomp::VerifyReport& report,
    const std::string& code,
    const std::string& expected)
{
    for (const decomp::VerificationIssue& issue : report.Issues)
    {
        if (issue.Code == code && issue.Evidence.find(expected) != std::string::npos)
        {
            return true;
        }
    }

    return false;
}
}
