#include "decomp/protocol.h"

#include <cmath>

#include "decomp/pseudo_tokens.h"
#include "decomp/string_utils.h"

namespace decomp
{
namespace
{
JsonValue ToJson(const FunctionRegion& region)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("start", JsonValue::MakeString(HexU64(region.Start)));
    object.Set("end", JsonValue::MakeString(HexU64(region.End)));
    return object;
}

JsonValue ToJson(const ModuleInfo& module)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("image_name", JsonValue::MakeString(module.ImageName));
    object.Set("module_name", JsonValue::MakeString(module.ModuleName));
    object.Set("loaded_image_name", JsonValue::MakeString(module.LoadedImageName));
    object.Set("base", JsonValue::MakeString(HexU64(module.Base)));
    object.Set("size", JsonValue::MakeNumber(static_cast<double>(module.Size)));
    object.Set("symbol_type", JsonValue::MakeNumber(static_cast<double>(module.SymbolType)));
    return object;
}

JsonValue ToJson(const StackFrameFacts& stackFrame)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue saved = JsonValue::MakeArray();

    for (const auto& reg : stackFrame.SavedNonvolatile)
    {
        saved.PushBack(JsonValue::MakeString(reg));
    }

    object.Set("stack_alloc", JsonValue::MakeNumber(static_cast<double>(stackFrame.StackAlloc)));
    object.Set("saved_nonvolatile", saved);
    object.Set("uses_cookie", JsonValue::MakeBoolean(stackFrame.UsesCookie));
    object.Set("frame_pointer", JsonValue::MakeBoolean(stackFrame.FramePointer));
    return object;
}

JsonValue ToJson(const DisassembledInstruction& instruction)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("address", JsonValue::MakeString(HexU64(instruction.Address)));
    object.Set("end_address", JsonValue::MakeString(HexU64(instruction.EndAddress)));
    object.Set("text", JsonValue::MakeString(instruction.Text));
    object.Set("operation_text", JsonValue::MakeString(instruction.OperationText));
    object.Set("mnemonic", JsonValue::MakeString(instruction.Mnemonic));
    object.Set("operand_text", JsonValue::MakeString(instruction.OperandText));
    object.Set("is_conditional_branch", JsonValue::MakeBoolean(instruction.IsConditionalBranch));
    object.Set("is_unconditional_branch", JsonValue::MakeBoolean(instruction.IsUnconditionalBranch));
    object.Set("is_call", JsonValue::MakeBoolean(instruction.IsCall));
    object.Set("is_return", JsonValue::MakeBoolean(instruction.IsReturn));
    object.Set("is_indirect", JsonValue::MakeBoolean(instruction.IsIndirect));
    object.Set("branch_target", JsonValue::MakeString(HexU64(instruction.BranchTarget)));
    object.Set("has_branch_target", JsonValue::MakeBoolean(instruction.HasBranchTarget));
    return object;
}

JsonValue ToJson(const BasicBlock& block)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue instructionAddresses = JsonValue::MakeArray();
    JsonValue successors = JsonValue::MakeArray();

    for (const auto address : block.InstructionAddresses)
    {
        instructionAddresses.PushBack(JsonValue::MakeString(HexU64(address)));
    }

    for (const auto& successor : block.Successors)
    {
        successors.PushBack(JsonValue::MakeString(successor));
    }

    object.Set("id", JsonValue::MakeString(block.Id));
    object.Set("start_address", JsonValue::MakeString(HexU64(block.StartAddress)));
    object.Set("end_address", JsonValue::MakeString(HexU64(block.EndAddress)));
    object.Set("instruction_addresses", instructionAddresses);
    object.Set("successors", successors);
    object.Set("has_terminal", JsonValue::MakeBoolean(block.HasTerminal));
    return object;
}

JsonValue ToJson(const CallSite& call)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(call.Site)));
    object.Set("target", JsonValue::MakeString(call.Target));
    object.Set("kind", JsonValue::MakeString(call.Kind));
    object.Set("returns", JsonValue::MakeBoolean(call.Returns));
    return object;
}

JsonValue ToJson(const SwitchInfo& info)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(info.Site)));
    object.Set("case_count", JsonValue::MakeNumber(static_cast<double>(info.CaseCount)));
    object.Set("detail", JsonValue::MakeString(info.Detail));
    return object;
}

JsonValue ToJson(const MemoryAccess& access)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(access.Site)));
    object.Set("access", JsonValue::MakeString(access.Access));
    object.Set("kind", JsonValue::MakeString(access.Kind));
    object.Set("size", JsonValue::MakeString(access.Size));
    object.Set("width_bits", JsonValue::MakeNumber(static_cast<double>(access.WidthBits)));
    object.Set("base_register", JsonValue::MakeString(access.BaseRegister));
    object.Set("index_register", JsonValue::MakeString(access.IndexRegister));
    object.Set("scale", JsonValue::MakeNumber(static_cast<double>(access.Scale)));
    object.Set("displacement", JsonValue::MakeString(access.Displacement));
    object.Set("rip_relative", JsonValue::MakeBoolean(access.RipRelative));
    return object;
}

JsonValue ToJson(const RecoveredArgument& argument)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("name", JsonValue::MakeString(argument.Name));
    object.Set("register", JsonValue::MakeString(argument.Register));
    object.Set("type_hint", JsonValue::MakeString(argument.TypeHint));
    object.Set("role_hint", JsonValue::MakeString(argument.RoleHint));
    object.Set("first_use_site", JsonValue::MakeString(HexU64(argument.FirstUseSite)));
    object.Set("use_count", JsonValue::MakeNumber(static_cast<double>(argument.UseCount)));
    object.Set("confidence", JsonValue::MakeNumber(argument.Confidence));
    return object;
}

JsonValue ToJson(const RecoveredLocal& local)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("name", JsonValue::MakeString(local.Name));
    object.Set("base_register", JsonValue::MakeString(local.BaseRegister));
    object.Set("offset", JsonValue::MakeString(HexS64(local.Offset)));
    object.Set("storage", JsonValue::MakeString(local.Storage));
    object.Set("type_hint", JsonValue::MakeString(local.TypeHint));
    object.Set("role_hint", JsonValue::MakeString(local.RoleHint));
    object.Set("first_site", JsonValue::MakeString(HexU64(local.FirstSite)));
    object.Set("last_site", JsonValue::MakeString(HexU64(local.LastSite)));
    object.Set("read_count", JsonValue::MakeNumber(static_cast<double>(local.ReadCount)));
    object.Set("write_count", JsonValue::MakeNumber(static_cast<double>(local.WriteCount)));
    object.Set("confidence", JsonValue::MakeNumber(local.Confidence));
    return object;
}

JsonValue ToJson(const ValueMerge& merge)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue predecessors = JsonValue::MakeArray();
    JsonValue incomingValues = JsonValue::MakeArray();

    for (const auto& predecessor : merge.Predecessors)
    {
        predecessors.PushBack(JsonValue::MakeString(predecessor));
    }

    for (const auto& value : merge.IncomingValues)
    {
        incomingValues.PushBack(JsonValue::MakeString(value));
    }

    object.Set("block_id", JsonValue::MakeString(merge.BlockId));
    object.Set("variable", JsonValue::MakeString(merge.Variable));
    object.Set("predecessors", predecessors);
    object.Set("incoming_values", incomingValues);
    object.Set("confidence", JsonValue::MakeNumber(merge.Confidence));
    return object;
}

JsonValue ToJson(const DataReference& reference)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(reference.Site)));
    object.Set("target_address", JsonValue::MakeString(HexU64(reference.TargetAddress)));
    object.Set("kind", JsonValue::MakeString(reference.Kind));
    object.Set("symbol", JsonValue::MakeString(reference.Symbol));
    object.Set("module_name", JsonValue::MakeString(reference.ModuleName));
    object.Set("display", JsonValue::MakeString(reference.Display));
    object.Set("preview", JsonValue::MakeString(reference.Preview));
    object.Set("rip_relative", JsonValue::MakeBoolean(reference.RipRelative));
    object.Set("dereferenced", JsonValue::MakeBoolean(reference.Dereferenced));
    return object;
}

JsonValue ToJson(const CallTargetInfo& call)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(call.Site)));
    object.Set("target_address", JsonValue::MakeString(HexU64(call.TargetAddress)));
    object.Set("display_name", JsonValue::MakeString(call.DisplayName));
    object.Set("target_kind", JsonValue::MakeString(call.TargetKind));
    object.Set("module_name", JsonValue::MakeString(call.ModuleName));
    object.Set("prototype", JsonValue::MakeString(call.Prototype));
    object.Set("return_type", JsonValue::MakeString(call.ReturnType));
    object.Set("side_effects", JsonValue::MakeString(call.SideEffects));
    object.Set("indirect", JsonValue::MakeBoolean(call.Indirect));
    object.Set("confidence", JsonValue::MakeNumber(call.Confidence));
    return object;
}

JsonValue ToJson(const NormalizedCondition& condition)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(condition.Site)));
    object.Set("block_id", JsonValue::MakeString(condition.BlockId));
    object.Set("branch_mnemonic", JsonValue::MakeString(condition.BranchMnemonic));
    object.Set("expression", JsonValue::MakeString(condition.Expression));
    object.Set("true_target_block", JsonValue::MakeString(condition.TrueTargetBlock));
    object.Set("false_target_block", JsonValue::MakeString(condition.FalseTargetBlock));
    object.Set("confidence", JsonValue::MakeNumber(condition.Confidence));
    return object;
}

JsonValue ToJson(const PdbScopedSymbol& symbol)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("name", JsonValue::MakeString(symbol.Name));
    object.Set("type", JsonValue::MakeString(symbol.Type));
    object.Set("storage", JsonValue::MakeString(symbol.Storage));
    object.Set("location", JsonValue::MakeString(symbol.Location));
    object.Set("site", JsonValue::MakeString(HexU64(symbol.Site)));
    object.Set("confidence", JsonValue::MakeNumber(symbol.Confidence));
    return object;
}

JsonValue ToJson(const PdbFieldHint& hint)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("base_name", JsonValue::MakeString(hint.BaseName));
    object.Set("base_type", JsonValue::MakeString(hint.BaseType));
    object.Set("field_name", JsonValue::MakeString(hint.FieldName));
    object.Set("field_type", JsonValue::MakeString(hint.FieldType));
    object.Set("base_register", JsonValue::MakeString(hint.BaseRegister));
    object.Set("offset", JsonValue::MakeString(HexS64(hint.Offset)));
    object.Set("site", JsonValue::MakeString(HexU64(hint.Site)));
    object.Set("confidence", JsonValue::MakeNumber(hint.Confidence));
    return object;
}

JsonValue ToJson(const PdbEnumHint& hint)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("type_name", JsonValue::MakeString(hint.TypeName));
    object.Set("constant_name", JsonValue::MakeString(hint.ConstantName));
    object.Set("expression", JsonValue::MakeString(hint.Expression));
    object.Set("value", JsonValue::MakeString(HexU64(hint.Value)));
    object.Set("site", JsonValue::MakeString(HexU64(hint.Site)));
    object.Set("confidence", JsonValue::MakeNumber(hint.Confidence));
    return object;
}

JsonValue ToJson(const PdbSourceLocation& source)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("site", JsonValue::MakeString(HexU64(source.Site)));
    object.Set("file", JsonValue::MakeString(source.File));
    object.Set("line", JsonValue::MakeNumber(static_cast<double>(source.Line)));
    object.Set("displacement", JsonValue::MakeString(HexU64(source.Displacement)));
    object.Set("confidence", JsonValue::MakeNumber(source.Confidence));
    return object;
}

JsonValue ToJson(const PdbFacts& pdb)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue params = JsonValue::MakeArray();
    JsonValue locals = JsonValue::MakeArray();
    JsonValue fieldHints = JsonValue::MakeArray();
    JsonValue enumHints = JsonValue::MakeArray();
    JsonValue sourceLocations = JsonValue::MakeArray();
    JsonValue conflicts = JsonValue::MakeArray();

    for (const auto& param : pdb.Params)
    {
        params.PushBack(ToJson(param));
    }

    for (const auto& local : pdb.Locals)
    {
        locals.PushBack(ToJson(local));
    }

    for (const auto& fieldHint : pdb.FieldHints)
    {
        fieldHints.PushBack(ToJson(fieldHint));
    }

    for (const auto& enumHint : pdb.EnumHints)
    {
        enumHints.PushBack(ToJson(enumHint));
    }

    for (const auto& source : pdb.SourceLocations)
    {
        sourceLocations.PushBack(ToJson(source));
    }

    for (const auto& conflict : pdb.Conflicts)
    {
        conflicts.PushBack(JsonValue::MakeString(conflict));
    }

    object.Set("availability", JsonValue::MakeString(pdb.Availability));
    object.Set("scope_kind", JsonValue::MakeString(pdb.ScopeKind));
    object.Set("symbol_file", JsonValue::MakeString(pdb.SymbolFile));
    object.Set("function_name", JsonValue::MakeString(pdb.FunctionName));
    object.Set("prototype", JsonValue::MakeString(pdb.Prototype));
    object.Set("return_type", JsonValue::MakeString(pdb.ReturnType));
    object.Set("params", params);
    object.Set("locals", locals);
    object.Set("field_hints", fieldHints);
    object.Set("enum_hints", enumHints);
    object.Set("source_locations", sourceLocations);
    object.Set("conflicts", conflicts);
    object.Set("confidence", JsonValue::MakeNumber(pdb.Confidence));
    return object;
}

JsonValue ToJson(const TypedNameConfidence& value)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("name", JsonValue::MakeString(value.Name));
    object.Set("type", JsonValue::MakeString(value.Type));
    object.Set("confidence", JsonValue::MakeNumber(value.Confidence));
    return object;
}

JsonValue ToJson(const PseudoCodeToken& token)
{
    JsonValue object = JsonValue::MakeObject();
    object.Set("kind", JsonValue::MakeString(token.Kind));
    object.Set("text", JsonValue::MakeString(token.Text));
    return object;
}

JsonValue ToJson(const EvidenceItem& evidence)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue blocks = JsonValue::MakeArray();

    for (const auto& block : evidence.Blocks)
    {
        blocks.PushBack(JsonValue::MakeString(block));
    }

    object.Set("claim", JsonValue::MakeString(evidence.Claim));
    object.Set("blocks", blocks);
    return object;
}

JsonValue ToJson(const VerifyReport& report)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue warnings = JsonValue::MakeArray();

    for (const auto& warning : report.Warnings)
    {
        warnings.PushBack(JsonValue::MakeString(warning));
    }

    object.Set("schema_ok", JsonValue::MakeBoolean(report.SchemaOk));
    object.Set("fact_conflicts", JsonValue::MakeNumber(static_cast<double>(report.FactConflicts)));
    object.Set("missing_evidence", JsonValue::MakeNumber(static_cast<double>(report.MissingEvidence)));
    object.Set("adjusted_confidence", JsonValue::MakeNumber(report.AdjustedConfidence));
    object.Set("warnings", warnings);
    return object;
}

std::string SessionKindToString(DebugSessionKind kind)
{
    switch (kind)
    {
    case DebugSessionKind::User:
        return "user";
    case DebugSessionKind::Kernel:
        return "kernel";
    default:
        return "unknown";
    }
}

std::string AnalysisModeToString(AnalysisMode mode)
{
    switch (mode)
    {
    case AnalysisMode::FileImage:
        return "file";
    default:
        return "live";
    }
}

bool TryGetString(const JsonValue& object, const std::string& key, std::string& value)
{
    const JsonValue* json = object.Find(key);

    if (json == nullptr || !json->IsString())
    {
        return false;
    }

    value = json->GetString();
    return true;
}

bool TryGetBool(const JsonValue& object, const std::string& key, bool& value)
{
    const JsonValue* json = object.Find(key);

    if (json == nullptr || !json->IsBoolean())
    {
        return false;
    }

    value = json->GetBoolean();
    return true;
}

bool TryGetDouble(const JsonValue& object, const std::string& key, double& value)
{
    const JsonValue* json = object.Find(key);

    if (json == nullptr || !json->IsNumber())
    {
        return false;
    }

    value = json->GetNumber();
    return true;
}

bool TryGetU32(const JsonValue& object, const std::string& key, uint32_t& value)
{
    double number = 0.0;

    if (!TryGetDouble(object, key, number) || number < 0.0)
    {
        return false;
    }

    value = static_cast<uint32_t>(number);
    return true;
}

bool TryGetU64(const JsonValue& object, const std::string& key, uint64_t& value)
{
    const JsonValue* json = object.Find(key);

    if (json == nullptr)
    {
        return false;
    }

    if (json->IsString())
    {
        return TryParseUnsigned(json->GetString(), value);
    }

    if (json->IsNumber())
    {
        const double number = json->GetNumber();

        if (number < 0.0)
        {
            return false;
        }

        value = static_cast<uint64_t>(number);
        return true;
    }

    return false;
}

bool TryGetS64(const JsonValue& object, const std::string& key, int64_t& value)
{
    const JsonValue* json = object.Find(key);

    if (json == nullptr)
    {
        return false;
    }

    if (json->IsString())
    {
        std::string text = TrimCopy(json->GetString());

        if (text.empty())
        {
            return false;
        }

        bool negative = false;

        if (text.front() == '-')
        {
            negative = true;
            text = text.substr(1);
        }

        uint64_t parsed = 0;

        if (!TryParseUnsigned(text, parsed))
        {
            return false;
        }

        value = negative ? -static_cast<int64_t>(parsed) : static_cast<int64_t>(parsed);
        return true;
    }

    if (json->IsNumber())
    {
        value = static_cast<int64_t>(json->GetNumber());
        return true;
    }

    return false;
}

DebugSessionKind ParseSessionKind(const std::string& value)
{
    if (StartsWithInsensitive(value, "user"))
    {
        return DebugSessionKind::User;
    }

    if (StartsWithInsensitive(value, "kernel"))
    {
        return DebugSessionKind::Kernel;
    }

    return DebugSessionKind::Unknown;
}

AnalysisMode ParseAnalysisMode(const std::string& value)
{
    if (StartsWithInsensitive(value, "file"))
    {
        return AnalysisMode::FileImage;
    }

    return AnalysisMode::LiveMemory;
}

bool ParseModuleInfo(const JsonValue& object, ModuleInfo& module)
{
    TryGetString(object, "image_name", module.ImageName);
    TryGetString(object, "module_name", module.ModuleName);
    TryGetString(object, "loaded_image_name", module.LoadedImageName);
    TryGetU64(object, "base", module.Base);
    TryGetU32(object, "size", module.Size);
    TryGetU32(object, "symbol_type", module.SymbolType);
    return true;
}

bool ParseTypedNameConfidence(const JsonValue& object, TypedNameConfidence& value)
{
    TryGetString(object, "name", value.Name);
    TryGetString(object, "type", value.Type);
    TryGetDouble(object, "confidence", value.Confidence);
    return true;
}

bool ParseRecoveredArgument(const JsonValue& object, RecoveredArgument& argument)
{
    TryGetString(object, "name", argument.Name);
    TryGetString(object, "register", argument.Register);
    TryGetString(object, "type_hint", argument.TypeHint);
    TryGetString(object, "role_hint", argument.RoleHint);
    TryGetU64(object, "first_use_site", argument.FirstUseSite);
    TryGetU32(object, "use_count", argument.UseCount);
    TryGetDouble(object, "confidence", argument.Confidence);
    return true;
}

bool ParseRecoveredLocal(const JsonValue& object, RecoveredLocal& local)
{
    TryGetString(object, "name", local.Name);
    TryGetString(object, "base_register", local.BaseRegister);
    TryGetS64(object, "offset", local.Offset);
    TryGetString(object, "storage", local.Storage);
    TryGetString(object, "type_hint", local.TypeHint);
    TryGetString(object, "role_hint", local.RoleHint);
    TryGetU64(object, "first_site", local.FirstSite);
    TryGetU64(object, "last_site", local.LastSite);
    TryGetU32(object, "read_count", local.ReadCount);
    TryGetU32(object, "write_count", local.WriteCount);
    TryGetDouble(object, "confidence", local.Confidence);
    return true;
}

bool ParseValueMerge(const JsonValue& object, ValueMerge& merge)
{
    TryGetString(object, "block_id", merge.BlockId);
    TryGetString(object, "variable", merge.Variable);
    TryGetDouble(object, "confidence", merge.Confidence);

    const JsonValue* predecessors = object.Find("predecessors");

    if (predecessors != nullptr && predecessors->IsArray())
    {
        for (const auto& item : predecessors->GetArray())
        {
            if (item.IsString())
            {
                merge.Predecessors.push_back(item.GetString());
            }
        }
    }

    const JsonValue* incomingValues = object.Find("incoming_values");

    if (incomingValues != nullptr && incomingValues->IsArray())
    {
        for (const auto& item : incomingValues->GetArray())
        {
            if (item.IsString())
            {
                merge.IncomingValues.push_back(item.GetString());
            }
        }
    }

    return true;
}

bool ParseDataReference(const JsonValue& object, DataReference& reference)
{
    TryGetU64(object, "site", reference.Site);
    TryGetU64(object, "target_address", reference.TargetAddress);
    TryGetString(object, "kind", reference.Kind);
    TryGetString(object, "symbol", reference.Symbol);
    TryGetString(object, "module_name", reference.ModuleName);
    TryGetString(object, "display", reference.Display);
    TryGetString(object, "preview", reference.Preview);
    TryGetBool(object, "rip_relative", reference.RipRelative);
    TryGetBool(object, "dereferenced", reference.Dereferenced);
    return true;
}

bool ParseCallTargetInfo(const JsonValue& object, CallTargetInfo& call)
{
    TryGetU64(object, "site", call.Site);
    TryGetU64(object, "target_address", call.TargetAddress);
    TryGetString(object, "display_name", call.DisplayName);
    TryGetString(object, "target_kind", call.TargetKind);
    TryGetString(object, "module_name", call.ModuleName);
    TryGetString(object, "prototype", call.Prototype);
    TryGetString(object, "return_type", call.ReturnType);
    TryGetString(object, "side_effects", call.SideEffects);
    TryGetBool(object, "indirect", call.Indirect);
    TryGetDouble(object, "confidence", call.Confidence);
    return true;
}

bool ParseNormalizedCondition(const JsonValue& object, NormalizedCondition& condition)
{
    TryGetU64(object, "site", condition.Site);
    TryGetString(object, "block_id", condition.BlockId);
    TryGetString(object, "branch_mnemonic", condition.BranchMnemonic);
    TryGetString(object, "expression", condition.Expression);
    TryGetString(object, "true_target_block", condition.TrueTargetBlock);
    TryGetString(object, "false_target_block", condition.FalseTargetBlock);
    TryGetDouble(object, "confidence", condition.Confidence);
    return true;
}

bool ParsePdbScopedSymbol(const JsonValue& object, PdbScopedSymbol& symbol)
{
    TryGetString(object, "name", symbol.Name);
    TryGetString(object, "type", symbol.Type);
    TryGetString(object, "storage", symbol.Storage);
    TryGetString(object, "location", symbol.Location);
    TryGetU64(object, "site", symbol.Site);
    TryGetDouble(object, "confidence", symbol.Confidence);
    return true;
}

bool ParsePdbFieldHint(const JsonValue& object, PdbFieldHint& hint)
{
    TryGetString(object, "base_name", hint.BaseName);
    TryGetString(object, "base_type", hint.BaseType);
    TryGetString(object, "field_name", hint.FieldName);
    TryGetString(object, "field_type", hint.FieldType);
    TryGetString(object, "base_register", hint.BaseRegister);
    TryGetS64(object, "offset", hint.Offset);
    TryGetU64(object, "site", hint.Site);
    TryGetDouble(object, "confidence", hint.Confidence);
    return true;
}

bool ParsePdbEnumHint(const JsonValue& object, PdbEnumHint& hint)
{
    TryGetString(object, "type_name", hint.TypeName);
    TryGetString(object, "constant_name", hint.ConstantName);
    TryGetString(object, "expression", hint.Expression);
    TryGetU64(object, "value", hint.Value);
    TryGetU64(object, "site", hint.Site);
    TryGetDouble(object, "confidence", hint.Confidence);
    return true;
}

bool ParsePdbSourceLocation(const JsonValue& object, PdbSourceLocation& source)
{
    TryGetU64(object, "site", source.Site);
    TryGetString(object, "file", source.File);
    TryGetU32(object, "line", source.Line);
    TryGetU64(object, "displacement", source.Displacement);
    TryGetDouble(object, "confidence", source.Confidence);
    return true;
}

bool ParsePdbFacts(const JsonValue& object, PdbFacts& pdb)
{
    TryGetString(object, "availability", pdb.Availability);
    TryGetString(object, "scope_kind", pdb.ScopeKind);
    TryGetString(object, "symbol_file", pdb.SymbolFile);
    TryGetString(object, "function_name", pdb.FunctionName);
    TryGetString(object, "prototype", pdb.Prototype);
    TryGetString(object, "return_type", pdb.ReturnType);
    TryGetDouble(object, "confidence", pdb.Confidence);

    const JsonValue* params = object.Find("params");

    if (params != nullptr && params->IsArray())
    {
        for (const auto& item : params->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            PdbScopedSymbol symbol;
            ParsePdbScopedSymbol(item, symbol);
            pdb.Params.push_back(symbol);
        }
    }

    const JsonValue* locals = object.Find("locals");

    if (locals != nullptr && locals->IsArray())
    {
        for (const auto& item : locals->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            PdbScopedSymbol symbol;
            ParsePdbScopedSymbol(item, symbol);
            pdb.Locals.push_back(symbol);
        }
    }

    const JsonValue* fieldHints = object.Find("field_hints");

    if (fieldHints != nullptr && fieldHints->IsArray())
    {
        for (const auto& item : fieldHints->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            PdbFieldHint hint;
            ParsePdbFieldHint(item, hint);
            pdb.FieldHints.push_back(hint);
        }
    }

    const JsonValue* enumHints = object.Find("enum_hints");

    if (enumHints != nullptr && enumHints->IsArray())
    {
        for (const auto& item : enumHints->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            PdbEnumHint hint;
            ParsePdbEnumHint(item, hint);
            pdb.EnumHints.push_back(hint);
        }
    }

    const JsonValue* sourceLocations = object.Find("source_locations");

    if (sourceLocations != nullptr && sourceLocations->IsArray())
    {
        for (const auto& item : sourceLocations->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            PdbSourceLocation source;
            ParsePdbSourceLocation(item, source);
            pdb.SourceLocations.push_back(source);
        }
    }

    const JsonValue* conflicts = object.Find("conflicts");

    if (conflicts != nullptr && conflicts->IsArray())
    {
        for (const auto& item : conflicts->GetArray())
        {
            if (item.IsString())
            {
                pdb.Conflicts.push_back(item.GetString());
            }
        }
    }

    return true;
}

bool ParsePseudoCodeToken(const JsonValue& object, PseudoCodeToken& token)
{
    TryGetString(object, "kind", token.Kind);
    TryGetString(object, "text", token.Text);
    return true;
}

bool ParseEvidenceItem(const JsonValue& object, EvidenceItem& evidence)
{
    TryGetString(object, "claim", evidence.Claim);
    const JsonValue* blocks = object.Find("blocks");

    if (blocks != nullptr && blocks->IsArray())
    {
        for (const auto& item : blocks->GetArray())
        {
            if (item.IsString())
            {
                evidence.Blocks.push_back(item.GetString());
            }
        }
    }

    return true;
}

bool ParseVerifyReport(const JsonValue& object, VerifyReport& report)
{
    TryGetBool(object, "schema_ok", report.SchemaOk);
    TryGetU32(object, "fact_conflicts", report.FactConflicts);
    TryGetU32(object, "missing_evidence", report.MissingEvidence);
    TryGetDouble(object, "adjusted_confidence", report.AdjustedConfidence);

    const JsonValue* warnings = object.Find("warnings");

    if (warnings != nullptr && warnings->IsArray())
    {
        for (const auto& warning : warnings->GetArray())
        {
            if (warning.IsString())
            {
                report.Warnings.push_back(warning.GetString());
            }
        }
    }

    return true;
}
}

JsonValue ToJson(const AnalyzeRequest& request)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue regions = JsonValue::MakeArray();
    JsonValue instructions = JsonValue::MakeArray();
    JsonValue blocks = JsonValue::MakeArray();
    JsonValue calls = JsonValue::MakeArray();
    JsonValue indirectCalls = JsonValue::MakeArray();
    JsonValue switches = JsonValue::MakeArray();
    JsonValue memoryAccesses = JsonValue::MakeArray();
    JsonValue recoveredArguments = JsonValue::MakeArray();
    JsonValue recoveredLocals = JsonValue::MakeArray();
    JsonValue valueMerges = JsonValue::MakeArray();
    JsonValue dataReferences = JsonValue::MakeArray();
    JsonValue callTargets = JsonValue::MakeArray();
    JsonValue normalizedConditions = JsonValue::MakeArray();
    JsonValue facts = JsonValue::MakeArray();
    JsonValue uncertainPoints = JsonValue::MakeArray();

    for (const auto& region : request.Facts.Regions)
    {
        regions.PushBack(ToJson(region));
    }

    for (const auto& instruction : request.Facts.Instructions)
    {
        instructions.PushBack(ToJson(instruction));
    }

    for (const auto& block : request.Facts.Blocks)
    {
        blocks.PushBack(ToJson(block));
    }

    for (const auto& call : request.Facts.Calls)
    {
        calls.PushBack(ToJson(call));
    }

    for (const auto& call : request.Facts.IndirectCalls)
    {
        indirectCalls.PushBack(ToJson(call));
    }

    for (const auto& info : request.Facts.Switches)
    {
        switches.PushBack(ToJson(info));
    }

    for (const auto& access : request.Facts.MemoryAccesses)
    {
        memoryAccesses.PushBack(ToJson(access));
    }

    for (const auto& argument : request.Facts.RecoveredArguments)
    {
        recoveredArguments.PushBack(ToJson(argument));
    }

    for (const auto& local : request.Facts.RecoveredLocals)
    {
        recoveredLocals.PushBack(ToJson(local));
    }

    for (const auto& merge : request.Facts.ValueMerges)
    {
        valueMerges.PushBack(ToJson(merge));
    }

    for (const auto& reference : request.Facts.DataReferences)
    {
        dataReferences.PushBack(ToJson(reference));
    }

    for (const auto& call : request.Facts.CallTargets)
    {
        callTargets.PushBack(ToJson(call));
    }

    for (const auto& condition : request.Facts.NormalizedConditions)
    {
        normalizedConditions.PushBack(ToJson(condition));
    }

    for (const auto& fact : request.Facts.Facts)
    {
        facts.PushBack(JsonValue::MakeString(fact));
    }

    for (const auto& value : request.Facts.UncertainPoints)
    {
        uncertainPoints.PushBack(JsonValue::MakeString(value));
    }

    object.Set("request_id", JsonValue::MakeString(request.RequestId));
    object.Set("timeout_ms", JsonValue::MakeNumber(static_cast<double>(request.TimeoutMs)));
    object.Set("brief_output", JsonValue::MakeBoolean(request.BriefOutput));
    object.Set("arch", JsonValue::MakeString(request.Facts.Arch));
    object.Set("session", JsonValue::MakeString(SessionKindToString(request.Facts.Session)));
    object.Set("mode", JsonValue::MakeString(AnalysisModeToString(request.Facts.Mode)));
    object.Set("preferred_natural_language_tag", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageTag));
    object.Set("preferred_natural_language_name", JsonValue::MakeString(request.Facts.PreferredNaturalLanguageName));
    object.Set("query_text", JsonValue::MakeString(request.Facts.QueryText));
    object.Set("module", ToJson(request.Facts.Module));
    object.Set("query_address", JsonValue::MakeString(HexU64(request.Facts.QueryAddress)));
    object.Set("entry_address", JsonValue::MakeString(HexU64(request.Facts.EntryAddress)));
    object.Set("rva", JsonValue::MakeString(HexU64(request.Facts.Rva)));
    object.Set("regions", regions);
    object.Set("stack_frame", ToJson(request.Facts.StackFrame));
    object.Set("calling_convention", JsonValue::MakeString(request.Facts.CallingConvention));
    object.Set("instructions", instructions);
    object.Set("blocks", blocks);
    object.Set("calls", calls);
    object.Set("indirect_calls", indirectCalls);
    object.Set("switches", switches);
    object.Set("memory_accesses", memoryAccesses);
    object.Set("recovered_arguments", recoveredArguments);
    object.Set("recovered_locals", recoveredLocals);
    object.Set("value_merges", valueMerges);
    object.Set("data_references", dataReferences);
    object.Set("call_targets", callTargets);
    object.Set("normalized_conditions", normalizedConditions);
    object.Set("pdb", ToJson(request.Facts.Pdb));
    object.Set("facts", facts);
    object.Set("uncertain_points", uncertainPoints);
    object.Set("pre_llm_confidence", JsonValue::MakeNumber(request.Facts.PreLlmConfidence));
    object.Set("bytes_sha256", JsonValue::MakeString(request.Facts.BytesSha256));
    object.Set("live_bytes_differ_from_image", JsonValue::MakeBoolean(request.Facts.LiveBytesDifferFromImage));
    return object;
}

JsonValue ToJson(const AnalyzeResponse& response)
{
    JsonValue object = JsonValue::MakeObject();
    JsonValue params = JsonValue::MakeArray();
    JsonValue locals = JsonValue::MakeArray();
    JsonValue pseudoCTokens = JsonValue::MakeArray();
    JsonValue uncertainties = JsonValue::MakeArray();
    JsonValue evidence = JsonValue::MakeArray();

    for (const auto& item : response.Params)
    {
        params.PushBack(ToJson(item));
    }

    for (const auto& item : response.Locals)
    {
        locals.PushBack(ToJson(item));
    }

    for (const auto& item : response.PseudoCTokens)
    {
        pseudoCTokens.PushBack(ToJson(item));
    }

    for (const auto& item : response.Uncertainties)
    {
        uncertainties.PushBack(JsonValue::MakeString(item));
    }

    for (const auto& item : response.Evidence)
    {
        evidence.PushBack(ToJson(item));
    }

    object.Set("status", JsonValue::MakeString(response.Status));
    object.Set("pseudo_c", JsonValue::MakeString(response.PseudoC));
    object.Set("pseudo_c_tokens", pseudoCTokens);
    object.Set("summary", JsonValue::MakeString(response.Summary));
    object.Set("params", params);
    object.Set("locals", locals);
    object.Set("uncertainties", uncertainties);
    object.Set("evidence", evidence);
    object.Set("confidence", JsonValue::MakeNumber(response.Confidence));
    object.Set("verifier", ToJson(response.Verifier));
    object.Set("provider", JsonValue::MakeString(response.Provider));
    object.Set("raw_model_json", JsonValue::MakeString(response.RawModelJson));
    object.Set("timing_ms", JsonValue::MakeNumber(static_cast<double>(response.TimingMs)));
    return object;
}

std::string SerializeAnalyzeRequest(const AnalyzeRequest& request, bool pretty)
{
    return SerializeJson(ToJson(request), pretty);
}

std::string SerializeAnalyzeResponse(const AnalyzeResponse& response, bool pretty)
{
    return SerializeJson(ToJson(response), pretty);
}

bool ParseAnalyzeRequest(const std::string& text, AnalyzeRequest& request, std::string& error)
{
    const JsonParseResult parsed = ParseJson(text);

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        error = parsed.Error.empty() ? "request must be a JSON object" : parsed.Error;
        return false;
    }

    const JsonValue& object = parsed.Value;
    TryGetString(object, "request_id", request.RequestId);
    TryGetU32(object, "timeout_ms", request.TimeoutMs);
    TryGetBool(object, "brief_output", request.BriefOutput);
    TryGetString(object, "arch", request.Facts.Arch);

    std::string session;
    std::string mode;
    TryGetString(object, "session", session);
    TryGetString(object, "mode", mode);
    TryGetString(object, "preferred_natural_language_tag", request.Facts.PreferredNaturalLanguageTag);
    TryGetString(object, "preferred_natural_language_name", request.Facts.PreferredNaturalLanguageName);
    request.Facts.Session = ParseSessionKind(session);
    request.Facts.Mode = ParseAnalysisMode(mode);
    TryGetString(object, "query_text", request.Facts.QueryText);
    TryGetU64(object, "query_address", request.Facts.QueryAddress);
    TryGetU64(object, "entry_address", request.Facts.EntryAddress);
    TryGetU64(object, "rva", request.Facts.Rva);
    TryGetString(object, "calling_convention", request.Facts.CallingConvention);
    TryGetDouble(object, "pre_llm_confidence", request.Facts.PreLlmConfidence);
    TryGetString(object, "bytes_sha256", request.Facts.BytesSha256);
    TryGetBool(object, "live_bytes_differ_from_image", request.Facts.LiveBytesDifferFromImage);

    const JsonValue* module = object.Find("module");

    if (module != nullptr && module->IsObject())
    {
        ParseModuleInfo(*module, request.Facts.Module);
    }

    const JsonValue* stackFrame = object.Find("stack_frame");

    if (stackFrame != nullptr && stackFrame->IsObject())
    {
        TryGetU32(*stackFrame, "stack_alloc", request.Facts.StackFrame.StackAlloc);
        TryGetBool(*stackFrame, "uses_cookie", request.Facts.StackFrame.UsesCookie);
        TryGetBool(*stackFrame, "frame_pointer", request.Facts.StackFrame.FramePointer);

        const JsonValue* saved = stackFrame->Find("saved_nonvolatile");

        if (saved != nullptr && saved->IsArray())
        {
            for (const auto& item : saved->GetArray())
            {
                if (item.IsString())
                {
                    request.Facts.StackFrame.SavedNonvolatile.push_back(item.GetString());
                }
            }
        }
    }

    const JsonValue* regions = object.Find("regions");

    if (regions != nullptr && regions->IsArray())
    {
        for (const auto& item : regions->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            FunctionRegion region;
            TryGetU64(item, "start", region.Start);
            TryGetU64(item, "end", region.End);
            request.Facts.Regions.push_back(region);
        }
    }

    const JsonValue* instructions = object.Find("instructions");

    if (instructions != nullptr && instructions->IsArray())
    {
        for (const auto& item : instructions->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            DisassembledInstruction instruction;
            TryGetU64(item, "address", instruction.Address);
            TryGetU64(item, "end_address", instruction.EndAddress);
            TryGetString(item, "text", instruction.Text);
            TryGetString(item, "operation_text", instruction.OperationText);
            TryGetString(item, "mnemonic", instruction.Mnemonic);
            TryGetString(item, "operand_text", instruction.OperandText);
            TryGetBool(item, "is_conditional_branch", instruction.IsConditionalBranch);
            TryGetBool(item, "is_unconditional_branch", instruction.IsUnconditionalBranch);
            TryGetBool(item, "is_call", instruction.IsCall);
            TryGetBool(item, "is_return", instruction.IsReturn);
            TryGetBool(item, "is_indirect", instruction.IsIndirect);
            TryGetU64(item, "branch_target", instruction.BranchTarget);
            TryGetBool(item, "has_branch_target", instruction.HasBranchTarget);
            request.Facts.Instructions.push_back(instruction);
        }
    }

    const JsonValue* blocks = object.Find("blocks");

    if (blocks != nullptr && blocks->IsArray())
    {
        for (const auto& item : blocks->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            BasicBlock block;
            TryGetString(item, "id", block.Id);
            TryGetU64(item, "start_address", block.StartAddress);
            TryGetU64(item, "end_address", block.EndAddress);
            TryGetBool(item, "has_terminal", block.HasTerminal);

            const JsonValue* instructionAddresses = item.Find("instruction_addresses");

            if (instructionAddresses != nullptr && instructionAddresses->IsArray())
            {
                for (const auto& addressValue : instructionAddresses->GetArray())
                {
                    uint64_t address = 0;

                    if (addressValue.IsString())
                    {
                        TryParseUnsigned(addressValue.GetString(), address);
                    }
                    else if (addressValue.IsNumber())
                    {
                        address = static_cast<uint64_t>(addressValue.GetNumber());
                    }

                    block.InstructionAddresses.push_back(address);
                }
            }

            const JsonValue* successors = item.Find("successors");

            if (successors != nullptr && successors->IsArray())
            {
                for (const auto& successor : successors->GetArray())
                {
                    if (successor.IsString())
                    {
                        block.Successors.push_back(successor.GetString());
                    }
                }
            }

            request.Facts.Blocks.push_back(block);
        }
    }

    const JsonValue* calls = object.Find("calls");

    if (calls != nullptr && calls->IsArray())
    {
        for (const auto& item : calls->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            CallSite call;
            TryGetU64(item, "site", call.Site);
            TryGetString(item, "target", call.Target);
            TryGetString(item, "kind", call.Kind);
            TryGetBool(item, "returns", call.Returns);
            request.Facts.Calls.push_back(call);
        }
    }

    const JsonValue* indirectCalls = object.Find("indirect_calls");

    if (indirectCalls != nullptr && indirectCalls->IsArray())
    {
        for (const auto& item : indirectCalls->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            CallSite call;
            TryGetU64(item, "site", call.Site);
            TryGetString(item, "target", call.Target);
            TryGetString(item, "kind", call.Kind);
            TryGetBool(item, "returns", call.Returns);
            request.Facts.IndirectCalls.push_back(call);
        }
    }

    const JsonValue* switches = object.Find("switches");

    if (switches != nullptr && switches->IsArray())
    {
        for (const auto& item : switches->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            SwitchInfo info;
            TryGetU64(item, "site", info.Site);
            TryGetU32(item, "case_count", info.CaseCount);
            TryGetString(item, "detail", info.Detail);
            request.Facts.Switches.push_back(info);
        }
    }

    const JsonValue* memoryAccesses = object.Find("memory_accesses");

    if (memoryAccesses != nullptr && memoryAccesses->IsArray())
    {
        for (const auto& item : memoryAccesses->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            MemoryAccess access;
            TryGetU64(item, "site", access.Site);
            TryGetString(item, "access", access.Access);
            TryGetString(item, "kind", access.Kind);
            TryGetString(item, "size", access.Size);
            TryGetU32(item, "width_bits", access.WidthBits);
            TryGetString(item, "base_register", access.BaseRegister);
            TryGetString(item, "index_register", access.IndexRegister);
            TryGetU32(item, "scale", access.Scale);
            TryGetString(item, "displacement", access.Displacement);
            TryGetBool(item, "rip_relative", access.RipRelative);
            request.Facts.MemoryAccesses.push_back(access);
        }
    }

    const JsonValue* recoveredArguments = object.Find("recovered_arguments");

    if (recoveredArguments != nullptr && recoveredArguments->IsArray())
    {
        for (const auto& item : recoveredArguments->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            RecoveredArgument argument;
            ParseRecoveredArgument(item, argument);
            request.Facts.RecoveredArguments.push_back(argument);
        }
    }

    const JsonValue* recoveredLocals = object.Find("recovered_locals");

    if (recoveredLocals != nullptr && recoveredLocals->IsArray())
    {
        for (const auto& item : recoveredLocals->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            RecoveredLocal local;
            ParseRecoveredLocal(item, local);
            request.Facts.RecoveredLocals.push_back(local);
        }
    }

    const JsonValue* valueMerges = object.Find("value_merges");

    if (valueMerges != nullptr && valueMerges->IsArray())
    {
        for (const auto& item : valueMerges->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            ValueMerge merge;
            ParseValueMerge(item, merge);
            request.Facts.ValueMerges.push_back(merge);
        }
    }

    const JsonValue* dataReferences = object.Find("data_references");

    if (dataReferences != nullptr && dataReferences->IsArray())
    {
        for (const auto& item : dataReferences->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            DataReference reference;
            ParseDataReference(item, reference);
            request.Facts.DataReferences.push_back(reference);
        }
    }

    const JsonValue* callTargets = object.Find("call_targets");

    if (callTargets != nullptr && callTargets->IsArray())
    {
        for (const auto& item : callTargets->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            CallTargetInfo call;
            ParseCallTargetInfo(item, call);
            request.Facts.CallTargets.push_back(call);
        }
    }

    const JsonValue* normalizedConditions = object.Find("normalized_conditions");

    if (normalizedConditions != nullptr && normalizedConditions->IsArray())
    {
        for (const auto& item : normalizedConditions->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            NormalizedCondition condition;
            ParseNormalizedCondition(item, condition);
            request.Facts.NormalizedConditions.push_back(condition);
        }
    }

    const JsonValue* pdb = object.Find("pdb");

    if (pdb != nullptr && pdb->IsObject())
    {
        ParsePdbFacts(*pdb, request.Facts.Pdb);
    }

    const JsonValue* facts = object.Find("facts");

    if (facts != nullptr && facts->IsArray())
    {
        for (const auto& item : facts->GetArray())
        {
            if (item.IsString())
            {
                request.Facts.Facts.push_back(item.GetString());
            }
        }
    }

    const JsonValue* uncertainPoints = object.Find("uncertain_points");

    if (uncertainPoints != nullptr && uncertainPoints->IsArray())
    {
        for (const auto& item : uncertainPoints->GetArray())
        {
            if (item.IsString())
            {
                request.Facts.UncertainPoints.push_back(item.GetString());
            }
        }
    }

    return true;
}

bool ParseAnalyzeResponse(const std::string& text, AnalyzeResponse& response, std::string& error)
{
    const JsonParseResult parsed = ParseJson(text);

    if (!parsed.Success || !parsed.Value.IsObject())
    {
        error = parsed.Error.empty() ? "response must be a JSON object" : parsed.Error;
        return false;
    }

    const JsonValue& object = parsed.Value;
    TryGetString(object, "status", response.Status);
    TryGetString(object, "pseudo_c", response.PseudoC);
    TryGetString(object, "summary", response.Summary);
    TryGetDouble(object, "confidence", response.Confidence);
    TryGetString(object, "provider", response.Provider);
    TryGetString(object, "raw_model_json", response.RawModelJson);
    TryGetU32(object, "timing_ms", response.TimingMs);

    const JsonValue* params = object.Find("params");

    if (params != nullptr && params->IsArray())
    {
        for (const auto& item : params->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            TypedNameConfidence value;
            ParseTypedNameConfidence(item, value);
            response.Params.push_back(value);
        }
    }

    const JsonValue* locals = object.Find("locals");

    if (locals != nullptr && locals->IsArray())
    {
        for (const auto& item : locals->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            TypedNameConfidence value;
            ParseTypedNameConfidence(item, value);
            response.Locals.push_back(value);
        }
    }

    const JsonValue* pseudoCTokens = object.Find("pseudo_c_tokens");

    if (pseudoCTokens != nullptr && pseudoCTokens->IsArray())
    {
        for (const auto& item : pseudoCTokens->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            PseudoCodeToken token;
            ParsePseudoCodeToken(item, token);
            response.PseudoCTokens.push_back(token);
        }
    }

    const JsonValue* uncertainties = object.Find("uncertainties");

    if (uncertainties != nullptr && uncertainties->IsArray())
    {
        for (const auto& item : uncertainties->GetArray())
        {
            if (item.IsString())
            {
                response.Uncertainties.push_back(item.GetString());
            }
        }
    }

    const JsonValue* evidence = object.Find("evidence");

    if (evidence != nullptr && evidence->IsArray())
    {
        for (const auto& item : evidence->GetArray())
        {
            if (!item.IsObject())
            {
                continue;
            }

            EvidenceItem parsedEvidence;
            ParseEvidenceItem(item, parsedEvidence);
            response.Evidence.push_back(parsedEvidence);
        }
    }

    const JsonValue* verifier = object.Find("verifier");

    if (verifier != nullptr && verifier->IsObject())
    {
        ParseVerifyReport(*verifier, response.Verifier);
    }

    EnsurePseudoCodeTokens(response);
    return true;
}
}
