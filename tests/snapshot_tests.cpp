#include "decomp/analyzer.h"
#include "decomp/json.h"
#include "decomp/llm_client.h"
#include "decomp/protocol.h"
#include "decomp/string_utils.h"
#include "decomp/verifier.h"
#include "snapshot_test_helpers.h"

#include <iostream>
#include <string>
#include <vector>

namespace
{
decomp::DisassembledInstruction MakeInstruction(
    uint64_t address,
    uint64_t endAddress,
    const std::string& mnemonic,
    const std::string& operands = std::string())
{
    decomp::DisassembledInstruction instruction;
    instruction.Address = address;
    instruction.EndAddress = endAddress;
    instruction.Mnemonic = mnemonic;
    instruction.OperandText = operands;
    instruction.OperationText = operands.empty() ? mnemonic : mnemonic + " " + operands;
    instruction.Text = instruction.OperationText;
    instruction.IsConditionalBranch = mnemonic.size() >= 2 && mnemonic[0] == 'j' && mnemonic != "jmp";
    instruction.IsUnconditionalBranch = mnemonic == "jmp";
    instruction.IsCall = mnemonic == "call";
    instruction.IsReturn = mnemonic == "ret" || mnemonic == "retn";
    instruction.IsIndirect = operands.find('[') != std::string::npos && (instruction.IsCall || instruction.IsUnconditionalBranch);
    return instruction;
}

decomp::DisassembledInstruction MakeBranch(
    uint64_t address,
    uint64_t endAddress,
    const std::string& mnemonic,
    uint64_t target)
{
    decomp::DisassembledInstruction instruction = MakeInstruction(address, endAddress, mnemonic, decomp::HexU64(target));
    instruction.HasBranchTarget = true;
    instruction.BranchTarget = target;
    return instruction;
}

bool ContainsReachingValueName(const std::vector<decomp::ReachingValue>& values, const std::string& name)
{
    for (const decomp::ReachingValue& value : values)
    {
        if (value.Name == name)
        {
            return true;
        }
    }

    return false;
}

const decomp::ControlFlowRegion* FindRegion(const decomp::AnalysisFacts& facts, const std::string& kind)
{
    for (const decomp::ControlFlowRegion& region : facts.ControlFlow)
    {
        if (region.Kind == kind)
        {
            return &region;
        }
    }

    return nullptr;
}

const decomp::BasicBlock* FindBlockStartingAt(const decomp::AnalysisFacts& facts, uint64_t address)
{
    for (const decomp::BasicBlock& block : facts.Blocks)
    {
        if (block.StartAddress == address)
        {
            return &block;
        }
    }

    return nullptr;
}

const decomp::BasicBlock* FindBlockContaining(const decomp::AnalysisFacts& facts, uint64_t address)
{
    for (const decomp::BasicBlock& block : facts.Blocks)
    {
        if (address >= block.StartAddress && address < block.EndAddress)
        {
            return &block;
        }
    }

    return nullptr;
}

bool HasEvidenceNodeKind(const decomp::AnalysisFacts& facts, const std::string& kind)
{
    for (const decomp::EvidenceNode& node : facts.EvidenceGraph.Nodes)
    {
        if (node.Kind == kind)
        {
            return true;
        }
    }

    return false;
}

bool HasEvidenceEdgeRelation(const decomp::AnalysisFacts& facts, const std::string& relation)
{
    for (const decomp::EvidenceEdge& edge : facts.EvidenceGraph.Edges)
    {
        if (edge.Relation == relation)
        {
            return true;
        }
    }

    return false;
}

const decomp::ObfuscationDispatcher* FindHighConfidenceDispatcher(const decomp::AnalysisFacts& facts)
{
    for (const decomp::ObfuscationDispatcher& dispatcher : facts.Obfuscation.Dispatchers)
    {
        if (dispatcher.Confidence >= 0.75)
        {
            return &dispatcher;
        }
    }

    return nullptr;
}

decomp::AnalysisFacts BuildDiamondFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x1000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x1000, 0x1030 } };
    std::vector<uint8_t> bytes(0x30, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x1000, 0x1004, "sub", "rsp, 0x28"));
    instructions.push_back(MakeInstruction(0x1004, 0x1007, "mov", "r10, rcx"));
    instructions.push_back(MakeInstruction(0x1007, 0x100b, "cmp", "rcx, 0"));
    instructions.push_back(MakeBranch(0x100b, 0x100d, "je", 0x1018));
    instructions.push_back(MakeInstruction(0x100d, 0x1015, "mov", "qword ptr [rsp+0x8], 1"));
    instructions.push_back(MakeBranch(0x1015, 0x1018, "jmp", 0x1020));
    instructions.push_back(MakeInstruction(0x1018, 0x1020, "mov", "qword ptr [rsp+0x8], 2"));
    instructions.push_back(MakeInstruction(0x1020, 0x1024, "mov", "rax, qword ptr [rsp+0x8]"));
    instructions.push_back(MakeInstruction(0x1024, 0x1028, "add", "r10, rdx"));
    instructions.push_back(MakeInstruction(0x1028, 0x1029, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!Diamond",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x1000,
        0x1000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildSwitchTargetFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x3000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x3000, 0x3020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x3000, 0x3004, "cmp", "rcx, 2"));
    instructions.push_back(MakeBranch(0x3004, 0x3006, "ja", 0x3014));
    instructions.push_back(MakeInstruction(0x3006, 0x300e, "jmp", "qword ptr [rip+rcx*8+0x80]"));
    instructions.push_back(MakeInstruction(0x300e, 0x3010, "mov", "eax, 1"));
    instructions.push_back(MakeInstruction(0x3010, 0x3013, "add", "eax, 2"));
    instructions.push_back(MakeInstruction(0x3013, 0x3014, "ret"));
    instructions.push_back(MakeInstruction(0x3014, 0x3017, "mov", "eax, 3"));
    instructions.push_back(MakeInstruction(0x3017, 0x3018, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!SwitchTarget",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x3000,
        0x3000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildFlagClobberFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x4000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x4000, 0x4020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x4000, 0x4003, "cmp", "rcx, 0"));
    instructions.push_back(MakeInstruction(0x4003, 0x4006, "add", "rax, 1"));
    instructions.push_back(MakeBranch(0x4006, 0x4008, "je", 0x4010));
    instructions.push_back(MakeInstruction(0x4008, 0x400d, "mov", "eax, 1"));
    instructions.push_back(MakeInstruction(0x400d, 0x400e, "ret"));
    instructions.push_back(MakeInstruction(0x4010, 0x4015, "mov", "eax, 2"));
    instructions.push_back(MakeInstruction(0x4015, 0x4016, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!FlagClobber",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x4000,
        0x4000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildImplicitAndCallFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x5000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x5000, 0x5020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x5000, 0x5001, "push", "rbx"));
    instructions.push_back(MakeInstruction(0x5001, 0x5006, "mov", "rdx, 5"));
    instructions.push_back(MakeInstruction(0x5006, 0x5009, "mov", "rax, rdx"));
    instructions.push_back(MakeInstruction(0x5009, 0x500b, "xor", "al, al"));
    instructions.push_back(MakeBranch(0x500b, 0x5010, "call", 0x5100));
    instructions.push_back(MakeInstruction(0x5010, 0x5013, "add", "rdx, 1"));
    instructions.push_back(MakeInstruction(0x5013, 0x5014, "movsb", "byte ptr [rdi], byte ptr [rsi]"));
    instructions.push_back(MakeInstruction(0x5014, 0x5015, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!ImplicitAndCall",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x5000,
        0x5000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildStackCallArgumentWindowFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x7000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x7000, 0x7060 } };
    std::vector<uint8_t> bytes(0x60, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x7000, 0x7004, "sub", "rsp, 0x50"));
    instructions.push_back(MakeInstruction(0x7004, 0x700c, "mov", "qword ptr [rsp+0x20], rcx"));
    instructions.push_back(MakeBranch(0x700c, 0x7011, "call", 0x7100));
    instructions.push_back(MakeInstruction(0x7011, 0x7019, "mov", "qword ptr [rsp+0x20], 0x1234"));

    uint64_t address = 0x7019;

    for (size_t index = 0; index < 10; ++index)
    {
        instructions.push_back(MakeInstruction(address, address + 3, "add", "rax, 1"));
        address += 3;
    }

    instructions.push_back(MakeBranch(address, address + 5, "call", 0x7108));
    address += 5;
    instructions.push_back(MakeInstruction(address, address + 1, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!StackCallArgumentWindow",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x7000,
        0x7000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildCrossBlockStackCallArgumentFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x7800;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x7800, 0x7830 } };
    std::vector<uint8_t> bytes(0x30, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x7800, 0x7804, "sub", "rsp, 0x50"));
    instructions.push_back(MakeInstruction(0x7804, 0x780c, "mov", "qword ptr [rsp+0x20], rdx"));
    instructions.push_back(MakeBranch(0x780c, 0x7811, "jmp", 0x7818));
    instructions.push_back(MakeBranch(0x7818, 0x781d, "call", 0x7900));
    instructions.push_back(MakeInstruction(0x781d, 0x781e, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!CrossBlockStackCallArgument",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x7800,
        0x7800,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildCfgStackFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x8000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x8000, 0x8030 } };
    std::vector<uint8_t> bytes(0x30, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x8000, 0x8004, "sub", "rsp, 0x20"));
    instructions.push_back(MakeInstruction(0x8004, 0x8007, "cmp", "rcx, 0"));
    instructions.push_back(MakeBranch(0x8007, 0x8009, "je", 0x8010));
    instructions.push_back(MakeInstruction(0x8009, 0x800d, "add", "rsp, 0x20"));
    instructions.push_back(MakeInstruction(0x800d, 0x800e, "ret"));
    instructions.push_back(MakeInstruction(0x8010, 0x8018, "mov", "qword ptr [rsp+0x8], 1"));
    instructions.push_back(MakeInstruction(0x8018, 0x8019, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!CfgStack",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x8000,
        0x8000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildLoopStackFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x8800;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x8800, 0x8830 } };
    std::vector<uint8_t> bytes(0x30, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x8800, 0x8804, "sub", "rsp, 0x20"));
    instructions.push_back(MakeInstruction(0x8804, 0x8808, "cmp", "rcx, 0"));
    instructions.push_back(MakeBranch(0x8808, 0x880a, "je", 0x8820));
    instructions.push_back(MakeInstruction(0x880a, 0x8812, "mov", "qword ptr [rsp+0x8], rcx"));
    instructions.push_back(MakeInstruction(0x8812, 0x8815, "dec", "rcx"));
    instructions.push_back(MakeBranch(0x8815, 0x8817, "jne", 0x8804));
    instructions.push_back(MakeInstruction(0x8820, 0x8821, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!LoopStack",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x8800,
        0x8800,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildCfgCallArgumentFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x9000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x9000, 0x9020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x9000, 0x9005, "mov", "rcx, 1"));
    instructions.push_back(MakeInstruction(0x9005, 0x9008, "cmp", "rdx, 0"));
    instructions.push_back(MakeBranch(0x9008, 0x900a, "je", 0x9010));
    instructions.push_back(MakeInstruction(0x900a, 0x9010, "mov", "rcx, 2"));
    instructions.push_back(MakeBranch(0x9010, 0x9015, "call", 0x9100));
    instructions.push_back(MakeInstruction(0x9015, 0x9016, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!CfgCallArgument",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x9000,
        0x9000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildStackAliasFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0xa000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0xa000, 0xa020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0xa000, 0xa004, "sub", "rsp, 0x30"));
    instructions.push_back(MakeInstruction(0xa004, 0xa009, "lea", "rax, [rsp+0x10]"));
    instructions.push_back(MakeInstruction(0xa009, 0xa011, "mov", "qword ptr [rax+0x8], 1"));
    instructions.push_back(MakeInstruction(0xa011, 0xa012, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!StackAlias",
        module,
        decomp::DebugSessionKind::User,
        options,
        0xa000,
        0xa000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildStackAliasHomeFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0xa800;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0xa800, 0xa820 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0xa800, 0xa804, "sub", "rsp, 0x30"));
    instructions.push_back(MakeInstruction(0xa804, 0xa809, "lea", "rax, [rsp+0x38]"));
    instructions.push_back(MakeInstruction(0xa809, 0xa811, "mov", "qword ptr [rax], rcx"));
    instructions.push_back(MakeInstruction(0xa811, 0xa812, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!StackAliasHome",
        module,
        decomp::DebugSessionKind::User,
        options,
        0xa800,
        0xa800,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildTailCallFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0xb000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0xb000, 0xb010 } };
    std::vector<uint8_t> bytes(0x10, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0xb000, 0xb004, "mov", "rcx, rdx"));
    instructions.push_back(MakeBranch(0xb004, 0xb009, "jmp", 0xc000));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!TailCall",
        module,
        decomp::DebugSessionKind::User,
        options,
        0xb000,
        0xb000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildCmovFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0xd000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0xd000, 0xd020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0xd000, 0xd003, "cmp", "rcx, rdx"));
    instructions.push_back(MakeInstruction(0xd003, 0xd006, "mov", "rax, rcx"));
    instructions.push_back(MakeInstruction(0xd006, 0xd00a, "cmovl", "rax, rdx"));
    instructions.push_back(MakeInstruction(0xd00a, 0xd00d, "cmp", "rax, 0"));
    instructions.push_back(MakeInstruction(0xd00d, 0xd011, "cmovnl", "rax, rcx"));
    instructions.push_back(MakeInstruction(0xd011, 0xd012, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!Cmov",
        module,
        decomp::DebugSessionKind::User,
        options,
        0xd000,
        0xd000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildStackNormalizedFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x6000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x6000, 0x6020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x6000, 0x6004, "sub", "rsp, 0x28"));
    instructions.push_back(MakeInstruction(0x6004, 0x6009, "mov", "qword ptr [rsp+0x8], 1"));
    instructions.push_back(MakeInstruction(0x6009, 0x600a, "push", "rbx"));
    instructions.push_back(MakeInstruction(0x600a, 0x600f, "mov", "qword ptr [rsp+0x10], 2"));
    instructions.push_back(MakeInstruction(0x600f, 0x6014, "mov", "rax, qword ptr [rsp+0x10]"));
    instructions.push_back(MakeInstruction(0x6014, 0x6015, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!StackNormalized",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x6000,
        0x6000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildIrOverwriteFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x2000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x2000, 0x2020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x2000, 0x2005, "mov", "rax, 1"));
    instructions.push_back(MakeInstruction(0x2005, 0x2008, "mov", "rax, rdx"));
    instructions.push_back(MakeInstruction(0x2008, 0x200b, "add", "rax, 2"));
    instructions.push_back(MakeInstruction(0x200b, 0x200d, "xor", "rcx, rcx"));
    instructions.push_back(MakeInstruction(0x200d, 0x2015, "mov", "qword ptr [r8], rax"));
    instructions.push_back(MakeInstruction(0x2015, 0x2016, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!IrOverwrite",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x2000,
        0x2000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildSimdArgumentFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0xe000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0xe000, 0xe020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0xe000, 0xe003, "xorps", "xmm2, xmm2"));
    instructions.push_back(MakeInstruction(0xe003, 0xe007, "ucomisd", "xmm0, xmm1"));
    instructions.push_back(MakeBranch(0xe007, 0xe00c, "call", 0xe100));
    instructions.push_back(MakeInstruction(0xe00c, 0xe00d, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!SimdArguments",
        module,
        decomp::DebugSessionKind::User,
        options,
        0xe000,
        0xe000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildIndirectVirtualCallFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0xf000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0xf000, 0xf020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0xf000, 0xf004, "mov", "rax, qword ptr [rcx]"));
    instructions.push_back(MakeInstruction(0xf004, 0xf00a, "call", "qword ptr [rax+0x18]"));
    instructions.push_back(MakeInstruction(0xf00a, 0xf00b, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!IndirectVirtualCall",
        module,
        decomp::DebugSessionKind::User,
        options,
        0xf000,
        0xf000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildLoopInductionFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x11000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x11000, 0x11020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x11000, 0x11002, "xor", "eax, eax"));
    instructions.push_back(MakeInstruction(0x11002, 0x11005, "cmp", "eax, ecx"));
    instructions.push_back(MakeBranch(0x11005, 0x11007, "jge", 0x11010));
    instructions.push_back(MakeInstruction(0x11007, 0x1100a, "add", "edx, 8"));
    instructions.push_back(MakeInstruction(0x1100a, 0x1100d, "add", "eax, 1"));
    instructions.push_back(MakeBranch(0x1100d, 0x1100f, "jmp", 0x11002));
    instructions.push_back(MakeInstruction(0x11010, 0x11011, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!LoopInduction",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x11000,
        0x11000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildKnownApiCallFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x12000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x12000, 0x12020 } };
    std::vector<uint8_t> bytes(0x20, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x12000, 0x12005, "call", "memcpy"));
    instructions.push_back(MakeInstruction(0x12005, 0x12006, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!KnownApi",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x12000,
        0x12000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildFlattenedDispatcherFacts(const decomp::DecompOptions& options)
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x13000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x13000, 0x13060 } };
    std::vector<uint8_t> bytes(0x60, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x13000, 0x13005, "mov", "eax, 0"));
    instructions.push_back(MakeBranch(0x13005, 0x13007, "jmp", 0x13040));
    instructions.push_back(MakeInstruction(0x13010, 0x13013, "add", "edx, 1"));
    instructions.push_back(MakeInstruction(0x13013, 0x13018, "mov", "eax, 1"));
    instructions.push_back(MakeBranch(0x13018, 0x1301A, "jmp", 0x13040));
    instructions.push_back(MakeInstruction(0x13020, 0x13023, "add", "edx, 2"));
    instructions.push_back(MakeInstruction(0x13023, 0x13028, "mov", "eax, 2"));
    instructions.push_back(MakeBranch(0x13028, 0x1302A, "jmp", 0x13040));
    instructions.push_back(MakeInstruction(0x13030, 0x13031, "ret"));
    instructions.push_back(MakeInstruction(0x13040, 0x13043, "cmp", "eax, 0"));
    instructions.push_back(MakeBranch(0x13043, 0x13045, "je", 0x13010));
    instructions.push_back(MakeInstruction(0x13045, 0x13048, "cmp", "eax, 1"));
    instructions.push_back(MakeBranch(0x13048, 0x1304A, "je", 0x13020));
    instructions.push_back(MakeInstruction(0x1304A, 0x1304D, "cmp", "eax, 2"));
    instructions.push_back(MakeBranch(0x1304D, 0x1304F, "je", 0x13030));
    instructions.push_back(MakeInstruction(0x1304F, 0x13050, "ret"));

    return decomp::BuildAnalysisFacts(
        "snapshot!FlattenedDispatcher",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x13000,
        0x13000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildFlattenedDispatcherFacts()
{
    decomp::DecompOptions options;
    return BuildFlattenedDispatcherFacts(options);
}

decomp::AnalysisFacts BuildLegitimateStateSwitchFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x14000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x14000, 0x14050 } };
    std::vector<uint8_t> bytes(0x50, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x14000, 0x14003, "cmp", "ecx, 0"));
    instructions.push_back(MakeBranch(0x14003, 0x14005, "je", 0x14020));
    instructions.push_back(MakeInstruction(0x14005, 0x14008, "cmp", "ecx, 1"));
    instructions.push_back(MakeBranch(0x14008, 0x1400A, "je", 0x14030));
    instructions.push_back(MakeInstruction(0x1400A, 0x1400D, "cmp", "ecx, 2"));
    instructions.push_back(MakeBranch(0x1400D, 0x1400F, "je", 0x14040));
    instructions.push_back(MakeInstruction(0x1400F, 0x14010, "ret"));
    instructions.push_back(MakeInstruction(0x14020, 0x14025, "mov", "eax, 1"));
    instructions.push_back(MakeInstruction(0x14025, 0x14026, "ret"));
    instructions.push_back(MakeInstruction(0x14030, 0x14035, "mov", "eax, 2"));
    instructions.push_back(MakeInstruction(0x14035, 0x14036, "ret"));
    instructions.push_back(MakeInstruction(0x14040, 0x14045, "mov", "eax, 3"));
    instructions.push_back(MakeInstruction(0x14045, 0x14046, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!LegitimateStateSwitch",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x14000,
        0x14000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildFanInCompareLoopFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x15000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x15000, 0x15060 } };
    std::vector<uint8_t> bytes(0x60, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeBranch(0x15000, 0x15002, "jmp", 0x15040));
    instructions.push_back(MakeInstruction(0x15010, 0x15013, "add", "edx, 1"));
    instructions.push_back(MakeBranch(0x15013, 0x15015, "jmp", 0x15040));
    instructions.push_back(MakeInstruction(0x15020, 0x15023, "add", "edx, 2"));
    instructions.push_back(MakeBranch(0x15023, 0x15025, "jmp", 0x15040));
    instructions.push_back(MakeInstruction(0x15030, 0x15031, "ret"));
    instructions.push_back(MakeInstruction(0x15040, 0x15043, "cmp", "ecx, 0"));
    instructions.push_back(MakeBranch(0x15043, 0x15045, "je", 0x15010));
    instructions.push_back(MakeInstruction(0x15045, 0x15048, "cmp", "ecx, 1"));
    instructions.push_back(MakeBranch(0x15048, 0x1504A, "je", 0x15020));
    instructions.push_back(MakeInstruction(0x1504A, 0x1504D, "cmp", "ecx, 2"));
    instructions.push_back(MakeBranch(0x1504D, 0x1504F, "je", 0x15030));
    instructions.push_back(MakeInstruction(0x1504F, 0x15050, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!FanInCompareLoop",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x15000,
        0x15000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildSwitchFlattenedDispatcherFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x16000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x16000, 0x16070 } };
    std::vector<uint8_t> bytes(0x70, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x16000, 0x16005, "mov", "eax, 0"));
    instructions.push_back(MakeBranch(0x16005, 0x16007, "jmp", 0x16040));
    instructions.push_back(MakeInstruction(0x16010, 0x16013, "add", "edx, 1"));
    instructions.push_back(MakeInstruction(0x16013, 0x16018, "mov", "eax, 1"));
    instructions.push_back(MakeBranch(0x16018, 0x1601A, "jmp", 0x16040));
    instructions.push_back(MakeInstruction(0x16020, 0x16023, "add", "edx, 2"));
    instructions.push_back(MakeInstruction(0x16023, 0x16028, "mov", "eax, 4"));
    instructions.push_back(MakeInstruction(0x16028, 0x1602B, "sub", "eax, 2"));
    instructions.push_back(MakeBranch(0x1602B, 0x1602D, "jmp", 0x16040));
    instructions.push_back(MakeInstruction(0x16030, 0x16031, "ret"));
    instructions.push_back(MakeInstruction(0x16040, 0x16043, "cmp", "eax, 2"));
    instructions.push_back(MakeBranch(0x16043, 0x16045, "ja", 0x16050));
    instructions.push_back(MakeInstruction(0x16045, 0x1604D, "jmp", "qword ptr [rip+rax*8+0x80]"));
    instructions.push_back(MakeInstruction(0x16050, 0x16051, "ret"));

    decomp::DecompOptions options;
    decomp::AnalysisFacts facts = decomp::BuildAnalysisFacts(
        "snapshot!SwitchFlattenedDispatcher",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x16000,
        0x16000,
        regions,
        bytes,
        instructions);

    if (!facts.Switches.empty())
    {
        facts.Switches[0].IndexExpression = "rax*8";
        facts.Switches[0].RangeKnown = true;
        facts.Switches[0].RangeMin = 0;
        facts.Switches[0].RangeMax = 2;
        facts.Switches[0].CaseCount = 3;
        facts.Switches[0].CaseTargets = { 0x16010, 0x16020, 0x16030 };
        facts.Switches[0].DefaultTarget = 0x16050;
        decomp::ApplyRecoveredSwitchTargets(facts);
    }

    return facts;
}

decomp::AnalysisFacts BuildConditionalFlattenedDispatcherFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x17000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x17000, 0x17090 } };
    std::vector<uint8_t> bytes(0x90, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x17000, 0x17005, "mov", "eax, 0"));
    instructions.push_back(MakeBranch(0x17005, 0x17007, "jmp", 0x17060));
    instructions.push_back(MakeInstruction(0x17010, 0x17013, "cmp", "edx, 0"));
    instructions.push_back(MakeInstruction(0x17013, 0x17018, "mov", "eax, 1"));
    instructions.push_back(MakeInstruction(0x17018, 0x1701D, "mov", "r8d, 2"));
    instructions.push_back(MakeInstruction(0x1701D, 0x17022, "cmovne", "eax, r8d"));
    instructions.push_back(MakeBranch(0x17022, 0x17024, "jmp", 0x17060));
    instructions.push_back(MakeInstruction(0x17030, 0x17033, "add", "edx, 4"));
    instructions.push_back(MakeInstruction(0x17033, 0x17038, "mov", "eax, 3"));
    instructions.push_back(MakeBranch(0x17038, 0x1703A, "jmp", 0x17060));
    instructions.push_back(MakeInstruction(0x17040, 0x17041, "ret"));
    instructions.push_back(MakeInstruction(0x17050, 0x17051, "ret"));
    instructions.push_back(MakeInstruction(0x17060, 0x17063, "cmp", "eax, 0"));
    instructions.push_back(MakeBranch(0x17063, 0x17065, "je", 0x17010));
    instructions.push_back(MakeInstruction(0x17065, 0x17068, "cmp", "eax, 1"));
    instructions.push_back(MakeBranch(0x17068, 0x1706A, "je", 0x17030));
    instructions.push_back(MakeInstruction(0x1706A, 0x1706D, "cmp", "eax, 2"));
    instructions.push_back(MakeBranch(0x1706D, 0x1706F, "je", 0x17040));
    instructions.push_back(MakeInstruction(0x1706F, 0x17072, "cmp", "eax, 3"));
    instructions.push_back(MakeBranch(0x17072, 0x17074, "je", 0x17050));
    instructions.push_back(MakeInstruction(0x17074, 0x17075, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!ConditionalFlattenedDispatcher",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x17000,
        0x17000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildOpaquePredicateFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x18000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x18000, 0x18030 } };
    std::vector<uint8_t> bytes(0x30, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x18000, 0x18003, "cmp", "ecx, ecx"));
    instructions.push_back(MakeBranch(0x18003, 0x18005, "je", 0x18010));
    instructions.push_back(MakeInstruction(0x18005, 0x1800A, "mov", "eax, 0xDEAD"));
    instructions.push_back(MakeInstruction(0x1800A, 0x1800B, "ret"));
    instructions.push_back(MakeInstruction(0x18010, 0x18015, "mov", "eax, 1"));
    instructions.push_back(MakeInstruction(0x18015, 0x18016, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!OpaquePredicate",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x18000,
        0x18000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildSubstitutionFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x19000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x19000, 0x19030 } };
    std::vector<uint8_t> bytes(0x30, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x19000, 0x19005, "mov", "eax, 5"));
    instructions.push_back(MakeInstruction(0x19005, 0x19008, "add", "eax, 0"));
    instructions.push_back(MakeInstruction(0x19008, 0x1900B, "xor", "eax, 0"));
    instructions.push_back(MakeInstruction(0x1900B, 0x1900E, "or", "eax, 0"));
    instructions.push_back(MakeInstruction(0x1900E, 0x19011, "shl", "eax, 0"));
    instructions.push_back(MakeInstruction(0x19011, 0x19012, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!Substitution",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x19000,
        0x19000,
        regions,
        bytes,
        instructions);
}

decomp::AnalysisFacts BuildOllvmLikeObfuscatedFacts()
{
    decomp::ModuleInfo module;
    module.ModuleName = "snapshot";
    module.ImageName = "snapshot.exe";
    module.Base = 0x1a000;
    module.Size = 0x1000;

    std::vector<decomp::FunctionRegion> regions = { { 0x1a000, 0x1a0a0 } };
    std::vector<uint8_t> bytes(0xa0, 0x90);
    std::vector<decomp::DisassembledInstruction> instructions;
    instructions.push_back(MakeInstruction(0x1a000, 0x1a005, "mov", "eax, 0"));
    instructions.push_back(MakeBranch(0x1a005, 0x1a007, "jmp", 0x1a080));
    instructions.push_back(MakeInstruction(0x1a010, 0x1a013, "cmp", "ecx, ecx"));
    instructions.push_back(MakeBranch(0x1a013, 0x1a015, "je", 0x1a020));
    instructions.push_back(MakeInstruction(0x1a015, 0x1a01a, "mov", "r9d, 0xDEAD"));
    instructions.push_back(MakeBranch(0x1a01a, 0x1a01c, "jmp", 0x1a080));
    instructions.push_back(MakeInstruction(0x1a020, 0x1a023, "add", "edx, 1"));
    instructions.push_back(MakeInstruction(0x1a023, 0x1a026, "add", "edx, 0"));
    instructions.push_back(MakeInstruction(0x1a026, 0x1a029, "xor", "edx, 0"));
    instructions.push_back(MakeInstruction(0x1a029, 0x1a02e, "mov", "eax, 1"));
    instructions.push_back(MakeBranch(0x1a02e, 0x1a030, "jmp", 0x1a080));
    instructions.push_back(MakeInstruction(0x1a040, 0x1a043, "add", "edx, 2"));
    instructions.push_back(MakeInstruction(0x1a043, 0x1a048, "mov", "eax, 2"));
    instructions.push_back(MakeBranch(0x1a048, 0x1a04a, "jmp", 0x1a080));
    instructions.push_back(MakeInstruction(0x1a060, 0x1a061, "ret"));
    instructions.push_back(MakeInstruction(0x1a080, 0x1a083, "cmp", "eax, 0"));
    instructions.push_back(MakeBranch(0x1a083, 0x1a085, "je", 0x1a010));
    instructions.push_back(MakeInstruction(0x1a085, 0x1a088, "cmp", "eax, 1"));
    instructions.push_back(MakeBranch(0x1a088, 0x1a08a, "je", 0x1a040));
    instructions.push_back(MakeInstruction(0x1a08a, 0x1a08d, "cmp", "eax, 2"));
    instructions.push_back(MakeBranch(0x1a08d, 0x1a08f, "je", 0x1a060));
    instructions.push_back(MakeInstruction(0x1a08f, 0x1a090, "ret"));

    decomp::DecompOptions options;
    return decomp::BuildAnalysisFacts(
        "snapshot!OllvmLikeObfuscated",
        module,
        decomp::DebugSessionKind::User,
        options,
        0x1a000,
        0x1a000,
        regions,
        bytes,
        instructions);
}

void TestAnalyzerSnapshot()
{
    decomp::AnalysisFacts facts = BuildDiamondFacts();
    decomp::AnalyzeRequest request;
    request.RequestId = "snapshot";
    request.Facts = facts;

    Expect(facts.Blocks.size() == 4, "diamond fixture should recover four basic blocks");
    Expect(!facts.ValueMerges.empty(), "diamond fixture should produce a stack-slot value merge");

    bool foundSlotMerge = false;

    for (const decomp::ValueMerge& merge : facts.ValueMerges)
    {
        if (merge.Variable == "local_20" && ContainsString(merge.IncomingValues, "1") && ContainsString(merge.IncomingValues, "2"))
        {
            foundSlotMerge = true;
        }
    }

    Expect(foundSlotMerge, "value merge snapshot should preserve both branch-local stack values");

    const decomp::ControlFlowRegion* branch = FindRegion(facts, "if_else_candidate");
    Expect(branch != nullptr, "control-flow snapshot should include an if/else candidate");
    Expect(branch != nullptr && ContainsString(branch->ExitBlocks, "bb3"), "if/else candidate should use post-dominator join bb3");
    Expect(branch != nullptr && branch->Evidence.find("postdominator join") != std::string::npos, "if/else evidence should mention post-dominator join");

    const decomp::BlockValueState* joinState = nullptr;

    for (const decomp::BlockValueState& state : facts.BlockValueStates)
    {
        if (state.BlockId == "bb3")
        {
            joinState = &state;
        }
    }

    Expect(joinState != nullptr, "block value states should include the diamond join block");
    Expect(joinState != nullptr && joinState->Converged, "block value dataflow should converge for the diamond fixture");
    Expect(joinState != nullptr && ContainsReachingValueName(joinState->LiveIn, "r10"), "block value state should preserve common reaching register definitions");
    Expect(joinState != nullptr && !ContainsReachingValueName(joinState->LiveIn, "local_20"), "conflicting stack local definitions should not appear as a single live-in value");

    bool foundEvidenceIrNode = false;
    bool foundEvidenceBlockState = false;
    bool foundEvidenceLiveInEdge = false;
    bool foundEvidenceBlockEdge = false;

    for (const decomp::EvidenceNode& node : facts.EvidenceGraph.Nodes)
    {
        if (node.Kind == "ir_value" && node.Site == 0x1020 && node.BlockId == "bb3")
        {
            foundEvidenceIrNode = true;
        }
        else if (node.Kind == "block_value_state" && node.BlockId == "bb3")
        {
            foundEvidenceBlockState = true;
        }
    }

    for (const decomp::EvidenceEdge& edge : facts.EvidenceGraph.Edges)
    {
        if (edge.Relation == "in_block" && edge.SourceId.find("ir:") == 0 && edge.TargetId == "block:bb3")
        {
            foundEvidenceBlockEdge = true;
        }
        else if (edge.Relation == "live_in" && edge.TargetId == "block_state:bb3")
        {
            foundEvidenceLiveInEdge = true;
        }
    }

    Expect(foundEvidenceBlockState, "evidence graph should expose block value state nodes");
    Expect(foundEvidenceLiveInEdge, "evidence graph should connect reaching definitions to block value states");
    Expect(foundEvidenceIrNode, "evidence graph should expose IR value nodes with block grounding");
    Expect(foundEvidenceBlockEdge, "evidence graph should link semantic facts back to basic blocks");
    Expect(facts.EvidenceGraph.Coverage > 0.0, "evidence graph should report semantic grounding coverage");

    const std::string serialized = decomp::SerializeAnalyzeRequest(request, true);
    Expect(serialized.find("\"value_merges\"") != std::string::npos, "request snapshot should serialize value_merges");
    Expect(serialized.find("\"control_flow\"") != std::string::npos, "request snapshot should serialize control_flow");
    Expect(serialized.find("\"block_value_states\"") != std::string::npos, "request snapshot should serialize block_value_states");
    Expect(serialized.find("\"evidence_graph\"") != std::string::npos, "request snapshot should serialize evidence_graph");

    const std::string promptDump = decomp::BuildDebugPromptDump(request);
    Expect(promptDump.find("\"graph_summary\"") != std::string::npos, "prompt snapshot should include graph_summary");
    Expect(promptDump.find("\"analyzer_skeleton\"") != std::string::npos, "prompt snapshot should include analyzer_skeleton");
    Expect(promptDump.find("\"block_value_states\"") != std::string::npos, "prompt snapshot should include block_value_states");
    Expect(promptDump.find("\"evidence_graph\"") != std::string::npos, "prompt snapshot should include evidence_graph");
}

void TestIrUseSnapshot()
{
    const decomp::AnalysisFacts facts = BuildIrOverwriteFacts();
    const decomp::IrValue* firstRax = nullptr;
    const decomp::IrValue* secondRax = nullptr;
    const decomp::IrValue* addRax = nullptr;

    for (const decomp::IrValue& value : facts.IrValues)
    {
        if (value.DefSite == 0x2000)
        {
            firstRax = &value;
        }
        else if (value.DefSite == 0x2005)
        {
            secondRax = &value;
        }
        else if (value.DefSite == 0x2008)
        {
            addRax = &value;
        }
    }

    Expect(firstRax != nullptr && firstRax->IsDead, "overwritten rax constant should remain dead");
    Expect(secondRax != nullptr && secondRax->Uses.empty(), "mov rax, rdx should not use the previous rax definition");
    Expect(secondRax != nullptr && !secondRax->IsDead, "mov rax, rdx should stay live because add rax, 2 consumes it");
    Expect(addRax != nullptr && secondRax != nullptr && ContainsString(addRax->Uses, secondRax->Id), "add rax, 2 should use the rax definition produced by mov rax, rdx");

    bool recoveredRcxArgument = false;
    bool recoveredR8PointerArgument = false;

    for (const decomp::RecoveredArgument& argument : facts.RecoveredArguments)
    {
        if (argument.Register == "rcx")
        {
            recoveredRcxArgument = true;
        }
        else if (argument.Register == "r8" && argument.RoleHint == "pointer_like")
        {
            recoveredR8PointerArgument = true;
        }
    }

    Expect(!recoveredRcxArgument, "xor rcx, rcx should not create a false incoming rcx argument");
    Expect(recoveredR8PointerArgument, "mov [r8], rax should read r8 as a pointer argument for address calculation");
}

void TestSwitchTargetPropagationSnapshot()
{
    decomp::AnalysisFacts facts = BuildSwitchTargetFacts();
    Expect(!facts.Switches.empty(), "switch target fixture should detect an indirect jump switch");
    Expect(!facts.Switches.empty() && facts.Switches[0].RangeKnown && facts.Switches[0].RangeMax == 2, "switch guard should recover an unsigned index range");
    Expect(!facts.Switches.empty() && facts.Switches[0].DefaultTarget == 0x3014, "switch guard should recover the default target");

    facts.Switches[0].TableAddress = 0x3800;
    facts.Switches[0].IndexExpression = "rcx*8";
    facts.Switches[0].CaseCount = 3;
    facts.Switches[0].CaseTargets = { 0x300e, 0x3010, 0x3014 };
    decomp::ApplyRecoveredSwitchTargets(facts);

    const decomp::BasicBlock* header = FindBlockContaining(facts, 0x3006);
    const decomp::BasicBlock* firstCase = FindBlockStartingAt(facts, 0x300e);
    const decomp::BasicBlock* splitCase = FindBlockStartingAt(facts, 0x3010);
    const decomp::BasicBlock* defaultCase = FindBlockStartingAt(facts, 0x3014);

    Expect(header != nullptr, "switch header block should still contain the indirect jump");
    Expect(firstCase != nullptr, "first switch case should remain a block start");
    Expect(splitCase != nullptr, "case target inside an existing block should split a new block");
    Expect(defaultCase != nullptr, "default switch case should be a block start");
    Expect(header != nullptr && splitCase != nullptr && ContainsString(header->Successors, splitCase->Id), "switch header should gain the split case successor");
    Expect(header != nullptr && defaultCase != nullptr && ContainsString(header->Successors, defaultCase->Id), "switch header should gain recovered default successor");

    const decomp::ControlFlowRegion* switchRegion = FindRegion(facts, "switch_candidate");
    Expect(switchRegion != nullptr && splitCase != nullptr && ContainsString(switchRegion->BodyBlocks, splitCase->Id), "switch control-flow region should include recovered case target blocks after refresh");
}

void TestFlagClobberSnapshot()
{
    const decomp::AnalysisFacts facts = BuildFlagClobberFacts();
    Expect(facts.NormalizedConditions.empty(), "flags-writing instruction between cmp and branch should prevent stale branch condition reuse");
}

void TestImplicitAndCallSnapshot()
{
    const decomp::AnalysisFacts facts = BuildImplicitAndCallFacts();
    bool hasPush = false;
    bool hasCallReturnWrite = false;
    bool hasRetRead = false;
    bool hasMovsSource = false;
    bool hasMovsDestination = false;

    for (const decomp::MemoryAccess& access : facts.MemoryAccesses)
    {
        hasPush = hasPush || (access.Implicit && access.Semantic == "push_stack_write");
        hasCallReturnWrite = hasCallReturnWrite || (access.Implicit && access.Semantic == "call_return_address_write");
        hasRetRead = hasRetRead || (access.Implicit && access.Semantic == "ret_return_address_read");
        hasMovsSource = hasMovsSource || (access.Implicit && access.Semantic == "movs_source_read");
        hasMovsDestination = hasMovsDestination || (access.Implicit && access.Semantic == "movs_destination_write");
    }

    Expect(hasPush, "push should emit an implicit stack write memory access");
    Expect(hasCallReturnWrite, "call should emit an implicit return-address stack write");
    Expect(hasRetRead, "ret should emit an implicit return-address stack read");
    Expect(hasMovsSource, "movsb with explicit operands should still emit an implicit string source read");
    Expect(hasMovsDestination, "movsb with explicit operands should still emit an implicit string destination write");
    Expect(facts.RecoveredLocals.empty(), "implicit call/ret/push stack effects should not create false stack locals");

    const decomp::IrValue* movRdx = nullptr;
    const decomp::IrValue* movRax = nullptr;
    const decomp::IrValue* xorAl = nullptr;
    const decomp::IrValue* addRdx = nullptr;

    for (const decomp::IrValue& value : facts.IrValues)
    {
        if (value.DefSite == 0x5001)
        {
            movRdx = &value;
        }
        else if (value.DefSite == 0x5006)
        {
            movRax = &value;
        }
        else if (value.DefSite == 0x5009)
        {
            xorAl = &value;
        }
        else if (value.DefSite == 0x5010)
        {
            addRdx = &value;
        }
    }

    Expect(xorAl != nullptr && movRax != nullptr && ContainsString(xorAl->Uses, movRax->Id), "partial self-xor should merge with and use the previous full register value");
    Expect(xorAl != nullptr && xorAl->Expression.find("merge_partial") != std::string::npos, "partial self-xor should not be promoted to full-register zero");
    Expect(addRdx != nullptr && movRdx != nullptr && !ContainsString(addRdx->Uses, movRdx->Id), "call clobber should prevent stale volatile register definitions from reaching later uses");

    bool foundCallArg2 = false;

    for (const decomp::CallArgumentFact& argument : facts.CallArguments)
    {
        if (argument.Site == 0x500b && argument.Ordinal == 2 && argument.Location == "rdx" && argument.Expression == "5")
        {
            foundCallArg2 = true;
        }
    }

    Expect(foundCallArg2, "call-site argument facts should capture rdx=5 before the call");
}

void TestCallArgumentStackWindowSnapshot()
{
    const decomp::AnalysisFacts facts = BuildStackCallArgumentWindowFacts();
    bool foundFreshStackArg5 = false;
    bool foundStaleStackArg5 = false;

    for (const decomp::CallArgumentFact& argument : facts.CallArguments)
    {
        if (argument.Ordinal != 5 || argument.Source != "stack_store")
        {
            continue;
        }

        if (argument.Site == 0x700c)
        {
            foundFreshStackArg5 = true;
        }
        else if (argument.Site == 0x7037)
        {
            foundStaleStackArg5 = true;
        }
    }

    Expect(foundFreshStackArg5, "nearby stack store should be recovered as a fifth call argument");
    Expect(!foundStaleStackArg5, "old stack stores should not leak into a later unrelated call");

    const decomp::AnalysisFacts crossBlockFacts = BuildCrossBlockStackCallArgumentFacts();
    bool foundCrossBlockStackArg5 = false;

    for (const decomp::CallArgumentFact& argument : crossBlockFacts.CallArguments)
    {
        if (argument.Site == 0x7818 && argument.Ordinal == 5 && argument.Source == "stack_store")
        {
            foundCrossBlockStackArg5 = true;
        }
    }

    Expect(foundCrossBlockStackArg5, "stack call arguments should flow across a direct predecessor block");
}

void TestCfgSensitiveFactsSnapshot()
{
    const decomp::AnalysisFacts stackFacts = BuildCfgStackFacts();
    bool foundBranchStackAccess = false;

    for (const decomp::MemoryAccess& access : stackFacts.MemoryAccesses)
    {
        if (access.Site == 0x8010 && access.StackFrameRelative && access.FrameOffset == -0x18)
        {
            foundBranchStackAccess = true;
        }
    }

    Expect(foundBranchStackAccess, "stack pointer tracking should use CFG predecessor state for out-of-line branch targets");

    const decomp::AnalysisFacts loopStackFacts = BuildLoopStackFacts();
    bool foundLoopStackAccess = false;

    for (const decomp::MemoryAccess& access : loopStackFacts.MemoryAccesses)
    {
        if (access.Site == 0x880a && access.StackFrameRelative && access.FrameOffset == -0x18)
        {
            foundLoopStackAccess = true;
        }
    }

    Expect(foundLoopStackAccess, "loop back-edges should not poison stack pointer facts before predecessor states converge");

    const decomp::AnalysisFacts callFacts = BuildCfgCallArgumentFacts();
    bool leakedMergedRcx = false;

    for (const decomp::CallArgumentFact& argument : callFacts.CallArguments)
    {
        if (argument.Site == 0x9010 && argument.Ordinal == 1)
        {
            leakedMergedRcx = true;
        }
    }

    Expect(!leakedMergedRcx, "conflicting predecessor register values should not be emitted as call-site arguments");
}

void TestStackAliasSnapshot()
{
    const decomp::AnalysisFacts facts = BuildStackAliasFacts();
    bool foundAliasAccess = false;
    bool foundAliasLocal = false;

    for (const decomp::MemoryAccess& access : facts.MemoryAccesses)
    {
        if (access.Site == 0xa009
            && access.BaseRegister == "rax"
            && access.StackFrameRelative
            && access.FrameOffset == -0x18)
        {
            foundAliasAccess = true;
        }
    }

    for (const decomp::RecoveredLocal& local : facts.RecoveredLocals)
    {
        if (local.BaseRegister == "frame"
            && local.RawBaseRegister == "rax"
            && local.Offset == -0x18)
        {
            foundAliasLocal = true;
        }
    }

    Expect(foundAliasAccess, "rsp-derived register aliases should annotate stack-frame-relative memory accesses");
    Expect(foundAliasLocal, "rsp-derived register aliases should participate in recovered local grouping");

    const decomp::AnalysisFacts homeFacts = BuildStackAliasHomeFacts();
    bool foundAliasHomeSlot = false;
    bool foundAliasTypeHint = false;

    for (const std::string& slot : homeFacts.Abi.HomeSlots)
    {
        if (slot.find("frame0x8") != std::string::npos && slot.find("via rax") != std::string::npos)
        {
            foundAliasHomeSlot = true;
        }
    }

    for (const decomp::TypeRecoveryHint& hint : homeFacts.TypeHints)
    {
        if (hint.Site == 0xa809 && hint.Source == "stack_frame_alias" && hint.Kind == "stack_home_slot")
        {
            foundAliasTypeHint = true;
        }
    }

    Expect(foundAliasHomeSlot, "rsp-derived aliases should contribute ABI home-slot facts");
    Expect(foundAliasTypeHint, "rsp-derived aliases should contribute stack-frame type hints");
}

void TestTailCallSnapshot()
{
    const decomp::AnalysisFacts facts = BuildTailCallFacts();
    bool foundAbiTailCall = false;
    bool foundCallTargetTailCall = false;
    bool foundCalleeSummaryTailCall = false;
    bool foundTailCallArgument = false;

    for (const std::string& tailCall : facts.Abi.TailCalls)
    {
        foundAbiTailCall = foundAbiTailCall || tailCall.find("0xB004") != std::string::npos;
    }

    for (const decomp::CallTargetInfo& target : facts.CallTargets)
    {
        if (target.Site == 0xb004 && target.TailCall && target.TargetAddress == 0xc000)
        {
            foundCallTargetTailCall = true;
        }
    }

    for (const decomp::CalleeSummary& summary : facts.CalleeSummaries)
    {
        if (summary.Site == 0xb004 && summary.TailCall && summary.Source == "tail_call_target")
        {
            foundCalleeSummaryTailCall = true;
        }
    }

    for (const decomp::CallArgumentFact& argument : facts.CallArguments)
    {
        if (argument.Site == 0xb004 && argument.Ordinal == 1 && argument.Location == "rcx")
        {
            foundTailCallArgument = true;
        }
    }

    Expect(foundAbiTailCall, "ABI facts should preserve direct tail-call jumps");
    Expect(foundCallTargetTailCall, "tail-call jumps should become first-class call targets");
    Expect(foundCalleeSummaryTailCall, "tail-call targets should become callee summaries");
    Expect(foundTailCallArgument, "tail-call sites should receive call argument facts");
}

void TestConditionalMoveSnapshot()
{
    const decomp::AnalysisFacts facts = BuildCmovFacts();
    const decomp::IrValue* cmovValue = nullptr;
    const decomp::IrValue* cmovAliasValue = nullptr;

    for (const decomp::IrValue& value : facts.IrValues)
    {
        if (value.DefSite == 0xd006)
        {
            cmovValue = &value;
        }
        else if (value.DefSite == 0xd00d)
        {
            cmovAliasValue = &value;
        }
    }

    Expect(cmovValue != nullptr, "cmov should produce an IR value");
    Expect(cmovValue != nullptr && cmovValue->Kind == "conditional_select", "cmov should be classified as a conditional select");
    Expect(cmovValue != nullptr && cmovValue->Expression.find("select(") != std::string::npos, "cmov expression should use a select form");
    Expect(cmovValue != nullptr && cmovValue->Expression.find("<") != std::string::npos, "cmov select expression should preserve the compare condition");
    Expect(cmovAliasValue != nullptr && cmovAliasValue->Kind == "conditional_select", "cmov negative aliases should also become conditional selects");
    Expect(cmovAliasValue != nullptr && cmovAliasValue->Expression.find(">=") != std::string::npos, "cmovnl should normalize to a signed >= condition");
}

void TestObfuscationFactsSnapshot()
{
    const decomp::AnalysisFacts facts = BuildFlattenedDispatcherFacts();
    const decomp::ObfuscationDispatcher* dispatcher = FindHighConfidenceDispatcher(facts);
    Expect(dispatcher != nullptr, "flattened dispatcher fixture should recover a high-confidence dispatcher");
    Expect(dispatcher != nullptr && dispatcher->Kind == "control_flow_flattening_dispatcher", "dispatcher kind should describe control-flow flattening");
    Expect(dispatcher != nullptr && dispatcher->StateVariable == "rax", "state variable should use canonical register spelling");
    Expect(dispatcher != nullptr && dispatcher->RecoveredEdges.size() >= 2, "flattened dispatcher should recover semantic state edges");

    bool foundStateVariable = false;
    std::string observedStateVariable;
    uint32_t observedWriteCount = 0;
    uint32_t observedReadCount = 0;

    for (const decomp::ObfuscationStateVariable& variable : facts.Obfuscation.StateVariables)
    {
        observedStateVariable = variable.Name;
        observedWriteCount = variable.WriteCount;
        observedReadCount = variable.ReadCount;

        if (variable.Name == "rax" && variable.WriteCount >= 3 && variable.ReadCount >= 3)
        {
            foundStateVariable = true;
        }
    }

    Expect(
        foundStateVariable,
        "obfuscation facts should expose the dispatcher state variable, observed="
            + observedStateVariable
            + " writes="
            + std::to_string(observedWriteCount)
            + " reads="
            + std::to_string(observedReadCount));

    const decomp::BasicBlock* entry = FindBlockStartingAt(facts, 0x13000);
    const decomp::BasicBlock* firstBody = FindBlockStartingAt(facts, 0x13010);
    bool foundRecoveredEntryEdge = false;
    bool foundSemanticEntryEdge = false;

    if (dispatcher != nullptr && entry != nullptr && firstBody != nullptr)
    {
        for (const decomp::RecoveredControlFlowEdge& edge : dispatcher->RecoveredEdges)
        {
            if (edge.SourceBlock == entry->Id && edge.TargetBlock == firstBody->Id && edge.StateValue == "0x0")
            {
                foundRecoveredEntryEdge = true;
            }
        }

        for (const decomp::SemanticControlFlowEdge& edge : facts.SemanticControlFlow.Edges)
        {
            if (edge.SourceBlock == entry->Id
                && edge.TargetBlock == firstBody->Id
                && edge.StateValue == "0x0"
                && !edge.Dead
                && edge.Source == "obfuscation.recovered_edge")
            {
                foundSemanticEntryEdge = true;
            }
        }
    }

    Expect(foundRecoveredEntryEdge, "recovered edges should map state constants back to original body blocks");
    Expect(foundSemanticEntryEdge, "semantic CFG overlay should expose recovered dispatcher edges");
    Expect(ContainsFactSubstring(facts, "obfuscation dispatcher: header="), "deterministic facts should describe dispatcher evidence");
    Expect(ContainsFactSubstring(facts, "obfuscation state variable: name=rax"), "deterministic facts should describe dispatcher state variable evidence");
    Expect(ContainsFactSubstring(facts, "obfuscation recovered edge: source="), "deterministic facts should describe recovered edge evidence");
    Expect(ContainsFactSubstring(facts, "semantic control-flow overlay: live_edges="), "deterministic facts should summarize semantic CFG overlay evidence");
    Expect(facts.DeobfuscationReadiness.Enabled, "deobfuscation readiness should default to enabled");
    Expect(facts.DeobfuscationReadiness.HasFlatteningDispatcher, "deobfuscation readiness should flag the flattening dispatcher");
    Expect(facts.DeobfuscationReadiness.HasHighConfidenceDispatcherEdges, "deobfuscation readiness should see high-confidence dispatcher edges");
    Expect(facts.DeobfuscationReadiness.SafeToRewriteControlFlow, "deobfuscation readiness should allow semantic CFG rewrite for recovered flattened flow");
    Expect(ContainsString(facts.DeobfuscationReadiness.SafeActions, "recover_dispatcher_edges"), "deobfuscation readiness should expose dispatcher recovery action");
    Expect(ContainsString(facts.DeobfuscationReadiness.SafeActions, "apply_semantic_control_flow_overlay"), "deobfuscation readiness should expose semantic overlay action");
    Expect(ContainsFactSubstring(facts, "deobfuscation readiness: mode=on"), "deterministic facts should summarize deobfuscation readiness mode");
    Expect(HasEvidenceNodeKind(facts, "obfuscation.dispatcher"), "evidence graph should expose obfuscation dispatcher nodes");
    Expect(HasEvidenceNodeKind(facts, "obfuscation.state_variable"), "evidence graph should expose obfuscation state-variable nodes");
    Expect(HasEvidenceNodeKind(facts, "obfuscation.recovered_edge"), "evidence graph should expose recovered obfuscation edges");
    Expect(HasEvidenceNodeKind(facts, "semantic_cfg.edge"), "evidence graph should expose semantic CFG edge nodes");
    Expect(HasEvidenceEdgeRelation(facts, "writes_state"), "evidence graph should link state-writing blocks to state variables");

    decomp::AnalyzeRequest request;
    request.RequestId = "obfuscation_snapshot";
    request.Facts = facts;

    const std::string serialized = decomp::SerializeAnalyzeRequest(request, true);
    Expect(serialized.find("\"obfuscation\"") != std::string::npos, "request snapshot should serialize obfuscation facts");
    Expect(serialized.find("\"recovered_edges\"") != std::string::npos, "request snapshot should serialize recovered obfuscation edges");
    Expect(serialized.find("\"semantic_control_flow\"") != std::string::npos, "request snapshot should serialize semantic CFG overlay");
    Expect(serialized.find("\"deobfuscation_readiness\"") != std::string::npos, "request snapshot should serialize deobfuscation readiness");

    decomp::AnalyzeRequest parsed;
    std::string error;
    Expect(decomp::ParseAnalyzeRequest(serialized, parsed, error), "obfuscation request should parse after serialization");
    Expect(!parsed.Facts.Obfuscation.Dispatchers.empty(), "obfuscation dispatchers should round-trip through protocol JSON");
    Expect(!parsed.Facts.Obfuscation.Dispatchers.empty() && parsed.Facts.Obfuscation.Dispatchers.front().RecoveredEdges.size() >= 2, "recovered obfuscation edges should round-trip through protocol JSON");
    Expect(parsed.Facts.SemanticControlFlow.Edges.size() >= 2, "semantic CFG overlay should round-trip through protocol JSON");
    Expect(parsed.Facts.DeobfuscationReadiness.Enabled, "deobfuscation readiness enabled flag should round-trip through protocol JSON");
    Expect(parsed.Facts.DeobfuscationReadiness.SafeToRewriteControlFlow, "deobfuscation readiness should round-trip through protocol JSON");
    Expect(ContainsString(parsed.Facts.DeobfuscationReadiness.SafeActions, "recover_dispatcher_edges"), "deobfuscation readiness safe actions should round-trip");

    const std::string promptDump = decomp::BuildDebugPromptDump(request);
    Expect(promptDump.find("\"obfuscation\"") != std::string::npos, "prompt dump should include obfuscation facts");
    Expect(promptDump.find("\"semantic_control_flow\"") != std::string::npos, "prompt dump should include semantic CFG overlay");
    Expect(promptDump.find("\"deobfuscation_readiness\"") != std::string::npos, "prompt dump should include deobfuscation readiness");
    Expect(promptDump.find("\"safe_actions\"") != std::string::npos, "prompt dump should include deobfuscation readiness actions");
    Expect(promptDump.find("semantic edge:") != std::string::npos, "analyzer skeleton should render semantic CFG comments");
    Expect(promptDump.find("\"usage_guidance\"") != std::string::npos, "prompt dump should include obfuscation usage guidance");

    decomp::DecompOptions deobfuscationOffOptions;
    deobfuscationOffOptions.DeobfuscationEnabled = false;
    const decomp::AnalysisFacts deobfuscationOffFacts = BuildFlattenedDispatcherFacts(deobfuscationOffOptions);
    Expect(!deobfuscationOffFacts.DeobfuscationReadiness.Enabled, "deobfuscation readiness should honor disabled option");
    Expect(deobfuscationOffFacts.DeobfuscationReadiness.HasFlatteningDispatcher, "deobfuscation disabled mode should still detect flattening facts");
    Expect(deobfuscationOffFacts.DeobfuscationReadiness.HasHighConfidenceDispatcherEdges, "deobfuscation disabled mode should still detect dispatcher edges");
    Expect(!deobfuscationOffFacts.DeobfuscationReadiness.SafeToRewriteControlFlow, "deobfuscation disabled mode should block control-flow rewrite");
    Expect(deobfuscationOffFacts.DeobfuscationReadiness.SafeActions.empty(), "deobfuscation disabled mode should not expose rewrite safe actions");
    Expect(ContainsString(deobfuscationOffFacts.DeobfuscationReadiness.BlockedAssumptions, "deobfuscation_disabled_by_option"), "deobfuscation disabled mode should expose disabled policy");

    decomp::AnalyzeRequest deobfuscationOffRequest;
    deobfuscationOffRequest.RequestId = "obfuscation_deobf_off_snapshot";
    deobfuscationOffRequest.Facts = deobfuscationOffFacts;

    const std::string deobfuscationOffSerialized = decomp::SerializeAnalyzeRequest(deobfuscationOffRequest, true);
    decomp::AnalyzeRequest parsedDeobfuscationOff;
    Expect(decomp::ParseAnalyzeRequest(deobfuscationOffSerialized, parsedDeobfuscationOff, error), "deobfuscation disabled request should parse after serialization");
    Expect(!parsedDeobfuscationOff.Facts.DeobfuscationReadiness.Enabled, "deobfuscation disabled flag should round-trip through protocol JSON");
    Expect(parsedDeobfuscationOff.Facts.DeobfuscationReadiness.HasFlatteningDispatcher, "deobfuscation disabled mode should keep flattening facts after round-trip");

    const std::string deobfuscationOffPromptDump = decomp::BuildDebugPromptDump(deobfuscationOffRequest);
    Expect(deobfuscationOffPromptDump.find("\"mode\": \"off\"") != std::string::npos, "deobfuscation disabled prompt should expose off mode");
    Expect(deobfuscationOffPromptDump.find("Deobfuscation is disabled by command option") != std::string::npos, "deobfuscation disabled prompt should explain raw CFG preservation");

    decomp::LlmClientConfig deobfuscationOffChunkConfig;
    deobfuscationOffChunkConfig.ChunkBlockLimit = 4;
    deobfuscationOffChunkConfig.ChunkCountLimit = 8;

    const std::string deobfuscationOffMergePromptDump = decomp::BuildDebugMergePromptDump(deobfuscationOffRequest, deobfuscationOffChunkConfig);
    Expect(!deobfuscationOffMergePromptDump.empty(), "deobfuscation disabled debug merge prompt dump should be available");

    const decomp::JsonValue deobfuscationOffMergeFactsJson = ParseDebugMergeFactsJson(deobfuscationOffMergePromptDump);
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_obfuscation_policy", "enabled" }, false, "deobfuscation disabled merge obfuscation policy should expose disabled state");
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_obfuscation_policy", "has_flattening_dispatcher" }, true, "deobfuscation disabled merge policy should keep flattening facts visible");
    ExpectJsonStringArrayContains(deobfuscationOffMergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_rewrite_rules" }, "preserve_raw_obfuscated_structure", "deobfuscation disabled merge policy should preserve raw obfuscated structure");
    ExpectJsonStringArrayContains(deobfuscationOffMergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_uncertainty_rules" }, "deobfuscation_disabled_by_option", "deobfuscation disabled merge policy should expose disabled uncertainty");
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "enabled" }, false, "deobfuscation disabled merge plan should expose disabled state");
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "safe_to_rewrite_obfuscated_cfg" }, false, "deobfuscation disabled merge plan should block obfuscated CFG rewrites");
    ExpectJsonStringArrayContains(deobfuscationOffMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "deobfuscation_actions" }, "preserve_raw_obfuscated_structure", "deobfuscation disabled plan should preserve raw structure");
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "requires_pseudo_c_deobfuscation_review" }, false, "deobfuscation disabled output contract should not require pseudo-C deobfuscation review");
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "safe_to_emit_deobfuscated_structure" }, false, "deobfuscation disabled output contract should block deobfuscated structure");
    ExpectJsonBooleanValue(deobfuscationOffMergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "requires_conflict_resolution" }, false, "deobfuscation disabled conflict policy should not require rewrite conflict resolution");

    const decomp::AnalysisFacts negativeStateSwitchFacts = BuildLegitimateStateSwitchFacts();
    Expect(!negativeStateSwitchFacts.DeobfuscationReadiness.SafeToRewriteControlFlow, "negative state-machine fixture should not mark CFG rewrite safe");
    Expect(!negativeStateSwitchFacts.DeobfuscationReadiness.HasFlatteningDispatcher, "negative state-machine fixture should not report a flattening dispatcher");

    decomp::AnalyzeRequest chunkScopedRequest;
    chunkScopedRequest.RequestId = "obfuscation_chunk_scope_snapshot";
    chunkScopedRequest.Facts = facts;
    chunkScopedRequest.Facts.Arch = "MERGE_ARCH_MARKER";
    chunkScopedRequest.Facts.Mode = decomp::AnalysisMode::LiveMemory;
    chunkScopedRequest.Facts.QueryAddress = 0x42424242;
    chunkScopedRequest.Facts.Rva = 0x31313131;
    chunkScopedRequest.Facts.Module.LoadedImageName = "CHUNK_MERGE_LOADED_IMAGE_MARKER.sys";
    chunkScopedRequest.Facts.Module.SymbolType = 424242;
    chunkScopedRequest.Facts.Abi.FrameBase = "CHUNK_ABI_FRAME_BASE_MARKER";
    chunkScopedRequest.Facts.Abi.HomeSlots.push_back("CHUNK_ABI_HOME_SLOT_MARKER");
    chunkScopedRequest.Facts.Abi.NoReturnCalls.push_back("CHUNK_ABI_NO_RETURN_MARKER");
    chunkScopedRequest.Facts.Abi.Notes.push_back("CHUNK_ABI_NOTE_MARKER");
    chunkScopedRequest.Facts.SessionPolicy.ExecutionKind = "CHUNK_SESSION_EXECUTION_MARKER";
    chunkScopedRequest.Facts.SessionPolicy.AnalysisStrategy = "CHUNK_SESSION_STRATEGY_MARKER";
    chunkScopedRequest.Facts.SessionPolicy.Notes.push_back("CHUNK_SESSION_NOTE_MARKER");

    decomp::SubstitutionIdiomFact outsideChunkIdiom;
    outsideChunkIdiom.BlockId = "bb_outside_chunk";
    outsideChunkIdiom.OriginalExpression = "OUTSIDE_CHUNK_OBF_MARKER";
    outsideChunkIdiom.SimplifiedExpression = "outside";
    outsideChunkIdiom.Pattern = "outside_chunk_marker";
    outsideChunkIdiom.Confidence = 0.99;
    chunkScopedRequest.Facts.Obfuscation.SubstitutionIdioms.push_back(outsideChunkIdiom);
    chunkScopedRequest.Facts.Facts.insert(
        chunkScopedRequest.Facts.Facts.begin(),
        "obfuscation substitution: block=bb_outside_chunk, original=OUTSIDE_CHUNK_FACT_MARKER => simplified=outside, confidence=0.99");
    chunkScopedRequest.Facts.UncertainPoints.insert(
        chunkScopedRequest.Facts.UncertainPoints.begin(),
        "obfuscation recovered edge: source=bb_outside_uncertainty, target=bb_other_outside_uncertainty, uncertainty=OUTSIDE_CHUNK_UNCERTAINTY_MARKER");
    chunkScopedRequest.Facts.UncertainPoints.insert(
        chunkScopedRequest.Facts.UncertainPoints.begin(),
        "GLOBAL_CHUNK_SAFE_UNCERTAINTY_MARKER");

    decomp::SemanticControlFlowEdge outsideChunkEdge;
    outsideChunkEdge.SourceBlock = "bb_outside_chunk";
    outsideChunkEdge.TargetBlock = "bb_other_outside_chunk";
    outsideChunkEdge.Evidence = "OUTSIDE_CHUNK_SEMANTIC_MARKER";
    outsideChunkEdge.Source = "test.outside_chunk";
    outsideChunkEdge.Confidence = 0.99;
    chunkScopedRequest.Facts.SemanticControlFlow.Edges.push_back(outsideChunkEdge);

    decomp::NormalizedCondition outsideChunkCondition;
    outsideChunkCondition.BlockId = "bb_outside_condition";
    outsideChunkCondition.Expression = "OUTSIDE_CHUNK_CONDITION_MARKER";
    outsideChunkCondition.TrueTargetBlock = "bb_outside_true";
    outsideChunkCondition.FalseTargetBlock = "bb_outside_false";
    outsideChunkCondition.Confidence = 0.99;
    chunkScopedRequest.Facts.NormalizedConditions.push_back(outsideChunkCondition);

    decomp::ControlFlowRegion insideChunkRegion;
    insideChunkRegion.Kind = "INSIDE_CHUNK_CONTROL_FLOW_MARKER";
    insideChunkRegion.HeaderBlock = entry != nullptr ? entry->Id : std::string();
    insideChunkRegion.BodyBlocks.push_back(insideChunkRegion.HeaderBlock);
    insideChunkRegion.Condition = "inside_chunk_control_condition";
    insideChunkRegion.Evidence = "INSIDE_CHUNK_CONTROL_FLOW_EVIDENCE_MARKER";
    insideChunkRegion.InductionVariable = "inside_i";
    insideChunkRegion.InitialValue = "0";
    insideChunkRegion.Step = "+1";
    insideChunkRegion.Bound = "inside_limit";
    insideChunkRegion.Direction = "forward";
    insideChunkRegion.Confidence = 0.99;
    chunkScopedRequest.Facts.ControlFlow.insert(chunkScopedRequest.Facts.ControlFlow.begin(), insideChunkRegion);

    decomp::ControlFlowRegion outsideChunkRegion;
    outsideChunkRegion.Kind = "OUTSIDE_CHUNK_REGION_MARKER";
    outsideChunkRegion.HeaderBlock = "bb_outside_region";
    outsideChunkRegion.BodyBlocks.push_back("bb_outside_region_body");
    outsideChunkRegion.Confidence = 0.99;
    chunkScopedRequest.Facts.ControlFlow.insert(chunkScopedRequest.Facts.ControlFlow.begin(), outsideChunkRegion);

    decomp::BasicBlock outsideChunkBlock;
    outsideChunkBlock.Id = "bb_outside_important";
    outsideChunkBlock.StartAddress = 0x77770000;
    outsideChunkBlock.EndAddress = 0x77770010;
    outsideChunkBlock.InstructionAddresses.push_back(0x77770000);
    chunkScopedRequest.Facts.Blocks.push_back(outsideChunkBlock);

    const uint64_t insideChunkSite = entry != nullptr && !entry->InstructionAddresses.empty()
        ? entry->InstructionAddresses.front()
        : 0x13000;

    chunkScopedRequest.Facts.ObservedBehavior.InstructionPointer = insideChunkSite;
    chunkScopedRequest.Facts.ObservedBehavior.StackPointer = 0x7777ABCD;
    chunkScopedRequest.Facts.ObservedBehavior.CurrentInstructionInFunction = true;

    decomp::ObservedArgumentValue chunkObservedArgument;
    chunkObservedArgument.Name = "arg_observed";
    chunkObservedArgument.Register = "rcx";
    chunkObservedArgument.Value = 0x7777C0DE;
    chunkObservedArgument.Symbol = "CHUNK_OBSERVED_ARGUMENT_MARKER";
    chunkObservedArgument.Source = "test.chunk_scope";
    chunkObservedArgument.Confidence = 0.99;
    chunkScopedRequest.Facts.ObservedBehavior.ArgumentSamples.push_back(chunkObservedArgument);

    decomp::ObservedMemoryHotspot chunkObservedHotspot;
    chunkObservedHotspot.Expression = "CHUNK_OBSERVED_HOTSPOT_MARKER";
    chunkObservedHotspot.Kind = "read";
    chunkObservedHotspot.ReadCount = 2;
    chunkObservedHotspot.Sites.push_back(insideChunkSite);
    chunkObservedHotspot.Confidence = 0.99;
    chunkScopedRequest.Facts.ObservedBehavior.MemoryHotspots.push_back(chunkObservedHotspot);

    decomp::StackPointerFact insideChunkStackPointer;
    insideChunkStackPointer.Site = insideChunkSite;
    insideChunkStackPointer.DeltaBefore = 0x13579B;
    insideChunkStackPointer.DeltaAfter = 0x2468AC;
    insideChunkStackPointer.FramePointerDelta = 0x11;
    insideChunkStackPointer.Known = true;
    insideChunkStackPointer.FramePointerKnown = true;
    insideChunkStackPointer.Confidence = 0.99;
    chunkScopedRequest.Facts.StackPointer.insert(chunkScopedRequest.Facts.StackPointer.begin(), insideChunkStackPointer);

    decomp::MemoryAccess insideChunkMemoryAccess;
    insideChunkMemoryAccess.Site = insideChunkSite;
    insideChunkMemoryAccess.Access = "read";
    insideChunkMemoryAccess.Kind = "memory";
    insideChunkMemoryAccess.Size = "qword";
    insideChunkMemoryAccess.WidthBits = 64;
    insideChunkMemoryAccess.BaseRegister = "rsp";
    insideChunkMemoryAccess.Displacement = "0x20";
    insideChunkMemoryAccess.Semantic = "INSIDE_CHUNK_MEMORY_ACCESS_MARKER";
    insideChunkMemoryAccess.StackFrameRelative = true;
    insideChunkMemoryAccess.FrameBase = "rsp";
    insideChunkMemoryAccess.FrameOffset = 0x20;
    insideChunkMemoryAccess.StackPointerDelta = 0x13579B;
    chunkScopedRequest.Facts.MemoryAccesses.insert(chunkScopedRequest.Facts.MemoryAccesses.begin(), insideChunkMemoryAccess);

    decomp::SwitchInfo mergeSwitch;
    mergeSwitch.Site = 0x7777D010;
    mergeSwitch.TableAddress = 0x7777D000;
    mergeSwitch.CaseCount = 2;
    mergeSwitch.DefaultTarget = 0x7777D0FF;
    mergeSwitch.RangeMin = 0;
    mergeSwitch.RangeMax = 1;
    mergeSwitch.RangeKnown = true;
    mergeSwitch.Detail = "MERGE_SWITCH_MARKER";
    mergeSwitch.IndexExpression = "merge_switch_state";
    mergeSwitch.CaseTargets.push_back(0x7777D020);
    mergeSwitch.CaseTargets.push_back(0x7777D030);
    chunkScopedRequest.Facts.Switches.insert(chunkScopedRequest.Facts.Switches.begin(), mergeSwitch);

    decomp::CallSite mergeDirectCall;
    mergeDirectCall.Site = 0x7777E010;
    mergeDirectCall.Target = "MERGE_DIRECT_CALL_MARKER";
    mergeDirectCall.Kind = "direct";
    mergeDirectCall.Returns = true;
    chunkScopedRequest.Facts.Calls.insert(chunkScopedRequest.Facts.Calls.begin(), mergeDirectCall);

    decomp::CallSite mergeIndirectCall;
    mergeIndirectCall.Site = 0x7777E020;
    mergeIndirectCall.Target = "MERGE_INDIRECT_CALL_MARKER";
    mergeIndirectCall.Kind = "indirect";
    mergeIndirectCall.Returns = true;
    chunkScopedRequest.Facts.IndirectCalls.insert(chunkScopedRequest.Facts.IndirectCalls.begin(), mergeIndirectCall);

    decomp::StackPointerFact outsideChunkStackPointer;
    outsideChunkStackPointer.Site = 0x77770020;
    outsideChunkStackPointer.DeltaBefore = 0x7ABCDE;
    outsideChunkStackPointer.DeltaAfter = 0x7ABCDF;
    outsideChunkStackPointer.FramePointerDelta = 0x22;
    outsideChunkStackPointer.Known = true;
    outsideChunkStackPointer.FramePointerKnown = true;
    outsideChunkStackPointer.Confidence = 0.99;
    chunkScopedRequest.Facts.StackPointer.push_back(outsideChunkStackPointer);

    decomp::IrValue insideChunkIrValue;
    insideChunkIrValue.Id = "test_inside_chunk_ir";
    insideChunkIrValue.BlockId = entry != nullptr ? entry->Id : std::string();
    insideChunkIrValue.DefSite = insideChunkSite;
    insideChunkIrValue.Target = "INSIDE_CHUNK_IR_TARGET_MARKER";
    insideChunkIrValue.Expression = "inside_chunk_expr";
    insideChunkIrValue.Canonical = "INSIDE_CHUNK_IR_CANONICAL_MARKER";
    insideChunkIrValue.Kind = "test";
    insideChunkIrValue.Confidence = 0.99;
    chunkScopedRequest.Facts.IrValues.push_back(insideChunkIrValue);

    decomp::IrValue outsideChunkIrValue;
    outsideChunkIrValue.Id = "test_outside_chunk_ir";
    outsideChunkIrValue.BlockId = outsideChunkBlock.Id;
    outsideChunkIrValue.DefSite = 0x77770030;
    outsideChunkIrValue.Target = "OUTSIDE_CHUNK_IR_TARGET_MARKER";
    outsideChunkIrValue.Expression = "outside_chunk_expr";
    outsideChunkIrValue.Canonical = "OUTSIDE_CHUNK_IR_CANONICAL_MARKER";
    outsideChunkIrValue.Kind = "test";
    outsideChunkIrValue.Confidence = 0.99;
    chunkScopedRequest.Facts.IrValues.push_back(outsideChunkIrValue);

    decomp::ReachingValue insideChunkLiveOutValue;
    insideChunkLiveOutValue.Name = "inside_chunk_state";
    insideChunkLiveOutValue.ValueId = "test_inside_chunk_state";
    insideChunkLiveOutValue.Canonical = "INSIDE_CHUNK_BLOCK_STATE_MARKER";
    insideChunkLiveOutValue.Storage = "rax";
    insideChunkLiveOutValue.Confidence = 0.99;

    decomp::BlockValueState insideChunkBlockState;
    insideChunkBlockState.BlockId = entry != nullptr ? entry->Id : std::string();
    insideChunkBlockState.LiveOut.push_back(insideChunkLiveOutValue);
    insideChunkBlockState.Converged = true;
    insideChunkBlockState.Confidence = 0.99;
    chunkScopedRequest.Facts.BlockValueStates.push_back(insideChunkBlockState);

    decomp::ReachingValue outsideChunkLiveOutValue;
    outsideChunkLiveOutValue.Name = "outside_chunk_state";
    outsideChunkLiveOutValue.ValueId = "test_outside_chunk_state";
    outsideChunkLiveOutValue.Canonical = "OUTSIDE_CHUNK_BLOCK_STATE_MARKER";
    outsideChunkLiveOutValue.Storage = "rbx";
    outsideChunkLiveOutValue.Confidence = 0.99;

    decomp::BlockValueState outsideChunkBlockState;
    outsideChunkBlockState.BlockId = outsideChunkBlock.Id;
    outsideChunkBlockState.LiveOut.push_back(outsideChunkLiveOutValue);
    outsideChunkBlockState.Converged = true;
    outsideChunkBlockState.Confidence = 0.99;
    chunkScopedRequest.Facts.BlockValueStates.push_back(outsideChunkBlockState);

    decomp::TypeRecoveryHint insideChunkTypeHint;
    insideChunkTypeHint.Site = insideChunkSite;
    insideChunkTypeHint.Expression = "inside_chunk_type_expr";
    insideChunkTypeHint.Type = "INSIDE_CHUNK_TYPE_HINT_MARKER";
    insideChunkTypeHint.Source = "test.chunk_scope";
    insideChunkTypeHint.Kind = "test";
    insideChunkTypeHint.Confidence = 0.99;
    chunkScopedRequest.Facts.TypeHints.push_back(insideChunkTypeHint);

    decomp::TypeRecoveryHint outsideChunkTypeHint;
    outsideChunkTypeHint.Site = 0x77770100;
    outsideChunkTypeHint.Expression = "outside_chunk_type_expr";
    outsideChunkTypeHint.Type = "OUTSIDE_CHUNK_TYPE_HINT_MARKER";
    outsideChunkTypeHint.Source = "test.chunk_scope";
    outsideChunkTypeHint.Kind = "test";
    outsideChunkTypeHint.Confidence = 0.99;
    chunkScopedRequest.Facts.TypeHints.push_back(outsideChunkTypeHint);

    decomp::IdiomPattern insideChunkIdiomPattern;
    insideChunkIdiomPattern.Site = insideChunkSite;
    insideChunkIdiomPattern.Kind = "test";
    insideChunkIdiomPattern.Name = "INSIDE_CHUNK_IDIOM_MARKER";
    insideChunkIdiomPattern.Summary = "inside chunk idiom";
    insideChunkIdiomPattern.Replacement = "inside_chunk_replacement";
    insideChunkIdiomPattern.Confidence = 0.99;
    chunkScopedRequest.Facts.Idioms.push_back(insideChunkIdiomPattern);

    decomp::IdiomPattern outsideChunkIdiomPattern;
    outsideChunkIdiomPattern.Site = 0x77770110;
    outsideChunkIdiomPattern.Kind = "test";
    outsideChunkIdiomPattern.Name = "OUTSIDE_CHUNK_IDIOM_MARKER";
    outsideChunkIdiomPattern.Summary = "outside chunk idiom";
    outsideChunkIdiomPattern.Replacement = "outside_chunk_replacement";
    outsideChunkIdiomPattern.Confidence = 0.99;
    chunkScopedRequest.Facts.Idioms.push_back(outsideChunkIdiomPattern);

    decomp::CalleeSummary insideChunkCalleeSummary;
    insideChunkCalleeSummary.Site = insideChunkSite;
    insideChunkCalleeSummary.Callee = "INSIDE_CHUNK_CALLEE_SUMMARY_MARKER";
    insideChunkCalleeSummary.ReturnType = "int";
    insideChunkCalleeSummary.ParameterModel = "inside_chunk_param";
    insideChunkCalleeSummary.Source = "test.chunk_scope";
    insideChunkCalleeSummary.Confidence = 0.99;
    chunkScopedRequest.Facts.CalleeSummaries.push_back(insideChunkCalleeSummary);

    decomp::CalleeSummary outsideChunkCalleeSummary;
    outsideChunkCalleeSummary.Site = 0x77770120;
    outsideChunkCalleeSummary.Callee = "OUTSIDE_CHUNK_CALLEE_SUMMARY_MARKER";
    outsideChunkCalleeSummary.ReturnType = "int";
    outsideChunkCalleeSummary.ParameterModel = "outside_chunk_param";
    outsideChunkCalleeSummary.Source = "test.chunk_scope";
    outsideChunkCalleeSummary.Confidence = 0.99;
    chunkScopedRequest.Facts.CalleeSummaries.push_back(outsideChunkCalleeSummary);

    decomp::EvidenceNode insideChunkEvidenceNode;
    insideChunkEvidenceNode.Id = "test_inside_chunk_evidence_node";
    insideChunkEvidenceNode.Kind = "type_hint";
    insideChunkEvidenceNode.Label = "INSIDE_CHUNK_EVIDENCE_NODE_MARKER";
    insideChunkEvidenceNode.Site = insideChunkSite;
    insideChunkEvidenceNode.BlockId = entry != nullptr ? entry->Id : std::string();
    insideChunkEvidenceNode.Confidence = 0.99;
    chunkScopedRequest.Facts.EvidenceGraph.Nodes.push_back(insideChunkEvidenceNode);

    decomp::EvidenceNode insideChunkEvidenceTarget;
    insideChunkEvidenceTarget.Id = "test_inside_chunk_evidence_target";
    insideChunkEvidenceTarget.Kind = "callee_summary";
    insideChunkEvidenceTarget.Label = "INSIDE_CHUNK_EVIDENCE_TARGET_MARKER";
    insideChunkEvidenceTarget.Site = insideChunkSite;
    insideChunkEvidenceTarget.BlockId = entry != nullptr ? entry->Id : std::string();
    insideChunkEvidenceTarget.Confidence = 0.99;
    chunkScopedRequest.Facts.EvidenceGraph.Nodes.push_back(insideChunkEvidenceTarget);

    decomp::EvidenceEdge insideChunkEvidenceEdge;
    insideChunkEvidenceEdge.SourceId = insideChunkEvidenceNode.Id;
    insideChunkEvidenceEdge.TargetId = insideChunkEvidenceTarget.Id;
    insideChunkEvidenceEdge.Relation = "INSIDE_CHUNK_EVIDENCE_EDGE_MARKER";
    insideChunkEvidenceEdge.Confidence = 0.99;
    chunkScopedRequest.Facts.EvidenceGraph.Edges.push_back(insideChunkEvidenceEdge);

    decomp::EvidenceNode outsideChunkEvidenceNode;
    outsideChunkEvidenceNode.Id = "test_outside_chunk_evidence_node";
    outsideChunkEvidenceNode.Kind = "type_hint";
    outsideChunkEvidenceNode.Label = "OUTSIDE_CHUNK_EVIDENCE_NODE_MARKER";
    outsideChunkEvidenceNode.Site = 0x77770130;
    outsideChunkEvidenceNode.BlockId = "bb_outside_evidence";
    outsideChunkEvidenceNode.Confidence = 0.99;
    chunkScopedRequest.Facts.EvidenceGraph.Nodes.push_back(outsideChunkEvidenceNode);

    decomp::EvidenceNode outsideChunkEvidenceTarget;
    outsideChunkEvidenceTarget.Id = "test_outside_chunk_evidence_target";
    outsideChunkEvidenceTarget.Kind = "callee_summary";
    outsideChunkEvidenceTarget.Label = "OUTSIDE_CHUNK_EVIDENCE_TARGET_MARKER";
    outsideChunkEvidenceTarget.Site = 0x77770140;
    outsideChunkEvidenceTarget.BlockId = "bb_outside_evidence";
    outsideChunkEvidenceTarget.Confidence = 0.99;
    chunkScopedRequest.Facts.EvidenceGraph.Nodes.push_back(outsideChunkEvidenceTarget);

    decomp::EvidenceEdge outsideChunkEvidenceEdge;
    outsideChunkEvidenceEdge.SourceId = outsideChunkEvidenceNode.Id;
    outsideChunkEvidenceEdge.TargetId = outsideChunkEvidenceTarget.Id;
    outsideChunkEvidenceEdge.Relation = "OUTSIDE_CHUNK_EVIDENCE_EDGE_MARKER";
    outsideChunkEvidenceEdge.Confidence = 0.99;
    chunkScopedRequest.Facts.EvidenceGraph.Edges.push_back(outsideChunkEvidenceEdge);

    decomp::PdbScopedSymbol insideChunkPdbLocal;
    insideChunkPdbLocal.Name = "INSIDE_CHUNK_PDB_LOCAL_MARKER";
    insideChunkPdbLocal.Type = "int";
    insideChunkPdbLocal.Storage = "stack";
    insideChunkPdbLocal.Location = "inside_chunk";
    insideChunkPdbLocal.Site = insideChunkSite;
    insideChunkPdbLocal.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.Locals.push_back(insideChunkPdbLocal);

    decomp::PdbScopedSymbol outsideChunkPdbLocal;
    outsideChunkPdbLocal.Name = "OUTSIDE_CHUNK_PDB_LOCAL_MARKER";
    outsideChunkPdbLocal.Type = "int";
    outsideChunkPdbLocal.Storage = "stack";
    outsideChunkPdbLocal.Location = "outside_chunk";
    outsideChunkPdbLocal.Site = 0x77770150;
    outsideChunkPdbLocal.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.Locals.push_back(outsideChunkPdbLocal);

    decomp::PdbFieldHint insideChunkPdbField;
    insideChunkPdbField.BaseName = "inside";
    insideChunkPdbField.BaseType = "INSIDE_CHUNK_PDB_FIELD_MARKER";
    insideChunkPdbField.FieldName = "field";
    insideChunkPdbField.FieldType = "int";
    insideChunkPdbField.Site = insideChunkSite;
    insideChunkPdbField.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.FieldHints.push_back(insideChunkPdbField);

    decomp::PdbFieldHint outsideChunkPdbField;
    outsideChunkPdbField.BaseName = "outside";
    outsideChunkPdbField.BaseType = "OUTSIDE_CHUNK_PDB_FIELD_MARKER";
    outsideChunkPdbField.FieldName = "field";
    outsideChunkPdbField.FieldType = "int";
    outsideChunkPdbField.Site = 0x77770160;
    outsideChunkPdbField.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.FieldHints.push_back(outsideChunkPdbField);

    decomp::PdbEnumHint insideChunkPdbEnum;
    insideChunkPdbEnum.TypeName = "INSIDE_CHUNK_PDB_ENUM_MARKER";
    insideChunkPdbEnum.ConstantName = "InsideValue";
    insideChunkPdbEnum.Expression = "inside_expr";
    insideChunkPdbEnum.Value = 1;
    insideChunkPdbEnum.Site = insideChunkSite;
    insideChunkPdbEnum.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.EnumHints.push_back(insideChunkPdbEnum);

    decomp::PdbEnumHint outsideChunkPdbEnum;
    outsideChunkPdbEnum.TypeName = "OUTSIDE_CHUNK_PDB_ENUM_MARKER";
    outsideChunkPdbEnum.ConstantName = "OutsideValue";
    outsideChunkPdbEnum.Expression = "outside_expr";
    outsideChunkPdbEnum.Value = 2;
    outsideChunkPdbEnum.Site = 0x77770170;
    outsideChunkPdbEnum.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.EnumHints.push_back(outsideChunkPdbEnum);

    decomp::PdbSourceLocation insideChunkPdbSource;
    insideChunkPdbSource.Site = insideChunkSite;
    insideChunkPdbSource.File = "INSIDE_CHUNK_PDB_SOURCE_MARKER.cpp";
    insideChunkPdbSource.Line = 10;
    insideChunkPdbSource.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.SourceLocations.push_back(insideChunkPdbSource);

    decomp::PdbSourceLocation outsideChunkPdbSource;
    outsideChunkPdbSource.Site = 0x77770180;
    outsideChunkPdbSource.File = "OUTSIDE_CHUNK_PDB_SOURCE_MARKER.cpp";
    outsideChunkPdbSource.Line = 20;
    outsideChunkPdbSource.Confidence = 0.99;
    chunkScopedRequest.Facts.Pdb.SourceLocations.push_back(outsideChunkPdbSource);

    decomp::LlmClientConfig chunkConfig;
    chunkConfig.ChunkBlockLimit = 4;
    chunkConfig.ChunkCountLimit = 8;
    const std::string chunkPromptDump = decomp::BuildDebugFirstChunkPromptDump(chunkScopedRequest, chunkConfig);
    Expect(!chunkPromptDump.empty(), "debug chunk prompt dump should expose the first chunk prompt");
    Expect(chunkPromptDump.find("\"arch\"") != std::string::npos, "chunk prompt should include analysis architecture");
    Expect(chunkPromptDump.find("MERGE_ARCH_MARKER") != std::string::npos, "chunk prompt should preserve analysis architecture");
    Expect(chunkPromptDump.find("\"mode\"") != std::string::npos, "chunk prompt should include analysis mode");
    Expect(chunkPromptDump.find("\"live\"") != std::string::npos, "chunk prompt should preserve live analysis mode");
    Expect(chunkPromptDump.find("\"query_address\"") != std::string::npos, "chunk prompt should include query address");
    Expect(chunkPromptDump.find("0x42424242") != std::string::npos, "chunk prompt should preserve query address");
    Expect(chunkPromptDump.find("\"rva\"") != std::string::npos, "chunk prompt should include function RVA");
    Expect(chunkPromptDump.find("0x31313131") != std::string::npos, "chunk prompt should preserve function RVA");
    Expect(chunkPromptDump.find("\"selection\"") != std::string::npos, "chunk prompt should include prompt selection metadata");
    Expect(chunkPromptDump.find("\"chunk_strategy\"") != std::string::npos, "chunk prompt should describe chunk selection strategy");
    Expect(chunkPromptDump.find("chunk-scoped facts + global fact carryover + spread sampling") != std::string::npos, "chunk prompt should preserve chunk fact selection strategy");
    Expect(chunkPromptDump.find("\"loaded_image_name\"") != std::string::npos, "chunk prompt should include loaded image provenance");
    Expect(chunkPromptDump.find("CHUNK_MERGE_LOADED_IMAGE_MARKER.sys") != std::string::npos, "chunk prompt should preserve loaded image provenance");
    Expect(chunkPromptDump.find("\"symbol_type\"") != std::string::npos, "chunk prompt should include symbol type provenance");
    Expect(chunkPromptDump.find("424242") != std::string::npos, "chunk prompt should preserve symbol type provenance");
    Expect(chunkPromptDump.find("\"analyzer_skeleton\"") != std::string::npos, "chunk prompt should include the analyzer skeleton");
    Expect(chunkPromptDump.find("chunk analyzer skeleton") != std::string::npos, "chunk analyzer skeleton should be chunk-local");
    Expect(chunkPromptDump.find("\"scope\":\"chunk\"") != std::string::npos, "chunk prompt obfuscation facts should be marked as chunk-scoped");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_OBF_MARKER") == std::string::npos, "chunk prompt should omit obfuscation facts outside the chunk block set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_SEMANTIC_MARKER") == std::string::npos, "chunk prompt should omit semantic CFG edges outside the chunk block set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_FACT_MARKER") == std::string::npos, "chunk prompt should omit obfuscation detail facts outside the chunk block set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_UNCERTAINTY_MARKER") == std::string::npos, "chunk prompt should omit obfuscation uncertainties outside the chunk block set");
    Expect(chunkPromptDump.find("GLOBAL_CHUNK_SAFE_UNCERTAINTY_MARKER") != std::string::npos, "chunk prompt should preserve global uncertainties without chunk block references");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_CONDITION_MARKER") == std::string::npos, "chunk graph summary should omit normalized conditions outside the chunk block set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_CONTROL_FLOW_MARKER") != std::string::npos, "chunk prompt should include control-flow regions inside the chunk block set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_REGION_MARKER") == std::string::npos, "chunk graph summary should omit control-flow regions outside the chunk block set");
    Expect(chunkPromptDump.find("CHUNK_ABI_HOME_SLOT_MARKER") != std::string::npos, "chunk prompt should include ABI facts for calling-convention context");
    Expect(chunkPromptDump.find("CHUNK_SESSION_EXECUTION_MARKER") != std::string::npos, "chunk prompt should include session policy facts for debugger context");
    Expect(chunkPromptDump.find("CHUNK_OBSERVED_ARGUMENT_MARKER") != std::string::npos, "chunk prompt should include observed behavior facts for runtime context");
    Expect(chunkPromptDump.find("0x13579B") != std::string::npos, "chunk prompt should include stack pointer facts inside the chunk instruction set");
    Expect(chunkPromptDump.find("0x7ABCDE") == std::string::npos, "chunk prompt should omit stack pointer facts outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_IR_TARGET_MARKER") != std::string::npos, "chunk prompt should include IR values inside the chunk block set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_IR_TARGET_MARKER") == std::string::npos, "chunk prompt should omit IR values outside the chunk block set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_BLOCK_STATE_MARKER") != std::string::npos, "chunk prompt should include block value states inside the chunk block set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_BLOCK_STATE_MARKER") == std::string::npos, "chunk prompt should omit block value states outside the chunk block set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_TYPE_HINT_MARKER") != std::string::npos, "chunk prompt should include type hints inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_TYPE_HINT_MARKER") == std::string::npos, "chunk prompt should omit type hints outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_IDIOM_MARKER") != std::string::npos, "chunk prompt should include idioms inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_IDIOM_MARKER") == std::string::npos, "chunk prompt should omit idioms outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_CALLEE_SUMMARY_MARKER") != std::string::npos, "chunk prompt should include callee summaries inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_CALLEE_SUMMARY_MARKER") == std::string::npos, "chunk prompt should omit callee summaries outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_EVIDENCE_NODE_MARKER") != std::string::npos, "chunk prompt should include evidence graph nodes inside the chunk scope");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_EVIDENCE_EDGE_MARKER") != std::string::npos, "chunk prompt should include evidence graph edges between selected chunk nodes");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_EVIDENCE_NODE_MARKER") == std::string::npos, "chunk prompt should omit evidence graph nodes outside the chunk scope");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_EVIDENCE_EDGE_MARKER") == std::string::npos, "chunk prompt should omit evidence graph edges outside the chunk scope");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_PDB_LOCAL_MARKER") != std::string::npos, "chunk prompt should include PDB locals inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_PDB_LOCAL_MARKER") == std::string::npos, "chunk prompt should omit PDB locals outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_PDB_FIELD_MARKER") != std::string::npos, "chunk prompt should include PDB field hints inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_PDB_FIELD_MARKER") == std::string::npos, "chunk prompt should omit PDB field hints outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_PDB_ENUM_MARKER") != std::string::npos, "chunk prompt should include PDB enum hints inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_PDB_ENUM_MARKER") == std::string::npos, "chunk prompt should omit PDB enum hints outside the chunk instruction set");
    Expect(chunkPromptDump.find("INSIDE_CHUNK_PDB_SOURCE_MARKER") != std::string::npos, "chunk prompt should include PDB source locations inside the chunk instruction set");
    Expect(chunkPromptDump.find("OUTSIDE_CHUNK_PDB_SOURCE_MARKER") == std::string::npos, "chunk prompt should omit PDB source locations outside the chunk instruction set");
    Expect(chunkPromptDump.find("bb_outside_chunk") == std::string::npos, "chunk graph summary should omit semantic edge blocks outside the chunk block set");
    Expect(chunkPromptDump.find("bb_other_outside_chunk") == std::string::npos, "chunk graph summary should omit semantic edge targets outside the chunk block set");
    Expect(chunkPromptDump.find("bb_outside_important") == std::string::npos, "chunk graph summary should omit important blocks outside the chunk block set");

    const std::string mergePromptDump = decomp::BuildDebugMergePromptDump(chunkScopedRequest, chunkConfig);
    Expect(!mergePromptDump.empty(), "debug merge prompt dump should expose merge facts");
    Expect(mergePromptDump.find("\"arch\"") != std::string::npos, "merge prompt should include analysis architecture");
    Expect(mergePromptDump.find("MERGE_ARCH_MARKER") != std::string::npos, "merge prompt should preserve analysis architecture");
    Expect(mergePromptDump.find("\"mode\"") != std::string::npos, "merge prompt should include analysis mode");
    Expect(mergePromptDump.find("\"live\"") != std::string::npos, "merge prompt should preserve live analysis mode");
    Expect(mergePromptDump.find("\"selection\"") != std::string::npos, "merge prompt should include prompt selection metadata");
    Expect(mergePromptDump.find("\"fact_strategy\"") != std::string::npos, "merge prompt should describe fact selection strategy");
    Expect(mergePromptDump.find("ranked high-signal facts + spread sampling") != std::string::npos, "merge prompt should preserve fact selection strategy");
    const decomp::JsonValue mergeFactsJson = ParseDebugMergeFactsJson(mergePromptDump);
    ExpectJsonObjectPath(mergeFactsJson, { "chunking" }, "merge facts should include chunking object");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "total_block_count" }, "chunking.total_block_count should be numeric");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "uncovered_block_count" }, "chunking.uncovered_block_count should be numeric");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "coverage_complete" }, "chunking.coverage_complete should be boolean");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "uncovered_block_ids" }, "chunking.uncovered_block_ids should be an array");

    const decomp::JsonValue* mergeChunkPlans = ExpectJsonArrayPath(mergeFactsJson, { "chunking", "chunk_plans" }, "chunking.chunk_plans should be an array");
    Expect(mergeChunkPlans != nullptr && !mergeChunkPlans->GetArray().empty(), "chunking.chunk_plans should not be empty");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "summary_alignment" }, "chunking.summary_alignment should be an object");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "summary_alignment", "alignment_complete" }, "summary alignment completion should be boolean");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_alignment", "missing_summary_chunk_ids" }, "missing summary chunk ids should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_alignment", "orphan_summary_chunk_ids" }, "orphan summary chunk ids should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_alignment", "duplicate_summary_chunk_ids" }, "duplicate summary chunk ids should be an array");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "summary_quality" }, "chunking.summary_quality should be an object");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "summary_quality", "average_confidence" }, "summary average confidence should be numeric");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "summary_quality", "low_confidence_threshold" }, "summary low-confidence threshold should be numeric");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_quality", "low_confidence_chunk_ids" }, "low-confidence chunk ids should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_quality", "empty_evidence_chunk_ids" }, "empty-evidence chunk ids should be an array");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "summary_evidence" }, "chunking.summary_evidence should be an object");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "summary_evidence", "evidence_block_coverage_ratio" }, "summary evidence block coverage should be numeric");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_evidence", "chunks_without_block_evidence" }, "chunks without block evidence should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "summary_evidence", "evidence_blocks_outside_chunk_plans" }, "ungrounded summary evidence blocks should be an array");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_risk" }, "chunking.merge_risk should be an object");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "merge_risk", "risk_count" }, "merge risk count should be numeric");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_risk", "risk_codes" }, "merge risk codes should be an array");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_risk", "has_low_confidence_chunks" }, true, "merge risk should flag low-confidence chunks");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_risk", "has_empty_evidence_chunks" }, true, "merge risk should flag empty-evidence chunks");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "merge_risk", "has_ungrounded_evidence_blocks" }, "merge risk ungrounded evidence flag should be boolean");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_risk", "risk_codes" }, "low_confidence_chunks", "merge risk codes should include low-confidence chunks");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_risk", "risk_codes" }, "empty_evidence_chunks", "merge risk codes should include empty evidence chunks");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_risk_details" }, "chunking.merge_risk_details should be an object");
    const decomp::JsonValue* riskedChunks = ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_risk_details", "risked_chunks" }, "risked chunks should be an array");
    Expect(riskedChunks != nullptr && !riskedChunks->GetArray().empty(), "risked chunks should not be empty for debug low-confidence summaries");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "merge_risk_details", "risked_chunk_count" }, "risked chunk count should be numeric");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "merge_risk_details", "risked_chunks_truncated" }, "risked chunk truncation flag should be boolean");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_review_plan" }, "chunking.merge_review_plan should be an object");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_review_plan", "review_actions" }, "merge review actions should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_review_plan", "priority_chunk_ids" }, "merge review priority chunk ids should be an array");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "merge_review_plan", "requires_summary_reconciliation" }, "summary reconciliation review flag should be boolean");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_review_plan", "requires_evidence_review" }, true, "merge review should require evidence review");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_review_plan", "review_actions" }, "recheck_low_confidence_chunks", "merge review actions should include low-confidence recheck");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_review_plan", "review_actions" }, "require_chunk_block_evidence", "merge review actions should require chunk block evidence");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_confidence_policy" }, "chunking.merge_confidence_policy should be an object");
    ExpectJsonNumberAtMost(mergeFactsJson, { "chunking", "merge_confidence_policy", "recommended_confidence_ceiling" }, 0.58, "merge confidence ceiling should be capped by weak debug chunks");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_confidence_policy", "ceiling_reasons" }, "confidence ceiling reasons should be an array");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_confidence_policy", "requires_uncertainty" }, true, "merge confidence policy should require uncertainty");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_confidence_policy", "can_report_high_confidence" }, false, "merge confidence policy should block high confidence");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_confidence_policy", "ceiling_reasons" }, "low_confidence_chunk_summary", "confidence ceiling reasons should include low-confidence chunk summary");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_confidence_policy", "ceiling_reasons" }, "weak_chunk_evidence", "confidence ceiling reasons should include weak chunk evidence");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_acceptance_checks" }, "chunking.merge_acceptance_checks should be an object");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_acceptance_checks", "acceptance_checks" }, "merge acceptance checks should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_acceptance_checks", "blocking_issues" }, "merge blocking issues should be an array");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_acceptance_checks", "must_bound_confidence" }, true, "merge acceptance checks should require confidence bounding");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_acceptance_checks", "ready_for_high_confidence_merge" }, false, "merge acceptance checks should block high-confidence merge");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_acceptance_checks", "blocking_issues" }, "uncertain_or_low_confidence_summary", "merge blocking issues should include low-confidence summary");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_acceptance_checks", "blocking_issues" }, "weak_chunk_evidence", "merge blocking issues should include weak chunk evidence");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_output_contract" }, "chunking.merge_output_contract should be an object");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_output_contract", "required_top_level_keys" }, "merge required top-level keys should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_output_contract", "required_evidence_keys" }, "merge required evidence keys should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_output_contract", "blocked_merge_rules" }, "merge blocked output rules should be an array");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_output_contract", "required_top_level_keys" }, "pseudo_c", "merge output contract should require pseudo_c");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_output_contract", "required_top_level_keys" }, "confidence", "merge output contract should require confidence");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_traceability_matrix" }, "chunking.merge_traceability_matrix should be an object");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "merge_traceability_matrix", "target_count" }, "traceability target count should be numeric");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_traceability_matrix", "targets" }, "traceability targets should be an array");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_traceability_matrix", "requires_source_path_review" }, true, "traceability matrix should require source path review");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_obfuscation_policy" }, "chunking.merge_obfuscation_policy should be an object");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_obfuscation_policy", "has_flattening_dispatcher" }, true, "merge obfuscation policy should flag flattening dispatcher");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_rewrite_rules" }, "obfuscation rewrite rules should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_uncertainty_rules" }, "obfuscation uncertainty rules should be an array");
    ExpectJsonNumberPath(mergeFactsJson, { "chunking", "merge_obfuscation_policy", "semantic_overlay_confidence_threshold" }, "semantic overlay confidence threshold should be numeric");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_rewrite_rules" }, "prefer_semantic_overlay_edges", "obfuscation rewrite rules should prefer semantic overlay edges");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_deobfuscation_plan" }, "chunking.merge_deobfuscation_plan should be an object");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_plan", "deobfuscation_actions" }, "deobfuscation actions should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_plan", "priority_fact_paths" }, "deobfuscation priority fact paths should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_plan", "blocked_assumptions" }, "blocked deobfuscation assumptions should be an array");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "merge_deobfuscation_plan", "safe_to_rewrite_obfuscated_cfg" }, "obfuscated CFG rewrite safety flag should be boolean");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_deobfuscation_plan", "deobfuscation_actions" }, "apply_semantic_control_flow_overlay", "deobfuscation plan should apply semantic CFG overlay");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_deobfuscation_plan", "blocked_assumptions" }, "raw_dispatcher_loop_is_source_loop", "deobfuscation plan should block raw dispatcher loop assumption");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_deobfuscation_output_contract" }, "chunking.merge_deobfuscation_output_contract should be an object");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "output_rules" }, "deobfuscation output rules should be an array");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "requires_pseudo_c_deobfuscation_review" }, true, "deobfuscation output contract should require pseudo-C review");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "requires_rewrite_evidence" }, true, "deobfuscation output contract should require rewrite evidence");
    ExpectJsonBooleanPath(mergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "safe_to_emit_deobfuscated_structure" }, "deobfuscated structure safety flag should be boolean");

    ExpectJsonObjectPath(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy" }, "chunking.merge_deobfuscation_conflict_policy should be an object");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "priority_order" }, "deobfuscation conflict priority order should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "conflict_checks" }, "deobfuscation conflict checks should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "confidence_downgrade_reasons" }, "deobfuscation confidence downgrade reasons should be an array");
    ExpectJsonArrayPath(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "required_evidence_paths" }, "deobfuscation conflict evidence paths should be an array");
    ExpectJsonBooleanValue(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "requires_uncertainty_on_conflict" }, true, "deobfuscation conflict policy should require uncertainty on conflict");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "priority_order" }, "high_confidence_semantic_overlay", "deobfuscation conflict priority should prefer high-confidence semantic overlay");
    ExpectJsonStringArrayContains(mergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "conflict_checks" }, "semantic_overlay_vs_raw_successors", "deobfuscation conflict checks should compare semantic overlay with raw successors");
    Expect(mergePromptDump.find("\"first_block\"") != std::string::npos, "merge prompt should include chunk first-block provenance");
    Expect(mergePromptDump.find("\"last_block\"") != std::string::npos, "merge prompt should include chunk last-block provenance");
    Expect(mergePromptDump.find("\"block_ids\"") != std::string::npos, "merge prompt should include chunk block ids");
    Expect(mergePromptDump.find("\"loaded_image_name\"") != std::string::npos, "merge prompt should include loaded image provenance");
    Expect(mergePromptDump.find("CHUNK_MERGE_LOADED_IMAGE_MARKER.sys") != std::string::npos, "merge prompt should preserve loaded image provenance");
    Expect(mergePromptDump.find("\"symbol_type\"") != std::string::npos, "merge prompt should include symbol type provenance");
    Expect(mergePromptDump.find("424242") != std::string::npos, "merge prompt should preserve symbol type provenance");
    Expect(mergePromptDump.find("\"type_hints\"") != std::string::npos, "merge prompt should include type hints");
    Expect(mergePromptDump.find("INSIDE_CHUNK_TYPE_HINT_MARKER") != std::string::npos, "merge prompt should preserve type hints for final synthesis");
    Expect(mergePromptDump.find("\"idioms\"") != std::string::npos, "merge prompt should include idiom facts");
    Expect(mergePromptDump.find("INSIDE_CHUNK_IDIOM_MARKER") != std::string::npos, "merge prompt should preserve idioms for final synthesis");
    Expect(mergePromptDump.find("\"callee_summaries\"") != std::string::npos, "merge prompt should include callee summary facts");
    Expect(mergePromptDump.find("INSIDE_CHUNK_CALLEE_SUMMARY_MARKER") != std::string::npos, "merge prompt should preserve callee summaries for final synthesis");
    Expect(mergePromptDump.find("\"control_flow\"") != std::string::npos, "merge prompt should include control-flow region facts");
    Expect(mergePromptDump.find("INSIDE_CHUNK_CONTROL_FLOW_MARKER") != std::string::npos, "merge prompt should preserve control-flow regions for final synthesis");
    Expect(mergePromptDump.find("\"abi\"") != std::string::npos, "merge prompt should include ABI facts");
    Expect(mergePromptDump.find("CHUNK_ABI_HOME_SLOT_MARKER") != std::string::npos, "merge prompt should preserve ABI facts for final synthesis");
    Expect(mergePromptDump.find("\"session_policy\"") != std::string::npos, "merge prompt should include session policy facts");
    Expect(mergePromptDump.find("CHUNK_SESSION_EXECUTION_MARKER") != std::string::npos, "merge prompt should preserve session policy facts for final synthesis");
    Expect(mergePromptDump.find("\"observed_behavior\"") != std::string::npos, "merge prompt should include observed behavior facts");
    Expect(mergePromptDump.find("CHUNK_OBSERVED_ARGUMENT_MARKER") != std::string::npos, "merge prompt should preserve observed argument samples for final synthesis");
    Expect(mergePromptDump.find("CHUNK_OBSERVED_HOTSPOT_MARKER") != std::string::npos, "merge prompt should preserve observed memory hotspots for final synthesis");
    Expect(mergePromptDump.find("\"stack_pointer\"") != std::string::npos, "merge prompt should include stack pointer facts");
    Expect(mergePromptDump.find("0x13579B") != std::string::npos, "merge prompt should preserve stack pointer facts for final synthesis");
    Expect(mergePromptDump.find("\"memory_accesses\"") != std::string::npos, "merge prompt should include memory access facts");
    Expect(mergePromptDump.find("INSIDE_CHUNK_MEMORY_ACCESS_MARKER") != std::string::npos, "merge prompt should preserve memory access facts for final synthesis");
    Expect(mergePromptDump.find("\"ir_values\"") != std::string::npos, "merge prompt should include IR value facts");
    Expect(mergePromptDump.find("INSIDE_CHUNK_IR_TARGET_MARKER") != std::string::npos, "merge prompt should preserve IR value facts for final synthesis");
    Expect(mergePromptDump.find("\"switches\"") != std::string::npos, "merge prompt should include switch facts");
    Expect(mergePromptDump.find("MERGE_SWITCH_MARKER") != std::string::npos, "merge prompt should preserve switch facts for final synthesis");
    Expect(mergePromptDump.find("\"direct_calls\"") != std::string::npos, "merge prompt should include direct call facts");
    Expect(mergePromptDump.find("MERGE_DIRECT_CALL_MARKER") != std::string::npos, "merge prompt should preserve direct call facts for final synthesis");
    Expect(mergePromptDump.find("\"indirect_calls\"") != std::string::npos, "merge prompt should include indirect call facts");
    Expect(mergePromptDump.find("MERGE_INDIRECT_CALL_MARKER") != std::string::npos, "merge prompt should preserve indirect call facts for final synthesis");
    Expect(mergePromptDump.find("\"blocks\"") != std::string::npos, "merge prompt should include block facts");
    Expect(mergePromptDump.find("bb_outside_important") != std::string::npos, "merge prompt should preserve block facts for final synthesis");

    const decomp::AnalysisFacts stateSwitchFacts = BuildLegitimateStateSwitchFacts();
    Expect(FindHighConfidenceDispatcher(stateSwitchFacts) == nullptr, "ordinary compare-chain state switch should not become a high-confidence flattening dispatcher");

    const decomp::AnalysisFacts fanInCompareLoopFacts = BuildFanInCompareLoopFacts();
    Expect(FindHighConfidenceDispatcher(fanInCompareLoopFacts) == nullptr, "fan-in compare loop without state writes should not become a flattening dispatcher");

    const decomp::AnalysisFacts switchFacts = BuildSwitchFlattenedDispatcherFacts();
    const decomp::ObfuscationDispatcher* switchDispatcher = FindHighConfidenceDispatcher(switchFacts);
    const decomp::BasicBlock* arithmeticBody = FindBlockStartingAt(switchFacts, 0x16020);
    const decomp::BasicBlock* switchExit = FindBlockStartingAt(switchFacts, 0x16030);
    bool foundSwitchArithmeticEdge = false;

    Expect(switchDispatcher != nullptr, "switch flattened fixture should recover a high-confidence dispatcher");
    Expect(switchDispatcher != nullptr && switchDispatcher->Kind == "control_flow_flattening_switch_dispatcher", "switch dispatcher should be classified separately");

    if (switchDispatcher != nullptr && arithmeticBody != nullptr && switchExit != nullptr)
    {
        for (const decomp::RecoveredControlFlowEdge& edge : switchDispatcher->RecoveredEdges)
        {
            if (edge.SourceBlock == arithmeticBody->Id && edge.TargetBlock == switchExit->Id && edge.StateValue == "0x2")
            {
                foundSwitchArithmeticEdge = true;
            }
        }
    }

    Expect(foundSwitchArithmeticEdge, "bounded evaluator should recover arithmetic state updates for switch dispatchers");

    const decomp::AnalysisFacts conditionalFacts = BuildConditionalFlattenedDispatcherFacts();
    const decomp::ObfuscationDispatcher* conditionalDispatcher = FindHighConfidenceDispatcher(conditionalFacts);
    const decomp::BasicBlock* conditionalBody = FindBlockStartingAt(conditionalFacts, 0x17010);
    bool foundConditionalState1 = false;
    bool foundConditionalState2 = false;

    Expect(conditionalDispatcher != nullptr, "conditional flattened fixture should recover a high-confidence dispatcher");

    if (conditionalDispatcher != nullptr && conditionalBody != nullptr)
    {
        for (const decomp::RecoveredControlFlowEdge& edge : conditionalDispatcher->RecoveredEdges)
        {
            if (edge.SourceBlock != conditionalBody->Id || !edge.Conditional || edge.Condition.empty())
            {
                continue;
            }

            if (edge.StateValue == "0x1")
            {
                foundConditionalState1 = true;
            }
            else if (edge.StateValue == "0x2")
            {
                foundConditionalState2 = true;
            }
        }
    }

    Expect(foundConditionalState1, "conditional state recovery should keep the retained cmov state edge");
    Expect(foundConditionalState2, "conditional state recovery should recover the selected cmov state edge");

    const decomp::AnalysisFacts opaqueFacts = BuildOpaquePredicateFacts();
    const decomp::BasicBlock* opaqueDeadBlock = FindBlockStartingAt(opaqueFacts, 0x18005);
    bool foundOpaquePredicate = false;
    bool foundOpaqueDeadOverlayEdge = false;

    for (const decomp::OpaquePredicateFact& predicate : opaqueFacts.Obfuscation.OpaquePredicates)
    {
        if (predicate.ConstantResult == "true"
            && opaqueDeadBlock != nullptr
            && predicate.DeadTargetBlock == opaqueDeadBlock->Id)
        {
            foundOpaquePredicate = true;
        }
    }

    if (opaqueDeadBlock != nullptr)
    {
        for (const decomp::SemanticControlFlowEdge& edge : opaqueFacts.SemanticControlFlow.Edges)
        {
            if (edge.TargetBlock == opaqueDeadBlock->Id
                && edge.Dead
                && edge.Source == "obfuscation.opaque_predicate.dead")
            {
                foundOpaqueDeadOverlayEdge = true;
            }
        }
    }

    Expect(foundOpaquePredicate, "opaque predicate fixture should prove the dead branch target");
    Expect(foundOpaqueDeadOverlayEdge, "semantic CFG overlay should expose opaque-predicate dead edges");
    Expect(ContainsFactSubstring(opaqueFacts, "obfuscation opaque predicate: "), "deterministic facts should describe opaque predicate evidence");
    Expect(ContainsFactSubstring(opaqueFacts, "result=true"), "opaque predicate detail fact should preserve the constant result");
    Expect(HasEvidenceNodeKind(opaqueFacts, "obfuscation.opaque_predicate"), "evidence graph should expose opaque predicate nodes");
    Expect(HasEvidenceNodeKind(opaqueFacts, "semantic_cfg.dead_edge"), "evidence graph should expose semantic CFG dead-edge nodes");

    decomp::AnalyzeRequest opaqueRequest;
    opaqueRequest.RequestId = "obfuscation_bcf_prompt_snapshot";
    opaqueRequest.Facts = opaqueFacts;
    const std::string opaquePromptDump = decomp::BuildDebugPromptDump(opaqueRequest);
    Expect(opaquePromptDump.find("\"opaque_predicates\"") != std::string::npos, "prompt dump should include opaque predicate facts");
    Expect(opaquePromptDump.find("opaque predicate:") != std::string::npos, "analyzer skeleton should render opaque predicate proof comments");

    const decomp::AnalysisFacts substitutionFacts = BuildSubstitutionFacts();
    bool foundAddZero = false;
    bool foundCanonicalAdd = false;

    for (const decomp::SubstitutionIdiomFact& idiom : substitutionFacts.Obfuscation.SubstitutionIdioms)
    {
        if (idiom.Pattern == "identity_add_zero")
        {
            foundAddZero = true;
        }
    }

    for (const decomp::IrValue& value : substitutionFacts.IrValues)
    {
        if (value.DefSite == 0x19005 && value.Canonical.find("+ 0") == std::string::npos)
        {
            foundCanonicalAdd = true;
        }
    }

    Expect(foundAddZero, "substitution fixture should record an add-zero identity");
    Expect(foundCanonicalAdd, "substitution canonicalizer should simplify add-zero canonical values");
    Expect(ContainsFactSubstring(substitutionFacts, "obfuscation substitution: "), "deterministic facts should describe substitution idiom evidence");
    Expect(ContainsFactSubstring(substitutionFacts, "pattern=identity_add_zero"), "substitution detail fact should preserve the matched pattern");
    Expect(HasEvidenceNodeKind(substitutionFacts, "obfuscation.substitution_idiom"), "evidence graph should expose substitution idiom nodes");
    Expect(HasEvidenceEdgeRelation(substitutionFacts, "simplifies"), "evidence graph should link substitution facts to IR values");

    decomp::AnalyzeRequest obfuscationRequest;
    obfuscationRequest.RequestId = "obfuscation_phase3_snapshot";
    obfuscationRequest.Facts = substitutionFacts;
    const std::string phase3PromptDump = decomp::BuildDebugPromptDump(obfuscationRequest);
    Expect(phase3PromptDump.find("\"substitution_idioms\"") != std::string::npos, "prompt dump should include substitution idioms");
    Expect(phase3PromptDump.find("substitution:") != std::string::npos, "analyzer skeleton should render substitution comments");

    const decomp::AnalysisFacts ollvmFacts = BuildOllvmLikeObfuscatedFacts();
    const decomp::ObfuscationDispatcher* ollvmDispatcher = FindHighConfidenceDispatcher(ollvmFacts);
    bool foundOllvmOpaquePredicate = false;
    bool foundOllvmSubstitution = false;
    bool foundOllvmRecoveredEdge = false;
    bool foundOllvmDeadEdge = false;

    Expect(ollvmDispatcher != nullptr, "OLLVM-like fixture should recover a high-confidence flattening dispatcher");
    Expect(ollvmDispatcher != nullptr && ollvmDispatcher->RecoveredEdges.size() >= 2, "OLLVM-like fixture should recover dispatcher semantic edges");

    for (const decomp::OpaquePredicateFact& predicate : ollvmFacts.Obfuscation.OpaquePredicates)
    {
        if (predicate.ConstantResult == "true" && !predicate.DeadTargetBlock.empty())
        {
            foundOllvmOpaquePredicate = true;
        }
    }

    for (const decomp::SubstitutionIdiomFact& idiom : ollvmFacts.Obfuscation.SubstitutionIdioms)
    {
        if (idiom.Pattern == "identity_add_zero" || idiom.Pattern == "identity_xor_zero")
        {
            foundOllvmSubstitution = true;
        }
    }

    for (const decomp::SemanticControlFlowEdge& edge : ollvmFacts.SemanticControlFlow.Edges)
    {
        if (edge.Source == "obfuscation.recovered_edge" && !edge.Dead)
        {
            foundOllvmRecoveredEdge = true;
        }
        else if (edge.Source == "obfuscation.opaque_predicate.dead" && edge.Dead)
        {
            foundOllvmDeadEdge = true;
        }
    }

    Expect(foundOllvmOpaquePredicate, "OLLVM-like fixture should recover bogus-control opaque predicate evidence");
    Expect(foundOllvmSubstitution, "OLLVM-like fixture should recover scalar substitution idiom evidence");
    Expect(foundOllvmRecoveredEdge, "OLLVM-like semantic CFG should include recovered flattened edges");
    Expect(foundOllvmDeadEdge, "OLLVM-like semantic CFG should include proven opaque dead edges");
    Expect(ollvmFacts.DeobfuscationReadiness.SafeToRewriteControlFlow, "OLLVM-like readiness should allow semantic CFG rewrite");
    Expect(ContainsString(ollvmFacts.DeobfuscationReadiness.SafeActions, "recover_dispatcher_edges"), "OLLVM-like readiness should recover dispatcher edges");
    Expect(ContainsString(ollvmFacts.DeobfuscationReadiness.SafeActions, "prune_proven_opaque_dead_edges"), "OLLVM-like readiness should prune proven opaque dead edges");
    Expect(ContainsString(ollvmFacts.DeobfuscationReadiness.SafeActions, "apply_local_substitution_simplifications"), "OLLVM-like readiness should apply local substitution simplifications");
    Expect(ContainsString(ollvmFacts.DeobfuscationReadiness.BlockedAssumptions, "raw_dispatcher_loop_is_source_loop"), "OLLVM-like readiness should block raw dispatcher loop assumption");
    Expect(ContainsFactSubstring(ollvmFacts, "obfuscation dispatcher: header="), "OLLVM-like facts should describe dispatcher evidence");
    Expect(ContainsFactSubstring(ollvmFacts, "obfuscation opaque predicate: "), "OLLVM-like facts should describe opaque predicate evidence");
    Expect(ContainsFactSubstring(ollvmFacts, "obfuscation substitution: "), "OLLVM-like facts should describe substitution evidence");
    Expect(HasEvidenceNodeKind(ollvmFacts, "obfuscation.dispatcher"), "OLLVM-like evidence graph should expose dispatcher nodes");
    Expect(HasEvidenceNodeKind(ollvmFacts, "obfuscation.opaque_predicate"), "OLLVM-like evidence graph should expose opaque predicate nodes");
    Expect(HasEvidenceNodeKind(ollvmFacts, "obfuscation.substitution_idiom"), "OLLVM-like evidence graph should expose substitution nodes");
    Expect(HasEvidenceEdgeRelation(ollvmFacts, "simplifies"), "OLLVM-like evidence graph should link substitution simplifications");

    decomp::AnalyzeRequest ollvmRequest;
    ollvmRequest.RequestId = "obfuscation_ollvm_like_snapshot";
    ollvmRequest.Facts = ollvmFacts;

    const std::string ollvmPromptDump = decomp::BuildDebugPromptDump(ollvmRequest);
    Expect(ollvmPromptDump.find("\"dispatchers\"") != std::string::npos, "OLLVM-like prompt should include dispatcher facts");
    Expect(ollvmPromptDump.find("\"opaque_predicates\"") != std::string::npos, "OLLVM-like prompt should include opaque predicate facts");
    Expect(ollvmPromptDump.find("\"substitution_idioms\"") != std::string::npos, "OLLVM-like prompt should include substitution facts");
    Expect(ollvmPromptDump.find("\"deobfuscation_readiness\"") != std::string::npos, "OLLVM-like prompt should include deobfuscation readiness");
    Expect(ollvmPromptDump.find("prune_proven_opaque_dead_edges") != std::string::npos, "OLLVM-like prompt should include opaque dead-edge readiness action");
    Expect(ollvmPromptDump.find("semantic edge:") != std::string::npos, "OLLVM-like analyzer skeleton should render semantic CFG overlay comments");
    Expect(ollvmPromptDump.find("opaque predicate:") != std::string::npos, "OLLVM-like analyzer skeleton should render opaque predicate comments");
    Expect(ollvmPromptDump.find("substitution:") != std::string::npos, "OLLVM-like analyzer skeleton should render substitution comments");

    decomp::LlmClientConfig ollvmChunkConfig;
    ollvmChunkConfig.ChunkBlockLimit = 4;
    ollvmChunkConfig.ChunkCountLimit = 8;

    const std::string ollvmMergePromptDump = decomp::BuildDebugMergePromptDump(ollvmRequest, ollvmChunkConfig);
    Expect(!ollvmMergePromptDump.empty(), "OLLVM-like debug merge prompt dump should be available");

    const decomp::JsonValue ollvmMergeFactsJson = ParseDebugMergeFactsJson(ollvmMergePromptDump);
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_obfuscation_policy", "has_flattening_dispatcher" }, true, "OLLVM-like merge policy should flag flattening dispatcher");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_obfuscation_policy", "has_opaque_predicates" }, true, "OLLVM-like merge policy should flag opaque predicates");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_obfuscation_policy", "has_substitution_idioms" }, true, "OLLVM-like merge policy should flag substitution idioms");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_rewrite_rules" }, "prefer_semantic_overlay_edges", "OLLVM-like merge rewrite rules should prefer semantic overlays");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_obfuscation_policy", "obfuscation_uncertainty_rules" }, "do_not_infer_dead_edges_without_opaque_predicate_facts", "OLLVM-like merge uncertainty rules should guard bogus-control pruning");

    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "requires_dispatcher_edge_reconciliation" }, true, "OLLVM-like deobfuscation plan should require dispatcher edge reconciliation");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "requires_opaque_dead_edge_pruning" }, true, "OLLVM-like deobfuscation plan should require opaque dead-edge pruning");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "requires_substitution_simplification" }, true, "OLLVM-like deobfuscation plan should require substitution simplification");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "requires_semantic_overlay_review" }, true, "OLLVM-like deobfuscation plan should require semantic overlay review");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "deobfuscation_actions" }, "recover_dispatcher_edges", "OLLVM-like deobfuscation actions should recover dispatcher edges");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "deobfuscation_actions" }, "prune_proven_opaque_dead_edges", "OLLVM-like deobfuscation actions should prune proven opaque edges");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "deobfuscation_actions" }, "apply_local_substitution_simplifications", "OLLVM-like deobfuscation actions should apply substitution simplifications");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_plan", "blocked_assumptions" }, "opaque_branch_is_dead_without_fact", "OLLVM-like deobfuscation plan should block unsupported bogus-control pruning");

    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "requires_pseudo_c_deobfuscation_review" }, true, "OLLVM-like output contract should require pseudo-C deobfuscation review");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_output_contract", "requires_rewrite_evidence" }, true, "OLLVM-like output contract should require rewrite evidence");
    ExpectJsonBooleanValue(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "requires_conflict_resolution" }, true, "OLLVM-like conflict policy should require conflict resolution");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "conflict_checks" }, "opaque_dead_edges_vs_visible_branch_paths", "OLLVM-like conflict checks should compare opaque dead edges with visible paths");
    ExpectJsonStringArrayContains(ollvmMergeFactsJson, { "chunking", "merge_deobfuscation_conflict_policy", "confidence_downgrade_reasons" }, "opaque_dead_edge_unproven", "OLLVM-like conflict policy should downgrade unproven opaque edge claims");
}

void TestSimdAbiSnapshot()
{
    const decomp::AnalysisFacts facts = BuildSimdArgumentFacts();
    bool foundFpArg1 = false;
    bool foundFpArg2 = false;
    bool foundFalseFpArg3 = false;
    bool foundCallFpArg1 = false;
    bool foundCallFpArg2 = false;

    for (const decomp::RecoveredArgument& argument : facts.RecoveredArguments)
    {
        if (argument.Register == "xmm0" && argument.Name == "fp_arg1" && argument.TypeHint == "double_or_vector")
        {
            foundFpArg1 = true;
        }
        else if (argument.Register == "xmm1" && argument.Name == "fp_arg2" && argument.RoleHint == "floating_or_vector")
        {
            foundFpArg2 = true;
        }
        else if (argument.Register == "xmm2")
        {
            foundFalseFpArg3 = true;
        }
    }

    for (const decomp::CallArgumentFact& argument : facts.CallArguments)
    {
        if (argument.Site == 0xe007 && argument.Ordinal == 1 && argument.Location == "xmm0")
        {
            foundCallFpArg1 = argument.TypeHint == "double_or_vector";
        }
        else if (argument.Site == 0xe007 && argument.Ordinal == 2 && argument.Location == "xmm1")
        {
            foundCallFpArg2 = argument.TypeHint == "double_or_vector";
        }
    }

    Expect(foundFpArg1, "SIMD argument recovery should treat xmm0 as fp_arg1");
    Expect(foundFpArg2, "SIMD argument recovery should treat xmm1 as fp_arg2");
    Expect(!foundFalseFpArg3, "SIMD zero idioms should not create false incoming vector arguments");
    Expect(foundCallFpArg1, "call argument facts should include xmm0 argument slot");
    Expect(foundCallFpArg2, "call argument facts should include xmm1 argument slot");
}

void TestIndirectVirtualCallSnapshot()
{
    const decomp::AnalysisFacts facts = BuildIndirectVirtualCallFacts();
    bool foundVirtualCall = false;
    bool foundVirtualSummary = false;

    for (const decomp::CallTargetInfo& target : facts.CallTargets)
    {
        if (target.Site == 0xf004
            && target.Indirect
            && target.VirtualCall
            && target.VtableOffset == 0x18
            && target.TargetExpression == "[rax+0x18]")
        {
            foundVirtualCall = true;
        }
    }

    for (const decomp::CalleeSummary& summary : facts.CalleeSummaries)
    {
        if (summary.Site == 0xf004 && summary.Source == "call_target")
        {
            foundVirtualSummary = true;
        }
    }

    decomp::AnalyzeRequest request;
    request.RequestId = "virtual_call_prompt_snapshot";
    request.Facts = facts;
    const std::string dump = decomp::BuildDebugPromptDump(request);
    const std::string serialized = decomp::SerializeAnalyzeRequest(request, false);
    decomp::AnalyzeRequest parsed;
    std::string error;

    Expect(foundVirtualCall, "indirect memory calls should become virtual call target candidates");
    Expect(foundVirtualSummary, "indirect call targets should produce callee summaries");
    Expect(dump.find("\"virtual_call\"") != std::string::npos, "prompt dump should expose virtual call metadata");
    Expect(dump.find("\"target_expression\"") != std::string::npos, "prompt dump should expose indirect target expressions");
    Expect(decomp::ParseAnalyzeRequest(serialized, parsed, error), "virtual call request should parse after serialization");
    Expect(!parsed.Facts.CallTargets.empty() && parsed.Facts.CallTargets.front().VirtualCall, "virtual call metadata should round-trip");
    Expect(!parsed.Facts.CallTargets.empty() && parsed.Facts.CallTargets.front().TargetExpression == "[rax+0x18]", "target expression should round-trip");
}

void TestLoopInductionSnapshot()
{
    const decomp::AnalysisFacts facts = BuildLoopInductionFacts();
    const decomp::ControlFlowRegion* loop = FindRegion(facts, "natural_loop");

    Expect(loop != nullptr, "loop fixture should recover a natural loop");
    Expect(loop != nullptr && loop->InductionVariable == "rax", "natural loop should annotate the induction register");
    Expect(loop != nullptr && loop->Step == "+1", "natural loop should annotate the induction step");
    Expect(loop != nullptr && loop->Direction == "increasing", "natural loop should annotate the induction direction");
    Expect(loop != nullptr && loop->InitialValue == "0", "natural loop should recover a nearby zero initializer");
    Expect(loop != nullptr && !loop->Bound.empty(), "natural loop should recover a compare bound");
}

void TestKnownApiSemanticSnapshot()
{
    const decomp::AnalysisFacts facts = BuildKnownApiCallFacts();
    const decomp::CalleeSummary* summary = nullptr;

    for (const decomp::CalleeSummary& candidate : facts.CalleeSummaries)
    {
        if (candidate.Site == 0x12000)
        {
            summary = &candidate;
        }
    }

    Expect(summary != nullptr, "known API call should produce a callee summary");
    Expect(summary != nullptr && summary->Source == "known_api_model", "memcpy should use the known API semantic model");
    Expect(summary != nullptr && summary->Parameters.size() == 3, "memcpy should expose dst/src/size parameters");
    Expect(summary != nullptr && summary->MemoryEffects.find("dst") != std::string::npos, "memcpy memory effects should describe destination writes");
    Expect(summary != nullptr && summary->Ownership == "no_transfer", "memcpy should not imply ownership transfer");
}

void TestStackNormalizationSnapshot()
{
    const decomp::AnalysisFacts facts = BuildStackNormalizedFacts();
    size_t local20Count = 0;
    bool hasRsp8FrameOffset = false;
    bool hasRsp10FrameOffset = false;

    for (const decomp::RecoveredLocal& local : facts.RecoveredLocals)
    {
        if (local.Name == "local_20" && local.BaseRegister == "frame")
        {
            ++local20Count;
            Expect(local.WriteCount == 2, "canonical local_20 should include both raw rsp writes");
            Expect(local.ReadCount == 1, "canonical local_20 should include the later raw rsp read");
        }
    }

    for (const decomp::MemoryAccess& access : facts.MemoryAccesses)
    {
        if (!access.Implicit && access.Access.find("[rsp+0x8]") != std::string::npos)
        {
            hasRsp8FrameOffset = access.StackFrameRelative && access.FrameOffset == -0x20;
        }
        else if (!access.Implicit && access.Access.find("[rsp+0x10]") != std::string::npos)
        {
            hasRsp10FrameOffset = hasRsp10FrameOffset || (access.StackFrameRelative && access.FrameOffset == -0x20);
        }
    }

    Expect(local20Count == 1, "different raw rsp offsets with different deltas should collapse into one canonical local");
    Expect(hasRsp8FrameOffset, "rsp+0x8 after stack allocation should normalize to frame offset -0x20");
    Expect(hasRsp10FrameOffset, "rsp+0x10 after push should normalize to the same frame offset -0x20");

    decomp::AnalyzeRequest request;
    request.RequestId = "stack_normalized";
    request.Facts = facts;

    const std::string serialized = decomp::SerializeAnalyzeRequest(request, false);
    Expect(serialized.find("\"stack_pointer\"") != std::string::npos, "request snapshot should serialize stack pointer facts");
    Expect(serialized.find("\"call_arguments\"") != std::string::npos, "request snapshot should serialize call argument facts");
}

void TestSwitchSchemaSnapshot()
{
    decomp::AnalysisFacts facts = BuildDiamondFacts();
    decomp::SwitchInfo info;
    info.Site = 0x100b;
    info.TableAddress = 0x1800;
    info.CaseCount = 2;
    info.DefaultTarget = 0x1020;
    info.RangeMin = 0;
    info.RangeMax = 1;
    info.RangeKnown = true;
    info.Detail = "jmp qword ptr [rip+rax*8+0x700]";
    info.IndexExpression = "rax*8";
    info.CaseTargets = { 0x100d, 0x1018 };
    facts.Switches.push_back(info);

    decomp::AnalyzeRequest request;
    request.RequestId = "switch_snapshot";
    request.Facts = facts;

    const std::string serialized = decomp::SerializeAnalyzeRequest(request, false);
    Expect(serialized.find("\"case_targets\"") != std::string::npos, "switch snapshot should serialize recovered case targets");
    Expect(serialized.find("\"table_address\"") != std::string::npos, "switch snapshot should serialize table address");
    Expect(serialized.find("\"default_target\"") != std::string::npos, "switch snapshot should serialize default target");
    Expect(serialized.find("\"range_known\"") != std::string::npos, "switch snapshot should serialize range metadata");

    decomp::AnalyzeRequest parsed;
    std::string error;
    Expect(decomp::ParseAnalyzeRequest(serialized, parsed, error), "switch snapshot should parse after serialization");
    Expect(!parsed.Facts.Switches.empty() && parsed.Facts.Switches.back().CaseTargets.size() == 2, "switch case targets should round-trip");
    Expect(!parsed.Facts.Switches.empty() && parsed.Facts.Switches.back().DefaultTarget == 0x1020, "switch default target should round-trip");
    Expect(!parsed.Facts.Switches.empty() && parsed.Facts.Switches.back().RangeKnown, "switch range metadata should round-trip");
}

void TestPromptCallArgumentPackingSnapshot()
{
    decomp::AnalyzeRequest request;
    request.RequestId = "prompt_call_argument_packing_snapshot";
    request.Facts = BuildStackCallArgumentWindowFacts();

    const std::string dump = decomp::BuildDebugPromptDump(request);
    Expect(dump.find("\"call_arguments\"") != std::string::npos, "prompt dump should include call argument facts");
    Expect(dump.find("\"argument_count\"") != std::string::npos, "prompt dump should pack call arguments by call site");
    Expect(dump.find("\"arguments\"") != std::string::npos, "prompt dump should include grouped call argument lists");
    Expect(dump.find("\"fact_strategy\"") != std::string::npos, "prompt dump should describe ranked fact selection");
}

void TestStructuredPrototypeSchemaSnapshot()
{
    decomp::AnalyzeRequest request;
    request.RequestId = "structured_prototype_snapshot";
    request.Facts = BuildDiamondFacts();

    decomp::PrototypeParameter first;
    first.Ordinal = 1;
    first.Name = "Buffer";
    first.Type = "void *";
    first.Location = "rcx";
    first.Confidence = 0.80;

    decomp::PrototypeParameter second;
    second.Ordinal = 2;
    second.Name = "Length";
    second.Type = "size_t";
    second.Location = "rdx";
    second.Confidence = 0.80;

    decomp::CallTargetInfo call;
    call.Site = 0x1024;
    call.DisplayName = "snapshot!TypedHelper";
    call.Prototype = "int snapshot!TypedHelper(void * Buffer, size_t Length)";
    call.Parameters = { first, second };
    call.Confidence = 0.84;
    request.Facts.CallTargets.push_back(call);

    request.Facts.Pdb.Prototype = "int snapshot!Diamond(void * Buffer, size_t Length)";
    request.Facts.Pdb.PrototypeParameters = { first, second };

    const std::string serialized = decomp::SerializeAnalyzeRequest(request, false);
    Expect(serialized.find("\"parameters\"") != std::string::npos, "structured call target parameters should serialize");
    Expect(serialized.find("\"prototype_parameters\"") != std::string::npos, "structured PDB prototype parameters should serialize");

    decomp::AnalyzeRequest parsed;
    std::string error;
    Expect(decomp::ParseAnalyzeRequest(serialized, parsed, error), "structured prototype request should parse after serialization");
    Expect(!parsed.Facts.CallTargets.empty() && parsed.Facts.CallTargets.back().Parameters.size() == 2, "call target prototype parameters should round-trip");
    Expect(parsed.Facts.Pdb.PrototypeParameters.size() == 2, "PDB prototype parameters should round-trip");

    const std::string dump = decomp::BuildDebugPromptDump(request);
    Expect(dump.find("\"parameters\"") != std::string::npos, "prompt dump should include structured call target parameters");
    Expect(dump.find("\"prototype_parameters\"") != std::string::npos, "prompt dump should include structured PDB parameters");
}

void TestVerifierSnapshot()
{
    decomp::AnalyzeRequest request;
    request.RequestId = "verifier_snapshot";
    request.Facts = BuildDiamondFacts();

    decomp::AnalyzeResponse response;
    response.Status = "ok";
    response.PseudoC = "void f(void) { switch (x) { default: break; } }";
    response.Summary = "unsupported switch claim";
    response.Confidence = 0.90;

    const decomp::VerifyReport report = decomp::VerifyResponse(request, response);
    bool foundSwitchIssue = false;

    for (const decomp::VerificationIssue& issue : report.Issues)
    {
        if (issue.Code == "control_flow.switch_without_evidence")
        {
            foundSwitchIssue = true;
        }
    }

    Expect(foundSwitchIssue, "verifier snapshot should flag unsupported switch claims");
    Expect(report.AdjustedConfidence < response.Confidence, "verifier snapshot should reduce confidence after fact conflict");
    const std::string switchFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(report);
    Expect(switchFeedbackPrompt.find("recovered switch facts") != std::string::npos, "verifier feedback should name switch fact grounding");
    Expect(switchFeedbackPrompt.find("dispatcher recovered edges") != std::string::npos, "verifier feedback should mention dispatcher edge grounding for switch recovery");

    decomp::AnalyzeResponse loopResponse;
    loopResponse.Status = "ok";
    loopResponse.PseudoC = "void f(void) { while (x) { x--; } }";
    loopResponse.Summary = "loop path";
    loopResponse.Confidence = 0.90;

    const decomp::VerifyReport loopReport = decomp::VerifyResponse(request, loopResponse);
    Expect(HasIssueCode(loopReport, "control_flow.loop_without_back_edge"), "verifier snapshot should flag unsupported loop claims");
    const std::string loopFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(loopReport);
    Expect(loopFeedbackPrompt.find("raw CFG or semantic_control_flow evidence contains a back edge") != std::string::npos, "verifier feedback should name loop back-edge grounding");
}

void TestVerifierCoverageSnapshot()
{
    decomp::AnalyzeRequest request;
    request.RequestId = "verifier_coverage_snapshot";
    request.Facts = BuildDiamondFacts();

    decomp::SwitchInfo switchInfo;
    switchInfo.Site = 0x100b;
    switchInfo.CaseCount = 1;
    switchInfo.CaseTargets = { 0x100d };
    request.Facts.Switches.push_back(switchInfo);

    decomp::CallTargetInfo call;
    call.Site = 0x1024;
    call.DisplayName = "snapshot!ImportantHelper";
    call.TargetKind = "internal_direct";
    call.Confidence = 0.82;
    request.Facts.CallTargets.push_back(call);

    decomp::CallArgumentFact callArg1;
    callArg1.Site = 0x1024;
    callArg1.Ordinal = 1;
    callArg1.Location = "rcx";
    callArg1.Expression = "input";
    callArg1.Confidence = 0.72;
    request.Facts.CallArguments.push_back(callArg1);

    decomp::CallArgumentFact callArg2;
    callArg2.Site = 0x1024;
    callArg2.Ordinal = 2;
    callArg2.Location = "rdx";
    callArg2.Expression = "5";
    callArg2.Confidence = 0.72;
    request.Facts.CallArguments.push_back(callArg2);

    decomp::AnalyzeResponse response;
    response.Status = "ok";
    response.PseudoC = "void f(void) { switch (x) { case 0: break; case 1: break; case 2: break; case 3: break; } }";
    response.Summary = "switch path";
    response.Confidence = 0.92;

    decomp::TypedNameConfidence param;
    param.Name = "inventedParameterName";
    param.Type = "int";
    param.Confidence = 0.90;
    response.Params.push_back(param);

    const decomp::VerifyReport report = decomp::VerifyResponse(request, response);
    Expect(HasIssueCode(report, "control_flow.too_many_switch_cases"), "verifier should flag switch cases beyond recovered targets");
    Expect(HasIssueCode(report, "call.recovered_targets_omitted"), "verifier should flag omitted high-confidence recovered call targets");
    Expect(HasIssueCode(report, "identifier.ungrounded_declared_names"), "verifier should flag ungrounded response parameter/local names");

    decomp::AnalyzeResponse symbolSuffixResponse;
    symbolSuffixResponse.Status = "ok";
    symbolSuffixResponse.PseudoC = "void f(void) { ImportantHelper(); }";
    symbolSuffixResponse.Summary = "calls helper";
    symbolSuffixResponse.Confidence = 0.92;

    const decomp::VerifyReport suffixReport = decomp::VerifyResponse(request, symbolSuffixResponse);
    Expect(!HasIssueCode(suffixReport, "call.recovered_targets_omitted"), "verifier should match recovered module-qualified calls by symbol suffix");
    Expect(HasIssueCode(suffixReport, "call.arguments_omitted"), "verifier should flag recovered call arguments omitted from pseudo calls");

    decomp::AnalyzeResponse symbolSuffixWithArgsResponse;
    symbolSuffixWithArgsResponse.Status = "ok";
    symbolSuffixWithArgsResponse.PseudoC = "void f(void) { ImportantHelper(1, 2); }";
    symbolSuffixWithArgsResponse.Summary = "calls helper with arguments";
    symbolSuffixWithArgsResponse.Confidence = 0.92;

    const decomp::VerifyReport suffixWithArgsReport = decomp::VerifyResponse(request, symbolSuffixWithArgsResponse);
    Expect(!HasIssueCode(suffixWithArgsReport, "call.arguments_omitted"), "verifier should accept pseudo calls that preserve recovered argument arity");

    decomp::AnalyzeRequest prototypeOnlyRequest;
    prototypeOnlyRequest.RequestId = "verifier_prototype_arity_snapshot";
    prototypeOnlyRequest.Facts = BuildDiamondFacts();

    decomp::PrototypeParameter protoParam1;
    protoParam1.Ordinal = 1;
    protoParam1.Name = "First";
    protoParam1.Type = "int";
    protoParam1.Location = "rcx";
    protoParam1.Confidence = 0.80;

    decomp::PrototypeParameter protoParam2 = protoParam1;
    protoParam2.Ordinal = 2;
    protoParam2.Name = "Second";
    protoParam2.Location = "rdx";

    decomp::CallTargetInfo prototypeOnlyCall;
    prototypeOnlyCall.Site = 0x1024;
    prototypeOnlyCall.DisplayName = "snapshot!PrototypeOnly";
    prototypeOnlyCall.Parameters = { protoParam1, protoParam2 };
    prototypeOnlyCall.Confidence = 0.82;
    prototypeOnlyRequest.Facts.CallTargets.push_back(prototypeOnlyCall);

    decomp::AnalyzeResponse prototypeOnlyResponse;
    prototypeOnlyResponse.Status = "ok";
    prototypeOnlyResponse.PseudoC = "void f(void) { PrototypeOnly(1); }";
    prototypeOnlyResponse.Summary = "calls helper";
    prototypeOnlyResponse.Confidence = 0.92;

    const decomp::VerifyReport prototypeOnlyReport = decomp::VerifyResponse(prototypeOnlyRequest, prototypeOnlyResponse);
    Expect(HasIssueCode(prototypeOnlyReport, "call.arguments_omitted"), "verifier should use structured prototype arity even without call argument facts");

    decomp::AnalyzeResponse commentedCallResponse;
    commentedCallResponse.Status = "ok";
    commentedCallResponse.PseudoC = "void f(void) { /* ImportantHelper(); */ }";
    commentedCallResponse.Summary = "does not call helper";
    commentedCallResponse.Confidence = 0.92;

    const decomp::VerifyReport commentedCallReport = decomp::VerifyResponse(request, commentedCallResponse);
    Expect(HasIssueCode(commentedCallReport, "call.recovered_targets_omitted"), "verifier should ignore call names that appear only in comments");

    decomp::AnalyzeResponse summaryOnlyCallResponse;
    summaryOnlyCallResponse.Status = "ok";
    summaryOnlyCallResponse.PseudoC = "void f(void) { return; }";
    summaryOnlyCallResponse.Summary = "mentions ImportantHelper but does not call it";
    summaryOnlyCallResponse.Confidence = 0.92;

    const decomp::VerifyReport summaryOnlyCallReport = decomp::VerifyResponse(request, summaryOnlyCallResponse);
    Expect(HasIssueCode(summaryOnlyCallReport, "call.recovered_targets_omitted"), "verifier should not count summary-only call mentions as recovered call coverage");

    decomp::AnalyzeResponse identifierOnlyCallResponse;
    identifierOnlyCallResponse.Status = "ok";
    identifierOnlyCallResponse.PseudoC = "void f(void) { int ImportantHelper = 0; }";
    identifierOnlyCallResponse.Summary = "declares a similarly named local";
    identifierOnlyCallResponse.Confidence = 0.92;

    const decomp::VerifyReport identifierOnlyCallReport = decomp::VerifyResponse(request, identifierOnlyCallResponse);
    Expect(HasIssueCode(identifierOnlyCallReport, "call.recovered_targets_omitted"), "verifier should not count plain identifiers as recovered call coverage");

    decomp::AnalyzeResponse commentedSwitchResponse;
    commentedSwitchResponse.Status = "ok";
    commentedSwitchResponse.PseudoC = "void f(void) { /* switch (x) { case 0: break; } */ }";
    commentedSwitchResponse.Summary = "straight-line path";
    commentedSwitchResponse.Confidence = 0.92;

    const decomp::VerifyReport commentedSwitchReport = decomp::VerifyResponse(request, commentedSwitchResponse);
    Expect(!HasIssueCode(commentedSwitchReport, "control_flow.too_many_switch_cases"), "verifier should ignore switch cases that appear only in comments");

    decomp::AnalyzeResponse lowEvidenceResponse;
    lowEvidenceResponse.Status = "ok";
    lowEvidenceResponse.PseudoC = "void f(void) { if (x) { ImportantHelper(1, 2); } }";
    lowEvidenceResponse.Summary = "partial evidence";
    lowEvidenceResponse.Confidence = 0.92;
    decomp::EvidenceItem evidence;
    evidence.Claim = "entry only";
    evidence.Blocks.push_back("bb0");
    lowEvidenceResponse.Evidence.push_back(evidence);

    const decomp::VerifyReport lowEvidenceReport = decomp::VerifyResponse(request, lowEvidenceResponse);
    Expect(HasIssueCode(lowEvidenceReport, "evidence.low_coverage"), "verifier should flag high-confidence responses with sparse high-signal evidence coverage");
    const std::string lowEvidenceFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(lowEvidenceReport);
    Expect(lowEvidenceFeedbackPrompt.find("block-grounded evidence entries") != std::string::npos, "verifier feedback should require block-grounded evidence coverage");
    Expect(lowEvidenceFeedbackPrompt.find("coverage gap") != std::string::npos, "verifier feedback should require uncertainty for evidence coverage gaps");

    decomp::AnalyzeRequest missingGraphRequest = request;
    missingGraphRequest.Facts.EvidenceGraph = decomp::EvidenceGraphFacts();

    decomp::AnalyzeResponse missingGraphResponse;
    missingGraphResponse.Status = "ok";
    missingGraphResponse.PseudoC = "void f(void) { ImportantHelper(1, 2); }";
    missingGraphResponse.Summary = "calls helper";
    missingGraphResponse.Confidence = 0.92;

    const decomp::VerifyReport missingGraphReport = decomp::VerifyResponse(missingGraphRequest, missingGraphResponse);
    Expect(HasIssueCode(missingGraphReport, "evidence_graph.missing"), "verifier should flag high-confidence semantic facts without an evidence graph");
    Expect(missingGraphReport.AdjustedConfidence < missingGraphResponse.Confidence, "missing evidence graph should reduce verifier confidence");
    const std::string missingGraphFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(missingGraphReport);
    Expect(missingGraphFeedbackPrompt.find("evidence_graph is absent or weak") != std::string::npos, "verifier feedback should require weaker claims without evidence graph grounding");
    Expect(missingGraphFeedbackPrompt.find("weak graph grounding") != std::string::npos, "verifier feedback should require graph-grounding uncertainty");

    decomp::AnalyzeRequest unconvergedRequest = request;

    if (!unconvergedRequest.Facts.BlockValueStates.empty())
    {
        unconvergedRequest.Facts.BlockValueStates[0].Converged = false;
    }

    decomp::AnalyzeResponse unconvergedResponse;
    unconvergedResponse.Status = "ok";
    unconvergedResponse.PseudoC = "void f(void) { ImportantHelper(1, 2); }";
    unconvergedResponse.Summary = "calls helper";
    unconvergedResponse.Confidence = 0.92;

    const decomp::VerifyReport unconvergedReport = decomp::VerifyResponse(unconvergedRequest, unconvergedResponse);
    Expect(HasIssueCode(unconvergedReport, "dataflow.unconverged_without_uncertainty"), "verifier should flag confident responses that omit unconverged dataflow uncertainty");
    Expect(unconvergedReport.AdjustedConfidence < unconvergedResponse.Confidence, "unconverged dataflow without uncertainty should reduce verifier confidence");
    const std::string unconvergedFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(unconvergedReport);
    Expect(unconvergedFeedbackPrompt.find("block_value_states are unconverged") != std::string::npos, "verifier feedback should name unconverged dataflow state");
    Expect(unconvergedFeedbackPrompt.find("alias-sensitive rewrites") != std::string::npos, "verifier feedback should constrain dataflow-dependent rewrites");

    decomp::AnalyzeRequest unsupportedObfuscationRequest;
    unsupportedObfuscationRequest.RequestId = "unsupported_obfuscation_claims";
    unsupportedObfuscationRequest.Facts = BuildDiamondFacts();

    decomp::AnalyzeResponse unsupportedObfuscationResponse;
    unsupportedObfuscationResponse.Status = "ok";
    unsupportedObfuscationResponse.PseudoC = "void f(void) { return; }";
    unsupportedObfuscationResponse.Summary = "recovered control-flow flattening dispatcher, removed opaque predicate dead branch, and applied instruction substitution idiom";
    unsupportedObfuscationResponse.Confidence = 0.91;

    const decomp::VerifyReport unsupportedObfuscationReport = decomp::VerifyResponse(unsupportedObfuscationRequest, unsupportedObfuscationResponse);
    Expect(HasIssueCode(unsupportedObfuscationReport, "obfuscation.dispatcher_claim_without_evidence"), "verifier should reject unsupported dispatcher recovery claims");
    Expect(HasIssueCode(unsupportedObfuscationReport, "obfuscation.dead_edge_claim_without_opaque_predicate"), "verifier should reject unsupported opaque dead-edge claims");
    Expect(HasIssueCode(unsupportedObfuscationReport, "obfuscation.substitution_claim_without_evidence"), "verifier should reject unsupported substitution claims");
    Expect(IssueEvidenceContains(unsupportedObfuscationReport, "obfuscation.dispatcher_claim_without_evidence", "recovered control-flow flattening dispatcher"), "dispatcher issue should include the matched claim context");
    Expect(IssueEvidenceContains(unsupportedObfuscationReport, "obfuscation.dead_edge_claim_without_opaque_predicate", "removed opaque predicate dead branch"), "opaque dead-edge issue should include the matched claim context");
    Expect(IssueEvidenceContains(unsupportedObfuscationReport, "obfuscation.substitution_claim_without_evidence", "applied instruction substitution idiom"), "substitution issue should include the matched claim context");
    const std::string obfuscationFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(unsupportedObfuscationReport);
    Expect(obfuscationFeedbackPrompt.find("claim_context_count=") != std::string::npos, "verifier feedback should preserve obfuscation claim context evidence");
    Expect(obfuscationFeedbackPrompt.find("recovered control-flow flattening dispatcher") != std::string::npos, "verifier feedback should include the dispatcher claim text");
    Expect(obfuscationFeedbackPrompt.find("removed opaque predicate dead branch") != std::string::npos, "verifier feedback should include the opaque dead-edge claim text");
    Expect(obfuscationFeedbackPrompt.find("obfuscation.opaque_predicates") != std::string::npos, "verifier feedback should name opaque predicate grounding facts");
    Expect(obfuscationFeedbackPrompt.find("obfuscation.substitution_idioms") != std::string::npos, "verifier feedback should name substitution grounding facts");

    decomp::AnalyzeResponse obfuscationUncertaintyResponse;
    obfuscationUncertaintyResponse.Status = "ok";
    obfuscationUncertaintyResponse.PseudoC = "void f(void) { return; }";
    obfuscationUncertaintyResponse.Summary = "dispatcher recovery was unavailable; opaque predicate evidence was unavailable, so no dead branch pruning was applied; substitution idioms were unavailable";
    obfuscationUncertaintyResponse.Uncertainties.push_back("obfuscation evidence unavailable");
    obfuscationUncertaintyResponse.Confidence = 0.72;

    const decomp::VerifyReport obfuscationUncertaintyReport = decomp::VerifyResponse(unsupportedObfuscationRequest, obfuscationUncertaintyResponse);
    Expect(!HasIssueCode(obfuscationUncertaintyReport, "obfuscation.dispatcher_claim_without_evidence"), "verifier should not treat unavailable dispatcher recovery as a recovery claim");
    Expect(!HasIssueCode(obfuscationUncertaintyReport, "obfuscation.dead_edge_claim_without_opaque_predicate"), "verifier should not treat negated opaque-pruning uncertainty as a dead-edge claim");
    Expect(!HasIssueCode(obfuscationUncertaintyReport, "obfuscation.substitution_claim_without_evidence"), "verifier should not treat unavailable substitution evidence as a simplification claim");

    decomp::AnalyzeRequest substitutionRequest;
    substitutionRequest.RequestId = "verifier_substitution_semantics_snapshot";
    substitutionRequest.Facts = BuildSubstitutionFacts();

    decomp::AnalyzeResponse scalarSubstitutionResponse;
    scalarSubstitutionResponse.Status = "ok";
    scalarSubstitutionResponse.PseudoC = "void f(void) { return; }";
    scalarSubstitutionResponse.Summary = "applied substitution idiom eax + 0 => eax";
    scalarSubstitutionResponse.Confidence = 0.91;

    const decomp::VerifyReport scalarSubstitutionReport = decomp::VerifyResponse(substitutionRequest, scalarSubstitutionResponse);
    Expect(!HasIssueCode(scalarSubstitutionReport, "obfuscation.substitution_memory_semantics_claim"), "verifier should allow scalar substitution claims backed by substitution facts");

    decomp::AnalyzeResponse memorySubstitutionResponse;
    memorySubstitutionResponse.Status = "ok";
    memorySubstitutionResponse.PseudoC = "void f(void) { return; }";
    memorySubstitutionResponse.Summary = "applied substitution idiom [rcx] + 0 => [rcx]";
    memorySubstitutionResponse.Confidence = 0.91;

    const decomp::VerifyReport memorySubstitutionReport = decomp::VerifyResponse(substitutionRequest, memorySubstitutionResponse);
    Expect(HasIssueCode(memorySubstitutionReport, "obfuscation.substitution_memory_semantics_claim"), "verifier should flag memory-sensitive substitution claims");
    Expect(IssueEvidenceContains(memorySubstitutionReport, "obfuscation.substitution_memory_semantics_claim", "[rcx] + 0"), "memory-sensitive substitution issue should include the matched rewrite context");
    const std::string substitutionFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(memorySubstitutionReport);
    Expect(substitutionFeedbackPrompt.find("pointer, load, store") != std::string::npos, "verifier feedback should instruct memory-sensitive substitution uncertainty");

    decomp::AnalyzeResponse memoryUncertaintyResponse;
    memoryUncertaintyResponse.Status = "ok";
    memoryUncertaintyResponse.PseudoC = "void f(void) { return; }";
    memoryUncertaintyResponse.Summary = "substitution idiom evidence was present, but memory effects were uncertain and pointer loads were not simplified";
    memoryUncertaintyResponse.Uncertainties.push_back("memory-sensitive substitution not applied");
    memoryUncertaintyResponse.Confidence = 0.78;

    const decomp::VerifyReport memoryUncertaintyReport = decomp::VerifyResponse(substitutionRequest, memoryUncertaintyResponse);
    Expect(!HasIssueCode(memoryUncertaintyReport, "obfuscation.substitution_memory_semantics_claim"), "verifier should not flag negated memory-substitution uncertainty as a rewrite claim");

    std::string rawSource;
    std::string rawTarget;

    for (const decomp::BasicBlock& block : request.Facts.Blocks)
    {
        if (!block.Successors.empty())
        {
            rawSource = block.Id;
            rawTarget = block.Successors.front();
            break;
        }
    }

    Expect(!rawSource.empty() && !rawTarget.empty(), "diamond fixture should expose at least one raw CFG edge");

    decomp::AnalyzeResponse supportedRawEdgeResponse;
    supportedRawEdgeResponse.Status = "ok";
    supportedRawEdgeResponse.PseudoC = "void f(void) { /* semantic edge: " + rawSource + " -> " + rawTarget + " */ return; }";
    supportedRawEdgeResponse.Summary = "preserves a listed raw edge";
    supportedRawEdgeResponse.Confidence = 0.91;

    const decomp::VerifyReport supportedRawEdgeReport = decomp::VerifyResponse(request, supportedRawEdgeResponse);
    Expect(!HasIssueCode(supportedRawEdgeReport, "control_flow.edge_claim_without_evidence"), "verifier should allow edge claims present in raw CFG");

    std::string unsupportedSource;
    std::string unsupportedTarget;

    for (const decomp::BasicBlock& source : request.Facts.Blocks)
    {
        for (const decomp::BasicBlock& target : request.Facts.Blocks)
        {
            if (source.Id != target.Id && !ContainsString(source.Successors, target.Id))
            {
                unsupportedSource = source.Id;
                unsupportedTarget = target.Id;
                break;
            }
        }

        if (!unsupportedSource.empty())
        {
            break;
        }
    }

    Expect(!unsupportedSource.empty() && !unsupportedTarget.empty(), "diamond fixture should expose at least one unsupported CFG edge pair");

    decomp::AnalyzeResponse unsupportedEdgeResponse;
    unsupportedEdgeResponse.Status = "ok";
    unsupportedEdgeResponse.PseudoC = "void f(void) { /* semantic edge: " + unsupportedSource + " -> " + unsupportedTarget + " */ return; }";
    unsupportedEdgeResponse.Summary = "claims an unsupported semantic edge";
    unsupportedEdgeResponse.Confidence = 0.91;

    const decomp::VerifyReport unsupportedEdgeReport = decomp::VerifyResponse(request, unsupportedEdgeResponse);
    Expect(HasIssueCode(unsupportedEdgeReport, "control_flow.edge_claim_without_evidence"), "verifier should reject concrete edge claims missing from raw and semantic CFG evidence");
    const std::string unsupportedEdgeFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(unsupportedEdgeReport);
    Expect(unsupportedEdgeFeedbackPrompt.find("raw CFG successors") != std::string::npos, "verifier feedback should name raw CFG edge grounding");
    Expect(unsupportedEdgeFeedbackPrompt.find("semantic_control_flow") != std::string::npos, "verifier feedback should name semantic CFG edge grounding");
    Expect(unsupportedEdgeFeedbackPrompt.find("obfuscation.dispatchers.recovered_edges") != std::string::npos, "verifier feedback should name dispatcher recovered edge grounding");

    decomp::AnalyzeResponse unsupportedDeadEdgeResponse;
    unsupportedDeadEdgeResponse.Status = "ok";
    unsupportedDeadEdgeResponse.PseudoC = "void f(void) { /* semantic dead edge pruned: " + rawSource + " -> " + rawTarget + " */ return; }";
    unsupportedDeadEdgeResponse.Summary = "claims a pruned dead edge without opaque proof";
    unsupportedDeadEdgeResponse.Confidence = 0.91;

    const decomp::VerifyReport unsupportedDeadEdgeReport = decomp::VerifyResponse(request, unsupportedDeadEdgeResponse);
    Expect(HasIssueCode(unsupportedDeadEdgeReport, "obfuscation.dead_edge_claim_without_matching_evidence"), "verifier should reject specific dead-edge claims without matching opaque predicate evidence");

    const decomp::AnalysisFacts flattenedFacts = BuildFlattenedDispatcherFacts();
    const decomp::SemanticControlFlowEdge* semanticEdge = nullptr;

    for (const decomp::SemanticControlFlowEdge& edge : flattenedFacts.SemanticControlFlow.Edges)
    {
        if (!edge.Dead && edge.Confidence >= 0.75)
        {
            semanticEdge = &edge;
            break;
        }
    }

    Expect(semanticEdge != nullptr, "flattened fixture should expose a high-confidence semantic CFG edge");

    if (semanticEdge != nullptr)
    {
        decomp::AnalyzeRequest semanticRequest;
        semanticRequest.RequestId = "verifier_semantic_edge_snapshot";
        semanticRequest.Facts = flattenedFacts;

        decomp::AnalyzeResponse supportedSemanticEdgeResponse;
        supportedSemanticEdgeResponse.Status = "ok";
        supportedSemanticEdgeResponse.PseudoC = "void f(void) { /* semantic edge: " + semanticEdge->SourceBlock + " -> " + semanticEdge->TargetBlock + " */ return; }";
        supportedSemanticEdgeResponse.Summary = "uses recovered semantic CFG overlay edge";
        supportedSemanticEdgeResponse.Confidence = 0.91;

        const decomp::VerifyReport supportedSemanticEdgeReport = decomp::VerifyResponse(semanticRequest, supportedSemanticEdgeResponse);
        Expect(!HasIssueCode(supportedSemanticEdgeReport, "control_flow.edge_claim_without_evidence"), "verifier should allow recovered semantic CFG edge claims");
    }

    const decomp::AnalysisFacts opaqueFacts = BuildOpaquePredicateFacts();
    const decomp::SemanticControlFlowEdge* deadSemanticEdge = nullptr;

    for (const decomp::SemanticControlFlowEdge& edge : opaqueFacts.SemanticControlFlow.Edges)
    {
        if (edge.Dead && edge.Confidence >= 0.75)
        {
            deadSemanticEdge = &edge;
            break;
        }
    }

    Expect(deadSemanticEdge != nullptr, "opaque predicate fixture should expose a high-confidence dead semantic CFG edge");

    if (deadSemanticEdge != nullptr)
    {
        decomp::AnalyzeRequest opaqueConflictRequest;
        opaqueConflictRequest.RequestId = "verifier_dead_edge_live_conflict_snapshot";
        opaqueConflictRequest.Facts = opaqueFacts;

        decomp::AnalyzeResponse liveDeadEdgeResponse;
        liveDeadEdgeResponse.Status = "ok";
        liveDeadEdgeResponse.PseudoC = "void f(void) { /* semantic edge: " + deadSemanticEdge->SourceBlock + " -> " + deadSemanticEdge->TargetBlock + " */ return; }";
        liveDeadEdgeResponse.Summary = "renders the visible branch path";
        liveDeadEdgeResponse.Confidence = 0.91;

        const decomp::VerifyReport liveDeadEdgeReport = decomp::VerifyResponse(opaqueConflictRequest, liveDeadEdgeResponse);
        Expect(HasIssueCode(liveDeadEdgeReport, "obfuscation.dead_edge_rendered_as_live"), "verifier should reject opaque-proven dead edges rendered as live paths");
    }

    decomp::AnalyzeRequest dispatcherConflictRequest;
    dispatcherConflictRequest.RequestId = "verifier_raw_dispatcher_loop_snapshot";
    dispatcherConflictRequest.Facts = flattenedFacts;

    decomp::AnalyzeResponse rawDispatcherLoopResponse;
    rawDispatcherLoopResponse.Status = "ok";
    rawDispatcherLoopResponse.PseudoC = "void f(void) { while (dispatcher_state != 3) { dispatcher_state = dispatcher_state + 1; } }";
    rawDispatcherLoopResponse.Summary = "raw dispatcher state machine loop is the recovered source logic";
    rawDispatcherLoopResponse.Confidence = 0.91;

    const decomp::VerifyReport rawDispatcherLoopReport = decomp::VerifyResponse(dispatcherConflictRequest, rawDispatcherLoopResponse);
    Expect(HasIssueCode(rawDispatcherLoopReport, "obfuscation.raw_dispatcher_loop_without_uncertainty"), "verifier should flag raw dispatcher loops emitted without uncertainty");
    Expect(IssueEvidenceContains(rawDispatcherLoopReport, "obfuscation.raw_dispatcher_loop_without_uncertainty", "raw dispatcher state machine loop"), "raw dispatcher loop issue should include the matched claim context");
    const std::string rawDispatcherFeedbackPrompt = decomp::BuildDebugVerifierFeedbackPrompt(rawDispatcherLoopReport);
    Expect(rawDispatcherFeedbackPrompt.find("raw dispatcher state machine loop") != std::string::npos, "verifier feedback should include raw dispatcher loop claim text");
    Expect(rawDispatcherFeedbackPrompt.find("obfuscation.dispatchers.recovered_edges") != std::string::npos, "verifier feedback should name dispatcher recovery fact paths");

    decomp::AnalyzeResponse rawDispatcherLoopUncertaintyResponse = rawDispatcherLoopResponse;
    rawDispatcherLoopUncertaintyResponse.Uncertainties.push_back("raw dispatcher loop retained as fallback uncertainty");

    const decomp::VerifyReport rawDispatcherLoopUncertaintyReport = decomp::VerifyResponse(dispatcherConflictRequest, rawDispatcherLoopUncertaintyResponse);
    Expect(!HasIssueCode(rawDispatcherLoopUncertaintyReport, "obfuscation.raw_dispatcher_loop_without_uncertainty"), "verifier should allow raw dispatcher loop text when uncertainty is explicit");
}

void TestMergeOutputPolicySnapshot()
{
    decomp::AnalyzeRequest request;
    request.RequestId = "merge_output_policy_snapshot";
    request.Facts = BuildDiamondFacts();

    decomp::LlmClientConfig config;
    config.ForceChunked = true;
    config.ChunkBlockLimit = 1;
    config.ChunkCountLimit = 8;

    decomp::AnalyzeResponse response;
    response.Status = "ok";
    response.PseudoC = "void f(void) { return; }";
    response.Summary = "clean high-confidence merge";
    response.Confidence = 0.92;

    decomp::ApplyDebugMergeOutputPolicy(request, config, response);

    Expect(response.Confidence <= 0.55, "merge output policy should cap confidence at the debug chunk ceiling");
    Expect(response.Verifier.AdjustedConfidence <= response.Confidence + 0.001, "merge output policy should cap verifier adjusted confidence");
    Expect(!response.Uncertainties.empty(), "merge output policy should emit required uncertainty");
    Expect(HasIssueCode(response.Verifier, "merge.confidence_ceiling_exceeded"), "merge output policy should flag confidence ceiling violations");
    Expect(HasIssueCode(response.Verifier, "merge.acceptance_blockers_missing_uncertainty"), "merge output policy should flag omitted acceptance uncertainty");
    Expect(HasIssueCode(response.Verifier, "merge.acceptance_blockers_high_confidence"), "merge output policy should flag high confidence with acceptance blockers");
}

void TestUxHelperSnapshot()
{
    decomp::AnalyzeRequest request;
    request.RequestId = "ux_helper_snapshot";
    request.Facts = BuildDiamondFacts();

    decomp::LlmClientConfig config;
    decomp::LlmChunkPlanSummary plan = decomp::SummarizeLlmChunkPlan(request, config);
    Expect(!plan.UseChunked, "small UX plan should use single-pass analysis");
    Expect(plan.EstimatedChunks == 1, "single-pass UX plan should report one estimated chunk");

    config.ForceChunked = true;
    plan = decomp::SummarizeLlmChunkPlan(request, config);
    Expect(plan.UseChunked, "forced UX plan should report chunked analysis");
    Expect(plan.EstimatedChunks >= 1, "forced UX plan should report at least one chunk");
    Expect(plan.Reason == "force_chunked", "forced UX plan should explain chunking reason");

    decomp::CallSite fatalCall;
    fatalCall.Site = 0x1024;
    fatalCall.Target = "snapshot!Fatal";
    fatalCall.Kind = "direct";
    fatalCall.Returns = false;
    request.Facts.Calls.push_back(fatalCall);

    decomp::AnalyzeResponse response;
    response.Status = "ok";
    response.PseudoC = "void f(void) { Fatal(); return; }";
    response.Summary = "calls fatal helper";
    response.Confidence = 0.88;

    decomp::VerifyResponse(request, response);
    std::vector<decomp::SuggestedFix> fixes = decomp::BuildSuggestedFixes(request, response);
    bool foundNoReturnFix = false;

    for (const decomp::SuggestedFix& fix : fixes)
    {
        if (fix.SwitchText == "/fix:noreturn:snapshot!Fatal")
        {
            foundNoReturnFix = true;
        }
    }

    Expect(foundNoReturnFix, "suggested fixes should include conservative no-return correction");

    decomp::AnalyzeRequest renameRequest;
    renameRequest.RequestId = "ux_rename_snapshot";
    renameRequest.Facts = BuildDiamondFacts();

    decomp::PdbScopedSymbol scopedParam;
    scopedParam.Name = "ctx";
    scopedParam.Type = "MY_CONTEXT*";
    scopedParam.Confidence = 0.91;
    renameRequest.Facts.Pdb.Params.push_back(scopedParam);

    decomp::AnalyzeResponse renameResponse;
    renameResponse.Status = "ok";
    renameResponse.PseudoC = "void f(void) { return; }";
    renameResponse.Summary = "generic names";
    renameResponse.Confidence = 0.75;

    decomp::TypedNameConfidence genericParam;
    genericParam.Name = "arg1";
    genericParam.Type = "void*";
    genericParam.Confidence = 0.60;
    renameResponse.Params.push_back(genericParam);
    decomp::VerifyResponse(renameRequest, renameResponse);
    fixes = decomp::BuildSuggestedFixes(renameRequest, renameResponse);
    bool foundRenameFix = false;

    for (const decomp::SuggestedFix& fix : fixes)
    {
        if (fix.SwitchText == "/fix:rename:arg1=ctx")
        {
            foundRenameFix = true;
        }
    }

    Expect(foundRenameFix, "suggested fixes should include PDB-backed rename correction");

    decomp::AnalyzeRequest fieldRequest;
    fieldRequest.RequestId = "ux_field_snapshot";
    fieldRequest.Facts = BuildDiamondFacts();

    decomp::ObservedMemoryHotspot hotspot;
    hotspot.Expression = "[rcx+0x18]";
    hotspot.Kind = "memory";
    hotspot.ReadCount = 3;
    hotspot.WriteCount = 1;
    hotspot.Confidence = 0.78;
    hotspot.Sites.push_back(0x1008);
    fieldRequest.Facts.ObservedBehavior.MemoryHotspots.push_back(hotspot);

    decomp::AnalyzeResponse fieldResponse;
    fieldResponse.Status = "ok";
    fieldResponse.PseudoC = "void f(void) { return; }";
    fieldResponse.Summary = "memory hotspot";
    fieldResponse.Confidence = 0.70;
    decomp::VerifyResponse(fieldRequest, fieldResponse);
    fixes = decomp::BuildSuggestedFixes(fieldRequest, fieldResponse);
    bool foundFieldFix = false;

    for (const decomp::SuggestedFix& fix : fixes)
    {
        if (fix.SwitchText == "/fix:field:[rcx+0x18]=TYPE")
        {
            foundFieldFix = true;
        }
    }

    Expect(foundFieldFix, "suggested fixes should include repeated hotspot field correction");
}
}

int main()
{
    TestAnalyzerSnapshot();
    TestIrUseSnapshot();
    TestSwitchTargetPropagationSnapshot();
    TestFlagClobberSnapshot();
    TestImplicitAndCallSnapshot();
    TestCallArgumentStackWindowSnapshot();
    TestCfgSensitiveFactsSnapshot();
    TestStackAliasSnapshot();
    TestTailCallSnapshot();
    TestConditionalMoveSnapshot();
    TestObfuscationFactsSnapshot();
    TestSimdAbiSnapshot();
    TestIndirectVirtualCallSnapshot();
    TestLoopInductionSnapshot();
    TestKnownApiSemanticSnapshot();
    TestStackNormalizationSnapshot();
    TestSwitchSchemaSnapshot();
    TestPromptCallArgumentPackingSnapshot();
    TestStructuredPrototypeSchemaSnapshot();
    TestVerifierSnapshot();
    TestVerifierCoverageSnapshot();
    TestMergeOutputPolicySnapshot();
    TestUxHelperSnapshot();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " snapshot test failure(s)\n";
        return 1;
    }

    std::cout << "snapshot tests passed\n";
    return 0;
}
