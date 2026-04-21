#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace decomp
{
enum class DebugSessionKind
{
    Unknown,
    User,
    Kernel
};

enum class AnalysisMode
{
    LiveMemory,
    FileImage
};

struct DecompOptions
{
    bool UseLiveMemory = true;
    bool BriefOutput = false;
    bool JsonOutput = false;
    bool DisableLlm = false;
    uint32_t TimeoutMs = 5000;
    uint32_t MaxInstructions = 4096;
    
};

struct FunctionRegion
{
    uint64_t Start = 0;
    uint64_t End = 0;
};

struct ModuleInfo
{
    std::string ImageName;
    std::string ModuleName;
    std::string LoadedImageName;
    uint64_t Base = 0;
    uint32_t Size = 0;
    uint32_t SymbolType = 0;
};

struct StackFrameFacts
{
    uint32_t StackAlloc = 0;
    std::vector<std::string> SavedNonvolatile;
    bool UsesCookie = false;
    bool FramePointer = false;
};

struct DisassembledInstruction
{
    uint64_t Address = 0;
    uint64_t EndAddress = 0;
    std::string Text;
    std::string OperationText;
    std::string Mnemonic;
    std::string OperandText;
    bool IsConditionalBranch = false;
    bool IsUnconditionalBranch = false;
    bool IsCall = false;
    bool IsReturn = false;
    bool IsIndirect = false;
    uint64_t BranchTarget = 0;
    bool HasBranchTarget = false;
};

struct BasicBlock
{
    std::string Id;
    uint64_t StartAddress = 0;
    uint64_t EndAddress = 0;
    std::vector<uint64_t> InstructionAddresses;
    std::vector<std::string> Successors;
    bool HasTerminal = false;
};

struct CallSite
{
    uint64_t Site = 0;
    std::string Target;
    std::string Kind;
    bool Returns = true;
};

struct SwitchInfo
{
    uint64_t Site = 0;
    uint32_t CaseCount = 0;
    std::string Detail;
};

struct MemoryAccess
{
    uint64_t Site = 0;
    std::string Access;
};

struct AnalysisFacts
{
    std::string Arch = "x64";
    DebugSessionKind Session = DebugSessionKind::Unknown;
    AnalysisMode Mode = AnalysisMode::LiveMemory;
    std::string QueryText;
    ModuleInfo Module;
    uint64_t QueryAddress = 0;
    uint64_t EntryAddress = 0;
    uint64_t Rva = 0;
    std::vector<FunctionRegion> Regions;
    StackFrameFacts StackFrame;
    std::string CallingConvention = "ms_x64";
    std::vector<DisassembledInstruction> Instructions;
    std::vector<BasicBlock> Blocks;
    std::vector<CallSite> Calls;
    std::vector<CallSite> IndirectCalls;
    std::vector<SwitchInfo> Switches;
    std::vector<MemoryAccess> MemoryAccesses;
    std::vector<std::string> Facts;
    std::vector<std::string> UncertainPoints;
    double PreLlmConfidence = 0.0;
    std::string BytesSha256;
    bool LiveBytesDifferFromImage = false;
};

struct AnalyzeRequest
{
    AnalysisFacts Facts;
    uint32_t TimeoutMs = 5000;
    bool BriefOutput = false;
    std::string RequestId;
};

struct TypedNameConfidence
{
    std::string Name;
    std::string Type;
    double Confidence = 0.0;
};

struct EvidenceItem
{
    std::string Claim;
    std::vector<std::string> Blocks;
};

struct VerifyReport
{
    bool SchemaOk = false;
    uint32_t FactConflicts = 0;
    uint32_t MissingEvidence = 0;
    double AdjustedConfidence = 0.0;
    std::vector<std::string> Warnings;
};

struct AnalyzeResponse
{
    std::string Status = "error";
    std::string PseudoC;
    std::string Summary;
    std::vector<TypedNameConfidence> Params;
    std::vector<TypedNameConfidence> Locals;
    std::vector<std::string> Uncertainties;
    std::vector<EvidenceItem> Evidence;
    double Confidence = 0.0;
    VerifyReport Verifier;
    std::string Provider;
    std::string RawModelJson;
    uint32_t TimingMs = 0;
};
}


