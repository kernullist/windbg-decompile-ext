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
    bool ExplainOutput = false;
    bool FactsOnlyOutput = false;
    bool DebugPromptOutput = false;
    bool DataModelOutput = false;
    bool LastExplainOutput = false;
    bool LastFactsOutput = false;
    bool LastJsonOutput = false;
    bool LastDataModelOutput = false;
    bool LastDebugPromptOutput = false;
    bool DisableLlm = false;
    bool ClearUserOverrides = false;
    bool VerboseOutput = false;
    uint32_t TimeoutMs = 5000;
    uint32_t MaxInstructions = 4096;
    std::vector<std::string> NoReturnOverrides;
    std::vector<std::string> TypeOverrides;
    std::vector<std::string> FieldOverrides;
    std::vector<std::string> RenameOverrides;
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
    std::string Kind;
    std::string Size;
    uint32_t WidthBits = 0;
    std::string BaseRegister;
    std::string IndexRegister;
    uint32_t Scale = 0;
    std::string Displacement;
    bool RipRelative = false;
};

struct RecoveredArgument
{
    std::string Name;
    std::string Register;
    std::string TypeHint;
    std::string RoleHint;
    uint64_t FirstUseSite = 0;
    uint32_t UseCount = 0;
    double Confidence = 0.0;
};

struct RecoveredLocal
{
    std::string Name;
    std::string BaseRegister;
    int64_t Offset = 0;
    std::string Storage;
    std::string TypeHint;
    std::string RoleHint;
    uint64_t FirstSite = 0;
    uint64_t LastSite = 0;
    uint32_t ReadCount = 0;
    uint32_t WriteCount = 0;
    double Confidence = 0.0;
};

struct ValueMerge
{
    std::string BlockId;
    std::string Variable;
    std::vector<std::string> Predecessors;
    std::vector<std::string> IncomingValues;
    double Confidence = 0.0;
};

struct IrValue
{
    std::string Id;
    std::string BlockId;
    uint64_t DefSite = 0;
    std::string Target;
    std::string Expression;
    std::string Canonical;
    std::string Kind;
    std::vector<std::string> Uses;
    bool IsConstant = false;
    bool IsCopy = false;
    bool IsDead = false;
    double Confidence = 0.0;
};

struct ControlFlowRegion
{
    std::string Kind;
    std::string HeaderBlock;
    std::vector<std::string> BodyBlocks;
    std::vector<std::string> LatchBlocks;
    std::vector<std::string> ExitBlocks;
    std::string Condition;
    std::string Evidence;
    double Confidence = 0.0;
};

struct AbiFacts
{
    uint32_t ShadowSpaceBytes = 32;
    bool PrologRecognized = false;
    bool EpilogRecognized = false;
    bool FramePointerEstablished = false;
    std::string FrameBase;
    std::vector<std::string> HomeSlots;
    std::vector<std::string> NoReturnCalls;
    std::vector<std::string> TailCalls;
    std::vector<std::string> Thunks;
    std::vector<std::string> ImportWrappers;
    std::vector<std::string> Notes;
    double Confidence = 0.0;
};

struct TypeRecoveryHint
{
    uint64_t Site = 0;
    std::string Expression;
    std::string Type;
    std::string Source;
    std::string Kind;
    std::string Evidence;
    bool PointerLike = false;
    bool ArrayLike = false;
    bool EnumLike = false;
    bool BitflagLike = false;
    double Confidence = 0.0;
};

struct IdiomPattern
{
    uint64_t Site = 0;
    std::string Kind;
    std::string Name;
    std::string Summary;
    std::string Replacement;
    std::string Evidence;
    double Confidence = 0.0;
};

struct CalleeSummary
{
    uint64_t Site = 0;
    std::string Callee;
    std::string ReturnType;
    std::string ParameterModel;
    std::string SideEffects;
    std::string MemoryEffects;
    std::string Ownership;
    std::string Source;
    double Confidence = 0.0;
};

struct DataReference
{
    uint64_t Site = 0;
    uint64_t TargetAddress = 0;
    std::string Kind;
    std::string Symbol;
    std::string ModuleName;
    std::string Display;
    std::string Preview;
    bool RipRelative = false;
    bool Dereferenced = false;
};

struct CallTargetInfo
{
    uint64_t Site = 0;
    uint64_t TargetAddress = 0;
    std::string DisplayName;
    std::string TargetKind;
    std::string ModuleName;
    std::string Prototype;
    std::string ReturnType;
    std::string SideEffects;
    bool Indirect = false;
    double Confidence = 0.0;
};

struct NormalizedCondition
{
    uint64_t Site = 0;
    std::string BlockId;
    std::string BranchMnemonic;
    std::string Expression;
    std::string TrueTargetBlock;
    std::string FalseTargetBlock;
    double Confidence = 0.0;
};

struct PdbScopedSymbol
{
    std::string Name;
    std::string Type;
    std::string Storage;
    std::string Location;
    uint64_t Site = 0;
    double Confidence = 0.0;
};

struct PdbFieldHint
{
    std::string BaseName;
    std::string BaseType;
    std::string FieldName;
    std::string FieldType;
    std::string BaseRegister;
    int64_t Offset = 0;
    uint64_t Site = 0;
    double Confidence = 0.0;
};

struct PdbEnumHint
{
    std::string TypeName;
    std::string ConstantName;
    std::string Expression;
    uint64_t Value = 0;
    uint64_t Site = 0;
    double Confidence = 0.0;
};

struct PdbSourceLocation
{
    uint64_t Site = 0;
    std::string File;
    uint32_t Line = 0;
    uint64_t Displacement = 0;
    double Confidence = 0.0;
};

struct PdbFacts
{
    std::string Availability = "none";
    std::string ScopeKind = "none";
    std::string SymbolFile;
    std::string FunctionName;
    std::string Prototype;
    std::string ReturnType;
    std::vector<PdbScopedSymbol> Params;
    std::vector<PdbScopedSymbol> Locals;
    std::vector<PdbFieldHint> FieldHints;
    std::vector<PdbEnumHint> EnumHints;
    std::vector<PdbSourceLocation> SourceLocations;
    std::vector<std::string> Conflicts;
    double Confidence = 0.0;
};

struct SessionPolicyFacts
{
    std::string DebugClass;
    std::string Qualifier;
    std::string ExecutionKind;
    std::string AnalysisStrategy;
    bool IsLive = false;
    bool IsDump = false;
    bool IsKernel = false;
    bool IsTraceLike = false;
    bool TtdAvailable = false;
    std::vector<std::string> Notes;
};

struct ObservedArgumentValue
{
    std::string Name;
    std::string Register;
    uint64_t Value = 0;
    std::string Symbol;
    std::string Source;
    double Confidence = 0.0;
};

struct ObservedMemoryHotspot
{
    std::string Expression;
    std::string Kind;
    uint32_t ReadCount = 0;
    uint32_t WriteCount = 0;
    std::vector<uint64_t> Sites;
    double Confidence = 0.0;
};

struct ObservedBehaviorFacts
{
    bool CurrentInstructionInFunction = false;
    uint64_t InstructionPointer = 0;
    uint64_t StackPointer = 0;
    uint64_t ReturnAddress = 0;
    std::vector<ObservedArgumentValue> ArgumentSamples;
    std::vector<ObservedMemoryHotspot> MemoryHotspots;
    std::vector<std::string> TtdQueries;
    std::vector<std::string> Notes;
    double Confidence = 0.0;
};

struct AnalysisFacts
{
    std::string Arch = "x64";
    DebugSessionKind Session = DebugSessionKind::Unknown;
    AnalysisMode Mode = AnalysisMode::LiveMemory;
    std::string PreferredNaturalLanguageTag = "en-US";
    std::string PreferredNaturalLanguageName = "English";
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
    std::vector<RecoveredArgument> RecoveredArguments;
    std::vector<RecoveredLocal> RecoveredLocals;
    std::vector<ValueMerge> ValueMerges;
    std::vector<IrValue> IrValues;
    std::vector<ControlFlowRegion> ControlFlow;
    AbiFacts Abi;
    std::vector<TypeRecoveryHint> TypeHints;
    std::vector<IdiomPattern> Idioms;
    std::vector<CalleeSummary> CalleeSummaries;
    std::vector<DataReference> DataReferences;
    std::vector<CallTargetInfo> CallTargets;
    std::vector<NormalizedCondition> NormalizedConditions;
    PdbFacts Pdb;
    SessionPolicyFacts SessionPolicy;
    ObservedBehaviorFacts ObservedBehavior;
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

struct VerificationIssue
{
    std::string Code;
    std::string Severity;
    std::string Message;
    std::string Evidence;
};

struct PseudoCodeToken
{
    std::string Kind;
    std::string Text;
};

struct VerifyReport
{
    bool SchemaOk = false;
    uint32_t FactConflicts = 0;
    uint32_t MissingEvidence = 0;
    double AdjustedConfidence = 0.0;
    std::vector<std::string> Warnings;
    std::vector<VerificationIssue> Issues;
};

struct AnalyzeResponse
{
    std::string Status = "error";
    std::string PseudoC;
    std::vector<PseudoCodeToken> PseudoCTokens;
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
