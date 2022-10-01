namespace Disarm;

public enum Arm64MnemonicCategory
{
    Unspecified,
    Barrier,
    Branch,
    Comparison,
    ConditionalBranch,
    FlagMath, //FEAT_FlagM - Condition flag manipulation
    FloatingPointComparison,
    FloatingPointConversion,
    FloatingPointDataProcessing,
    FloatingPointMath,
    Exception,
    GeneralDataProcessing,
    Hint,
    LoadAddress, //ADR, ADRP, etc
    Math, //Covers integer math (add/sub), logical operations (and/or/xor/shifts), and things like CRC32
    MemoryTagging, //FEAT_MTE - Memory Tagging Extension, IRG/GMI/SUBP
    MemoryToOrFromRegister, //LDR, STR, etc
    Move, //Only applies to non-SIMD moves - see also SimdConstantToRegister and SimdRegisterToRegister
    PointerAuthentication, //FEAT_PAuth - Pointer Authentication Extension, PACGA etc
    Pstate,
    Return,
    ScalableVectorExtension, //FEAT_SVE - Scalable Vector Extension, SVE instructions
    SimdComparison,
    SimdConstantToRegister, //FMOV, MOVI, etc
    SimdCryptographic,
    SimdRegisterToRegister, //INS (element), SMOV, UMOV, DUP, etc
    SimdScalarConversion, //Conversion to/from integer, floating point, etc
    SimdScalarMath,
    SimdScalarRegisterToRegister, //FMOV, MOV, etc
    SimdStructureLoadOrStore,
    SimdVectorMath,
    System,
}