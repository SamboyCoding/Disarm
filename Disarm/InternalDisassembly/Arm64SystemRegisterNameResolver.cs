namespace Disarm.InternalDisassembly;

//maps packed o0:op1:CRn:CRm:op2 encodings to architectural names
internal static class Arm64SystemRegisterNameResolver
{
    public static string? Resolve(long encoding) => encoding switch
    {
        0xC000 => "MIDR_EL1",
        0xC005 => "MPIDR_EL1",
        0xD801 => "CTR_EL0",
        0xD807 => "DCZID_EL0",
        0xDA10 => "NZCV",
        0xDA20 => "FPCR",
        0xDA21 => "FPSR",
        0xDE82 => "TPIDR_EL0",
        0xDE83 => "TPIDRRO_EL0",
        0xDF00 => "CNTFRQ_EL0",
        0xDF01 => "CNTPCT_EL0",
        0xDF02 => "CNTVCT_EL0",
        _ => null,
    };
}
