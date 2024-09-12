using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class SimdTest : BaseDisarmTest
{
    public SimdTest(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestSimdInstruction() 
        => DisassembleAndCheckMnemonic(0x4EA0_1C08, Arm64Mnemonic.MOV);

    [Fact]
    public void TestScvtf() 
        => DisassembleAndCheckMnemonic(0x1E2202A1U, Arm64Mnemonic.SCVTF);

    [Fact]
    public void Test2SourceFp() 
        => DisassembleAndCheckMnemonic(0x1E201820U, Arm64Mnemonic.FDIV);

    [Fact]
    public void TestFp16Scvtf()
    {
        var result = DisassembleAndCheckMnemonic(0x5E21D800U, Arm64Mnemonic.SCVTF);
        Assert.Equal(Arm64Register.S0, result.Op0Reg);
    }

    [Fact]
    public void TestFpCompare()
    {
        var result = DisassembleAndCheckMnemonic(0x1E602020U, Arm64Mnemonic.FCMP);
        Assert.Equal(Arm64Register.D1, result.Op0Reg);
        Assert.Equal(Arm64Register.D0, result.Op1Reg);
    }

    [Fact]
    public void TestFsqrt()
    {
        var result = DisassembleAndCheckMnemonic(0x1E61C020U, Arm64Mnemonic.FSQRT);
        Assert.Equal(Arm64Register.D0, result.Op0Reg);
        Assert.Equal(Arm64Register.D1, result.Op1Reg);
    }

    [Fact]
    public void TestFcsel()
    {
        var result = DisassembleAndCheckMnemonic(0x1E281C00U, Arm64Mnemonic.FCSEL);
        Assert.Equal(Arm64Register.S0, result.Op0Reg);
        Assert.Equal(Arm64Register.S0, result.Op1Reg);
        Assert.Equal(Arm64Register.S8, result.Op2Reg);
        Assert.Equal(Arm64ConditionCode.NE, result.FinalOpConditionCode);
    }

    [Fact]
    public void TestMovi()
    {
        var result = DisassembleAndCheckMnemonic(0x2F00E400U, Arm64Mnemonic.MOVI);
        Assert.Equal(Arm64Register.D0, result.Op0Reg);
        Assert.Equal(0, result.Op1Imm);
    }

    [Fact]
    public void TestAdvancedSimdCopy()
    {
        //MOV V0.S[1], V1.S[0]
        var result = DisassembleAndCheckMnemonic(0x6E0C0420U, Arm64Mnemonic.MOV);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op1Kind);
        Assert.Equal(Arm64Register.V0, result.Op0Reg);
        Assert.Equal(Arm64Register.V1, result.Op1Reg);
        Assert.Equal(1, result.Op0VectorElement.Index);
        Assert.Equal(0, result.Op1VectorElement.Index);
        Assert.Equal(Arm64VectorElementWidth.S, result.Op0VectorElement.Width);
        Assert.Equal(Arm64VectorElementWidth.S, result.Op1VectorElement.Width);
    }

    [Fact]
    public void TestMixedVectorElementToRegMov()
    {
        var result = DisassembleAndCheckMnemonic(0x5E0C0401, Arm64Mnemonic.MOV);
        Assert.Equal(Arm64OperandKind.Register, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.VectorRegisterElement, result.Op1Kind);
        Assert.Equal(Arm64Register.S1, result.Op0Reg);
        Assert.Equal(Arm64Register.V0, result.Op1Reg);
        Assert.Equal(Arm64VectorElementWidth.S, result.Op1VectorElement.Width);
        Assert.Equal(1, result.Op1VectorElement.Index);
    }

    [Fact]
    public void TestFmovImmediateToScalar()
    {
        var result = DisassembleAndCheckMnemonic(0x1E3E1000, Arm64Mnemonic.FMOV);
        Assert.Equal(Arm64OperandKind.Register, result.Op0Kind);
        Assert.Equal(Arm64OperandKind.FloatingPointImmediate, result.Op1Kind);
        Assert.Equal(Arm64Register.S0, result.Op0Reg);
        Assert.Equal(-1, result.Op1FpImm);
    }

    [Fact]
    public void TestCryptoAes()
    {
        var insn = DisassembleAndCheckMnemonic(0x4E284820, Arm64Mnemonic.AESE);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.V1, insn.Op1Reg);
        
        Assert.Equal(Arm64ArrangementSpecifier.SixteenB, insn.Op0Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.SixteenB, insn.Op1Arrangement);
        
        Assert.Equal("0x00000000 AESE V0.16B, V1.16B", insn.ToString());

        DisassembleAndCheckMnemonic(0x4E285820, Arm64Mnemonic.AESD);
        DisassembleAndCheckMnemonic(0x4E286820, Arm64Mnemonic.AESMC);
        DisassembleAndCheckMnemonic(0x4E287820, Arm64Mnemonic.AESIMC);
    }

    [Fact]
    public void TestCryptoTwoRegSha()
    {
        var insn = DisassembleAndCheckMnemonic(0x5E280820, Arm64Mnemonic.SHA1H);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.S0, insn.Op0Reg);
        Assert.Equal(Arm64Register.S1, insn.Op1Reg);
        
        Assert.Equal("0x00000000 SHA1H S0, S1", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E281820, Arm64Mnemonic.SHA1SU1);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.V1, insn.Op1Reg);
        
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op0Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op1Arrangement);
        
        Assert.Equal("0x00000000 SHA1SU1 V0.4S, V1.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E282820, Arm64Mnemonic.SHA256SU0);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.V1, insn.Op1Reg);
        
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op0Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op1Arrangement);
        
        Assert.Equal("0x00000000 SHA256SU0 V0.4S, V1.4S", insn.ToString());
    }

    [Fact]
    public void TestCryptoThreeRegSha()
    {
        var insn = DisassembleAndCheckMnemonic(0x5E020020, Arm64Mnemonic.SHA1C);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op2Kind);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.S1, insn.Op1Reg);
        Assert.Equal(Arm64Register.V2, insn.Op2Reg);
        
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op2Arrangement);
        
        Assert.Equal("0x00000000 SHA1C V0, S1, V2.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E021020, Arm64Mnemonic.SHA1P);
        
        Assert.Equal("0x00000000 SHA1P V0, S1, V2.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E022020, Arm64Mnemonic.SHA1M);
        
        Assert.Equal("0x00000000 SHA1M V0, S1, V2.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E023020, Arm64Mnemonic.SHA1SU0);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.V1, insn.Op1Reg);
        Assert.Equal(Arm64Register.V2, insn.Op2Reg);
        
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op0Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op1Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op2Arrangement);
        
        Assert.Equal("0x00000000 SHA1SU0 V0.4S, V1.4S, V2.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E024020, Arm64Mnemonic.SHA256H);
        
        Assert.Equal("0x00000000 SHA256H V0, V1, V2.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E025020, Arm64Mnemonic.SHA256H2);
        
        Assert.Equal("0x00000000 SHA256H2 V0, V1, V2.4S", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5E026020, Arm64Mnemonic.SHA256SU1);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.V1, insn.Op1Reg);
        Assert.Equal(Arm64Register.V2, insn.Op2Reg);
        
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op0Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op1Arrangement);
        Assert.Equal(Arm64ArrangementSpecifier.FourS, insn.Op2Arrangement);
        
        Assert.Equal("0x00000000 SHA256SU1 V0.4S, V1.4S, V2.4S", insn.ToString());
    }

    [Fact]
    public void TestAdvancedSimdThreeSame()
    {
        var insn = DisassembleAndCheckMnemonic(0x0EA21C20, Arm64Mnemonic.ORR);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op1Kind);
        Assert.Equal(Arm64OperandKind.Register, insn.Op2Kind);
        
        Assert.Equal(Arm64Register.V0, insn.Op0Reg);
        Assert.Equal(Arm64Register.V1, insn.Op1Reg);
        Assert.Equal(Arm64Register.V2, insn.Op2Reg);
        
        Assert.Equal("0x00000000 ORR V0.8B, V1.8B, V2.8B", insn.ToString());
    }

    [Fact]
    public void TestScalarAdvancedSimdShiftByImmediate()
    {
        Arm64Instruction inst;
        inst = DisassembleAndCheckMnemonic(0x7F40060A, Arm64Mnemonic.USHR);
        Assert.Equal("0x00000000 USHR D10, D16, 0x40", inst.ToString());        
        inst = DisassembleAndCheckMnemonic(0x7F40171D, Arm64Mnemonic.USRA); 
        Assert.Equal("0x00000000 USRA D29, D24, 0x40", inst.ToString());        
        inst = DisassembleAndCheckMnemonic(0x7F402491, Arm64Mnemonic.URSHR);
        Assert.Equal("0x00000000 URSHR D17, D4, 0x40", inst.ToString());        
        inst = DisassembleAndCheckMnemonic(0x7F4035AA, Arm64Mnemonic.URSRA);
        Assert.Equal("0x00000000 URSRA D10, D13, 0x40", inst.ToString());       
        inst = DisassembleAndCheckMnemonic(0x7F404693, Arm64Mnemonic.SRI);  
        Assert.Equal("0x00000000 SRI D19, D20, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F405591, Arm64Mnemonic.SLI);
        Assert.Equal("0x00000000 SLI D17, D12, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F086526, Arm64Mnemonic.SQSHLU);
        Assert.Equal("0x00000000 SQSHLU B6, B9, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F106526, Arm64Mnemonic.SQSHLU);
        Assert.Equal("0x00000000 SQSHLU H6, H9, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F206526, Arm64Mnemonic.SQSHLU);
        Assert.Equal("0x00000000 SQSHLU S6, S9, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F406526, Arm64Mnemonic.SQSHLU);
        Assert.Equal("0x00000000 SQSHLU D6, D9, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F08766F, Arm64Mnemonic.UQSHL);
        Assert.Equal("0x00000000 UQSHL B15, B19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F10766F, Arm64Mnemonic.UQSHL);
        Assert.Equal("0x00000000 UQSHL H15, H19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F20766F, Arm64Mnemonic.UQSHL);
        Assert.Equal("0x00000000 UQSHL S15, S19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F40766F, Arm64Mnemonic.UQSHL);
        Assert.Equal("0x00000000 UQSHL D15, D19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F10867C, Arm64Mnemonic.SQSHRUN);
        Assert.Equal("0x00000000 SQSHRUN H28, S19, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F20867C, Arm64Mnemonic.SQSHRUN);
        Assert.Equal("0x00000000 SQSHRUN S28, D19, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F108C56, Arm64Mnemonic.SQRSHRUN);
        Assert.Equal("0x00000000 SQRSHRUN H22, S2, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F208C56, Arm64Mnemonic.SQRSHRUN);
        Assert.Equal("0x00000000 SQRSHRUN S22, D2, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F109429, Arm64Mnemonic.UQSHRN);
        Assert.Equal("0x00000000 UQSHRN H9, S1, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F3F9429, Arm64Mnemonic.UQSHRN);
        Assert.Equal("0x00000000 UQSHRN S9, D1, 0x1", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F109DEE, Arm64Mnemonic.UQRSHRN);
        Assert.Equal("0x00000000 UQRSHRN H14, S15, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F209DEE, Arm64Mnemonic.UQRSHRN);
        Assert.Equal("0x00000000 UQRSHRN S14, D15, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F10E492, Arm64Mnemonic.UCVTF);
        Assert.Equal("0x00000000 UCVTF H18, H4, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F20E492, Arm64Mnemonic.UCVTF);
        Assert.Equal("0x00000000 UCVTF S18, S4, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F40E492, Arm64Mnemonic.UCVTF);
        Assert.Equal("0x00000000 UCVTF D18, D4, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F10FDCF, Arm64Mnemonic.FCVTZU);
        Assert.Equal("0x00000000 FCVTZU H15, H14, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F20FDCF, Arm64Mnemonic.FCVTZU);
        Assert.Equal("0x00000000 FCVTZU S15, S14, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x7F40FDCF, Arm64Mnemonic.FCVTZU);
        Assert.Equal("0x00000000 FCVTZU D15, D14, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F400797, Arm64Mnemonic.SSHR);
        Assert.Equal("0x00000000 SSHR D23, D28, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F401559, Arm64Mnemonic.SSRA);
        Assert.Equal("0x00000000 SSRA D25, D10, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F402697, Arm64Mnemonic.SRSHR);
        Assert.Equal("0x00000000 SRSHR D23, D20, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F40357D, Arm64Mnemonic.SRSRA);
        Assert.Equal("0x00000000 SRSRA D29, D11, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F40569A, Arm64Mnemonic.SHL);
        Assert.Equal("0x00000000 SHL D26, D20, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F087668, Arm64Mnemonic.SQSHL);
        Assert.Equal("0x00000000 SQSHL B8, B19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F107668, Arm64Mnemonic.SQSHL);
        Assert.Equal("0x00000000 SQSHL H8, H19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F207668, Arm64Mnemonic.SQSHL);
        Assert.Equal("0x00000000 SQSHL S8, S19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F407668, Arm64Mnemonic.SQSHL);
        Assert.Equal("0x00000000 SQSHL D8, D19, 0x0", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F1095A0, Arm64Mnemonic.SQSHRN);
        Assert.Equal("0x00000000 SQSHRN H0, S13, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F2095A0, Arm64Mnemonic.SQSHRN);
        Assert.Equal("0x00000000 SQSHRN S0, D13, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F109F2B, Arm64Mnemonic.SQRSHRN);
        Assert.Equal("0x00000000 SQRSHRN H11, S25, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F209F2B, Arm64Mnemonic.SQRSHRN);
        Assert.Equal("0x00000000 SQRSHRN S11, D25, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F10E533, Arm64Mnemonic.SCVTF);
        Assert.Equal("0x00000000 SCVTF H19, H9, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F20E533, Arm64Mnemonic.SCVTF);
        Assert.Equal("0x00000000 SCVTF S19, S9, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F40E533, Arm64Mnemonic.SCVTF);
        Assert.Equal("0x00000000 SCVTF D19, D9, 0x40", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F10FDBA, Arm64Mnemonic.FCVTZS);
        Assert.Equal("0x00000000 FCVTZS H26, H13, 0x10", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F20FDBA, Arm64Mnemonic.FCVTZS);
        Assert.Equal("0x00000000 FCVTZS S26, S13, 0x20", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F40FDBA, Arm64Mnemonic.FCVTZS);
        Assert.Equal("0x00000000 FCVTZS D26, D13, 0x40", inst.ToString());
    }

    [Fact]
    public void TestScalarAdvancedSimdScalarXIndexedElement()
    {
        Arm64Instruction inst;
        inst = DisassembleAndCheckMnemonic(0x5F553862, Arm64Mnemonic.SQDMLAL);
        Assert.Equal("0x00000000 SQDMLAL S2, H3, V5.H[5]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F557021, Arm64Mnemonic.SQDMLSL);
        Assert.Equal("0x00000000 SQDMLSL S1, H1, V5.H[1]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F55B021, Arm64Mnemonic.SQDMULL);
        Assert.Equal("0x00000000 SQDMULL S1, H1, V5.H[1]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F55C021, Arm64Mnemonic.SQDMULH);
        Assert.Equal("0x00000000 SQDMULH H1, H1, V5.H[1]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5F55D021, Arm64Mnemonic.SQRDMULH);
        Assert.Equal("0x00000000 SQRDMULH H1, H1, V5.H[1]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5FA01021, Arm64Mnemonic.FMLA);
        Assert.Equal("0x00000000 FMLA S1, S1, V0.S[1]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5FA05021, Arm64Mnemonic.FMLS);
        Assert.Equal("0x00000000 FMLS S1, S1, V0.S[1]", inst.ToString());
        inst = DisassembleAndCheckMnemonic(0x5FA09021, Arm64Mnemonic.FMUL);
        Assert.Equal("0x00000000 FMUL S1, S1, V0.S[1]", inst.ToString());
        DisassembleAndCheckMnemonic(0x7F55D021, Arm64Mnemonic.SQRDMLAH);
        DisassembleAndCheckMnemonic(0x7F55F021, Arm64Mnemonic.SQRDMLSH);
        inst = DisassembleAndCheckMnemonic(0x7FA09021, Arm64Mnemonic.FMULX);
        Assert.Equal("0x00000000 FMULX S1, S1, V0.S[1]", inst.ToString());
    }
}
