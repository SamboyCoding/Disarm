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

    [Fact]
    public void TestScalarAdvancedSimdScalarTwoRegisterMiscFp16()
    {
        DisassembleAndCheckMnemonic(0x5E79A812, Arm64Mnemonic.FCVTNS);
        DisassembleAndCheckMnemonic(0x5E79B812, Arm64Mnemonic.FCVTMS);
        DisassembleAndCheckMnemonic(0x5E79C812, Arm64Mnemonic.FCVTAS);
        DisassembleAndCheckMnemonic(0x5E79D812, Arm64Mnemonic.SCVTF);
        DisassembleAndCheckMnemonic(0x5EF8C812, Arm64Mnemonic.FCMGT);
        DisassembleAndCheckMnemonic(0x5EF8D812, Arm64Mnemonic.FCMEQ);
        DisassembleAndCheckMnemonic(0x5EF8E812, Arm64Mnemonic.FCMLT);
        DisassembleAndCheckMnemonic(0x5EF9A812, Arm64Mnemonic.FCVTPS);
        DisassembleAndCheckMnemonic(0x5EF9B812, Arm64Mnemonic.FCVTZS);
        DisassembleAndCheckMnemonic(0x5EF9D812, Arm64Mnemonic.FRECPE);
        DisassembleAndCheckMnemonic(0x5EF9F812, Arm64Mnemonic.FRECPX);
        DisassembleAndCheckMnemonic(0x7E79A812, Arm64Mnemonic.FCVTNU);
        DisassembleAndCheckMnemonic(0x7E79B812, Arm64Mnemonic.FCVTMU);
        DisassembleAndCheckMnemonic(0x7E79C812, Arm64Mnemonic.FCVTAU);
        DisassembleAndCheckMnemonic(0x7E79D812, Arm64Mnemonic.UCVTF);
        DisassembleAndCheckMnemonic(0x7EF8C812, Arm64Mnemonic.FCMGE);
        DisassembleAndCheckMnemonic(0x7EF8D812, Arm64Mnemonic.FCMLE);
        DisassembleAndCheckMnemonic(0x7EF9A812, Arm64Mnemonic.FCVTPU);
        DisassembleAndCheckMnemonic(0x7EF9B812, Arm64Mnemonic.FCVTZU);
        DisassembleAndCheckMnemonic(0x7EF9D812, Arm64Mnemonic.FRSQRTE);
    }
    
    [Fact]
    public void TestScalarAdvancedSimdScalarTwoRegisterMisc()
    {
        DisassembleAndCheckMnemonic(0x5EA03820, Arm64Mnemonic.SUQADD);
        DisassembleAndCheckMnemonic(0x5EA07820, Arm64Mnemonic.SQABS);
        DisassembleAndCheckMnemonic(0x5EE08841, Arm64Mnemonic.CMGT);
        DisassembleAndCheckMnemonic(0x5EE09841, Arm64Mnemonic.CMEQ);
        DisassembleAndCheckMnemonic(0x5EE0A841, Arm64Mnemonic.CMLT);
        DisassembleAndCheckMnemonic(0x5EE0B841, Arm64Mnemonic.ABS);
        DisassembleAndCheckMnemonic(0x5E214841, Arm64Mnemonic.SQXTN);
        DisassembleAndCheckMnemonic(0x5E21A841, Arm64Mnemonic.FCVTNS);
        DisassembleAndCheckMnemonic(0x5E21B841, Arm64Mnemonic.FCVTMS);
        DisassembleAndCheckMnemonic(0x5E21C841, Arm64Mnemonic.FCVTAS);
        DisassembleAndCheckMnemonic(0x5E21D841, Arm64Mnemonic.SCVTF);
        DisassembleAndCheckMnemonic(0x5EA0C841, Arm64Mnemonic.FCMGT);
        DisassembleAndCheckMnemonic(0x5EA0D841, Arm64Mnemonic.FCMEQ);
        DisassembleAndCheckMnemonic(0x5EA0E841, Arm64Mnemonic.FCMLT);
        DisassembleAndCheckMnemonic(0x5EA1B841, Arm64Mnemonic.FCVTZS); 
        DisassembleAndCheckMnemonic(0x5EA1D841, Arm64Mnemonic.FRECPE);
        DisassembleAndCheckMnemonic(0x5EA1F841, Arm64Mnemonic.FRECPX);
        DisassembleAndCheckMnemonic(0x7EA03841, Arm64Mnemonic.USQADD);
        DisassembleAndCheckMnemonic(0x7EA07841, Arm64Mnemonic.SQNEG);
        DisassembleAndCheckMnemonic(0x7EE08841, Arm64Mnemonic.CMGE);
        DisassembleAndCheckMnemonic(0x7EE09841, Arm64Mnemonic.CMLE);
        DisassembleAndCheckMnemonic(0x7EE0B841, Arm64Mnemonic.NEG);
        DisassembleAndCheckMnemonic(0x7EA12841, Arm64Mnemonic.SQXTUN);
        DisassembleAndCheckMnemonic(0x7EA14841, Arm64Mnemonic.UQXTN);
        DisassembleAndCheckMnemonic(0x7E616841, Arm64Mnemonic.FCVTXN);
        DisassembleAndCheckMnemonic(0x7E21A841, Arm64Mnemonic.FCVTNU);
        DisassembleAndCheckMnemonic(0x7E21B841, Arm64Mnemonic.FCVTMU);
        DisassembleAndCheckMnemonic(0x7E21C841, Arm64Mnemonic.FCVTAU);
        DisassembleAndCheckMnemonic(0x7E21D841, Arm64Mnemonic.UCVTF);
        DisassembleAndCheckMnemonic(0x7EA0C841, Arm64Mnemonic.FCMGE);
        DisassembleAndCheckMnemonic(0x7EA0D841, Arm64Mnemonic.FCMLE);
        DisassembleAndCheckMnemonic(0x7EA1A841, Arm64Mnemonic.FCVTPU);
        DisassembleAndCheckMnemonic(0x7EA1B841, Arm64Mnemonic.FCVTZU);
        DisassembleAndCheckMnemonic(0x7EA1D841, Arm64Mnemonic.FRSQRTE);
    }
    
    [Fact]
    public void TestScalarAdvancedSimdScalarPairwise()
    {
        DisassembleAndCheckMnemonic(0x5EF1B801, Arm64Mnemonic.ADDP);
        DisassembleAndCheckMnemonic(0x7E70C801, Arm64Mnemonic.FMAXNMP);
        DisassembleAndCheckMnemonic(0x7E70D801, Arm64Mnemonic.FADDP);
        DisassembleAndCheckMnemonic(0x7E70F801, Arm64Mnemonic.FMAXP);
        DisassembleAndCheckMnemonic(0x7EF0C801, Arm64Mnemonic.FMINNMP);
        DisassembleAndCheckMnemonic(0x7EF0F801, Arm64Mnemonic.FMINP);
    }
    
    [Fact]
    public void TestScalarAdvancedSimdScalarThreeDifferent()
    {
        DisassembleAndCheckMnemonic(0x5E639041, Arm64Mnemonic.SQDMLAL);
        DisassembleAndCheckMnemonic(0x5E63B041, Arm64Mnemonic.SQDMLSL);
        DisassembleAndCheckMnemonic(0x5E63D041, Arm64Mnemonic.SQDMULL);
    }
     
    [Fact]
    public void TestScalarAdvancedSimdScalarThreeSame()
    {
        DisassembleAndCheckMnemonic(0x5EE3_0C41, Arm64Mnemonic.SQADD);
        DisassembleAndCheckMnemonic(0x5EE3_2C41, Arm64Mnemonic.SQSUB);
        DisassembleAndCheckMnemonic(0x5EE3_3441, Arm64Mnemonic.CMGT);
        DisassembleAndCheckMnemonic(0x5EE3_3C41, Arm64Mnemonic.CMGE);
        DisassembleAndCheckMnemonic(0x5EE3_4441, Arm64Mnemonic.SSHL);
        DisassembleAndCheckMnemonic(0x5EE3_4C41, Arm64Mnemonic.SQSHL);
        DisassembleAndCheckMnemonic(0x5EE3_5441, Arm64Mnemonic.SRSHL);
        DisassembleAndCheckMnemonic(0x5EE3_5C41, Arm64Mnemonic.SQRSHL);
        DisassembleAndCheckMnemonic(0x5EE3_8441, Arm64Mnemonic.ADD);
        DisassembleAndCheckMnemonic(0x5EE3_8C41, Arm64Mnemonic.CMTST);
        DisassembleAndCheckMnemonic(0x5EA3_B441, Arm64Mnemonic.SQDMULH);
        DisassembleAndCheckMnemonic(0x5E23_DC41, Arm64Mnemonic.FMULX);
        DisassembleAndCheckMnemonic(0x5E23_E441, Arm64Mnemonic.FCMEQ);
        DisassembleAndCheckMnemonic(0x5E23_FC41, Arm64Mnemonic.FRECPS);
        DisassembleAndCheckMnemonic(0x5EA3_FC41, Arm64Mnemonic.FRSQRTS);
        DisassembleAndCheckMnemonic(0x7EA3_0C41, Arm64Mnemonic.UQADD);
        DisassembleAndCheckMnemonic(0x7EA3_2C41, Arm64Mnemonic.UQSUB);
        DisassembleAndCheckMnemonic(0x7EE3_3441, Arm64Mnemonic.CMHI);
        DisassembleAndCheckMnemonic(0x7EE3_3C41, Arm64Mnemonic.CMHS);
        DisassembleAndCheckMnemonic(0x7EE3_4441, Arm64Mnemonic.USHL);
        DisassembleAndCheckMnemonic(0x7EE3_4C41, Arm64Mnemonic.UQSHL);
        DisassembleAndCheckMnemonic(0x7EE3_5441, Arm64Mnemonic.URSHL);
        DisassembleAndCheckMnemonic(0x7EE3_5C41, Arm64Mnemonic.UQRSHL);
        DisassembleAndCheckMnemonic(0x7EE3_8441, Arm64Mnemonic.SUB);
        DisassembleAndCheckMnemonic(0x7EE3_8C41, Arm64Mnemonic.CMEQ);
        DisassembleAndCheckMnemonic(0x7EA3_B441, Arm64Mnemonic.SQRDMULH);
        DisassembleAndCheckMnemonic(0x7E63_E441, Arm64Mnemonic.FCMGE);
        DisassembleAndCheckMnemonic(0x7E63_EC41, Arm64Mnemonic.FACGE);
        DisassembleAndCheckMnemonic(0x7EE3_D441, Arm64Mnemonic.FABD);
        DisassembleAndCheckMnemonic(0x7EE3_E441, Arm64Mnemonic.FCMGT);
        DisassembleAndCheckMnemonic(0x7EE3_EC41, Arm64Mnemonic.FACGT);
    }
    
    [Fact]
    public void TestScalarAdvancedSimdScalarThreeSameFp16()
    {
        DisassembleAndCheckMnemonic(0x5E401C00, Arm64Mnemonic.FMULX);
        DisassembleAndCheckMnemonic(0x5E402400, Arm64Mnemonic.FCMEQ);
        DisassembleAndCheckMnemonic(0x5E403C00, Arm64Mnemonic.FRECPS);
        DisassembleAndCheckMnemonic(0x5EC03C00, Arm64Mnemonic.FRSQRTS);
        DisassembleAndCheckMnemonic(0x7E402400, Arm64Mnemonic.FCMGE);
        DisassembleAndCheckMnemonic(0x7E402C00, Arm64Mnemonic.FACGE);
        DisassembleAndCheckMnemonic(0x7EC01400, Arm64Mnemonic.FABD);
        DisassembleAndCheckMnemonic(0x7EC02400, Arm64Mnemonic.FCMGT);
        DisassembleAndCheckMnemonic(0x7EC02C00, Arm64Mnemonic.FACGT);
    }
    
    [Fact]
    public void TestScalarAdvancedSimdScalarThreeSameExtra()
    {
        DisassembleAndCheckMnemonic(0x7E808400, Arm64Mnemonic.SQRDMLAH);
        DisassembleAndCheckMnemonic(0x7EC08C00, Arm64Mnemonic.SQRDMLSH);
    }

    [Fact]
    public void TestAdvancedSimdPermute()
    {
        Assert.Equal("0x00000000 UZP1 V0.16B, V1.16B, V2.16B", DisassembleAndCheckMnemonic(0x4E021820, Arm64Mnemonic.UZP1).ToString());
        Assert.Equal("0x00000000 TRN1 V3.8H, V4.8H, V5.8H", DisassembleAndCheckMnemonic(0x4E452883, Arm64Mnemonic.TRN1).ToString());
        Assert.Equal("0x00000000 ZIP1 V6.4S, V7.4S, V8.4S", DisassembleAndCheckMnemonic(0x4E8838E6, Arm64Mnemonic.ZIP1).ToString());
        Assert.Equal("0x00000000 UZP2 V9.2S, V10.2S, V11.2S", DisassembleAndCheckMnemonic(0x0E8B5949, Arm64Mnemonic.UZP2).ToString());
        Assert.Equal("0x00000000 TRN2 V12.2D, V13.2D, V14.2D", DisassembleAndCheckMnemonic(0x4ECE69AC, Arm64Mnemonic.TRN2).ToString());
        Assert.Equal("0x00000000 ZIP2 V15.8B, V16.8B, V17.8B", DisassembleAndCheckMnemonic(0x0E117A0F, Arm64Mnemonic.ZIP2).ToString());
    }

    [Fact]
    public void TestAdvancedSimdExtract()
    {
        Assert.Equal("0x00000000 EXT V0.16B, V1.16B, V2.16B, 0xC", DisassembleAndCheckMnemonic(0x6E026020, Arm64Mnemonic.EXT).ToString());
        Assert.Equal("0x00000000 EXT V3.8B, V4.8B, V5.8B, 0x3", DisassembleAndCheckMnemonic(0x2E051883, Arm64Mnemonic.EXT).ToString());
    }

    [Fact]
    public void TestAdvancedSimdCopyForms()
    {
        Assert.Equal("0x00000000 DUP V0.16B, V1.B[5]", DisassembleAndCheckMnemonic(0x4E0B0420, Arm64Mnemonic.DUP).ToString());
        Assert.Equal("0x00000000 DUP V2.4S, W3", DisassembleAndCheckMnemonic(0x4E040C62, Arm64Mnemonic.DUP).ToString());
        Assert.Equal("0x00000000 DUP V4.2D, X5", DisassembleAndCheckMnemonic(0x4E080CA4, Arm64Mnemonic.DUP).ToString());

        Assert.Equal("0x00000000 SMOV W4, V5.B[2]", DisassembleAndCheckMnemonic(0x0E052CA4, Arm64Mnemonic.SMOV).ToString());
        Assert.Equal("0x00000000 SMOV X6, V7.H[3]", DisassembleAndCheckMnemonic(0x4E0E2CE6, Arm64Mnemonic.SMOV).ToString());
        Assert.Equal("0x00000000 SMOV X0, V1.S[1]", DisassembleAndCheckMnemonic(0x4E0C2C20, Arm64Mnemonic.SMOV).ToString());

        //narrow umov keeps its name, word and doubleword forms are movs
        Assert.Equal("0x00000000 UMOV W8, V9.B[4]", DisassembleAndCheckMnemonic(0x0E093D28, Arm64Mnemonic.UMOV).ToString());
        Assert.Equal("0x00000000 MOV W0, V1.S[2]", DisassembleAndCheckMnemonic(0x0E143C20, Arm64Mnemonic.MOV).ToString());
        Assert.Equal("0x00000000 MOV X10, V11.D[1]", DisassembleAndCheckMnemonic(0x4E183D6A, Arm64Mnemonic.MOV).ToString());

        //ins (general) is displayed as mov
        Assert.Equal("0x00000000 MOV V12.S[1], W13", DisassembleAndCheckMnemonic(0x4E0C1DAC, Arm64Mnemonic.MOV).ToString());
        Assert.Equal("0x00000000 MOV V14.D[0], X15", DisassembleAndCheckMnemonic(0x4E081DEE, Arm64Mnemonic.MOV).ToString());
    }

    [Fact]
    public void TestAdvancedSimdThreeSameUnsigned()
    {
        Assert.Equal("0x00000000 EOR V0.16B, V1.16B, V2.16B", DisassembleAndCheckMnemonic(0x6E221C20, Arm64Mnemonic.EOR).ToString());
        Assert.Equal("0x00000000 BSL V3.8B, V4.8B, V5.8B", DisassembleAndCheckMnemonic(0x2E651C83, Arm64Mnemonic.BSL).ToString());
        Assert.Equal("0x00000000 BIT V6.16B, V7.16B, V8.16B", DisassembleAndCheckMnemonic(0x6EA81CE6, Arm64Mnemonic.BIT).ToString());
        Assert.Equal("0x00000000 BIF V9.16B, V10.16B, V11.16B", DisassembleAndCheckMnemonic(0x6EEB1D49, Arm64Mnemonic.BIF).ToString());
        Assert.Equal("0x00000000 UQADD V0.8H, V1.8H, V2.8H", DisassembleAndCheckMnemonic(0x6E620C20, Arm64Mnemonic.UQADD).ToString());
        Assert.Equal("0x00000000 CMHI V3.4S, V4.4S, V5.4S", DisassembleAndCheckMnemonic(0x6EA53483, Arm64Mnemonic.CMHI).ToString());
        Assert.Equal("0x00000000 CMEQ V6.16B, V7.16B, V8.16B", DisassembleAndCheckMnemonic(0x6E288CE6, Arm64Mnemonic.CMEQ).ToString());
        Assert.Equal("0x00000000 SUB V9.2D, V10.2D, V11.2D", DisassembleAndCheckMnemonic(0x6EEB8549, Arm64Mnemonic.SUB).ToString());
        Assert.Equal("0x00000000 FDIV V12.4S, V13.4S, V14.4S", DisassembleAndCheckMnemonic(0x6E2EFDAC, Arm64Mnemonic.FDIV).ToString());
        Assert.Equal("0x00000000 FADDP V15.2S, V16.2S, V17.2S", DisassembleAndCheckMnemonic(0x2E31D60F, Arm64Mnemonic.FADDP).ToString());
        Assert.Equal("0x00000000 FABD V18.2D, V19.2D, V20.2D", DisassembleAndCheckMnemonic(0x6EF4D672, Arm64Mnemonic.FABD).ToString());
        Assert.Equal("0x00000000 FACGE V21.4S, V22.4S, V23.4S", DisassembleAndCheckMnemonic(0x6E37EED5, Arm64Mnemonic.FACGE).ToString());
        Assert.Equal("0x00000000 FACGT V24.2D, V25.2D, V26.2D", DisassembleAndCheckMnemonic(0x6EFAEF38, Arm64Mnemonic.FACGT).ToString());
        Assert.Equal("0x00000000 FMAXNMP V27.4S, V28.4S, V29.4S", DisassembleAndCheckMnemonic(0x6E3DC79B, Arm64Mnemonic.FMAXNMP).ToString());
        Assert.Equal("0x00000000 UABA V0.8B, V1.8B, V2.8B", DisassembleAndCheckMnemonic(0x2E227C20, Arm64Mnemonic.UABA).ToString());
        Assert.Equal("0x00000000 PMUL V3.16B, V4.16B, V5.16B", DisassembleAndCheckMnemonic(0x6E259C83, Arm64Mnemonic.PMUL).ToString());
        Assert.Equal("0x00000000 UMAXP V6.4H, V7.4H, V8.4H", DisassembleAndCheckMnemonic(0x2E68A4E6, Arm64Mnemonic.UMAXP).ToString());
    }

    [Fact]
    public void TestAdvancedSimdVectorByElement()
    {
        Assert.Equal("0x00000000 FMUL V0.4S, V1.4S, V2.S[3]", DisassembleAndCheckMnemonic(0x4FA29820, Arm64Mnemonic.FMUL).ToString());
        Assert.Equal("0x00000000 FMLA V3.2D, V4.2D, V5.D[1]", DisassembleAndCheckMnemonic(0x4FC51883, Arm64Mnemonic.FMLA).ToString());
        Assert.Equal("0x00000000 FMLS V6.2S, V7.2S, V8.S[1]", DisassembleAndCheckMnemonic(0x0FA850E6, Arm64Mnemonic.FMLS).ToString());
        Assert.Equal("0x00000000 FMULX V9.4S, V10.4S, V11.S[2]", DisassembleAndCheckMnemonic(0x6F8B9949, Arm64Mnemonic.FMULX).ToString());

        Assert.Equal("0x00000000 MLA V0.4H, V1.4H, V2.H[2]", DisassembleAndCheckMnemonic(0x2F620020, Arm64Mnemonic.MLA).ToString());
        Assert.Equal("0x00000000 MLS V3.8H, V4.8H, V5.H[7]", DisassembleAndCheckMnemonic(0x6F754883, Arm64Mnemonic.MLS).ToString());
        Assert.Equal("0x00000000 MUL V6.4S, V7.4S, V8.S[0]", DisassembleAndCheckMnemonic(0x4F8880E6, Arm64Mnemonic.MUL).ToString());

        Assert.Equal("0x00000000 SMULL V0.4S, V1.4H, V2.H[1]", DisassembleAndCheckMnemonic(0x0F52A020, Arm64Mnemonic.SMULL).ToString());
        Assert.Equal("0x00000000 SMULL2 V3.2D, V4.4S, V5.S[3]", DisassembleAndCheckMnemonic(0x4FA5A883, Arm64Mnemonic.SMULL2).ToString());
        Assert.Equal("0x00000000 UMULL V6.2D, V7.2S, V8.S[1]", DisassembleAndCheckMnemonic(0x2FA8A0E6, Arm64Mnemonic.UMULL).ToString());
        Assert.Equal("0x00000000 UMLAL V9.4S, V10.4H, V11.H[5]", DisassembleAndCheckMnemonic(0x2F5B2949, Arm64Mnemonic.UMLAL).ToString());
        Assert.Equal("0x00000000 UMLSL2 V12.2D, V13.4S, V14.S[2]", DisassembleAndCheckMnemonic(0x6F8E69AC, Arm64Mnemonic.UMLSL2).ToString());
        Assert.Equal("0x00000000 SMLSL V18.2D, V19.2S, V20.S[3]", DisassembleAndCheckMnemonic(0x0FB46A72, Arm64Mnemonic.SMLSL).ToString());

        Assert.Equal("0x00000000 SQDMULH V0.8H, V1.8H, V2.H[4]", DisassembleAndCheckMnemonic(0x4F42C820, Arm64Mnemonic.SQDMULH).ToString());
        Assert.Equal("0x00000000 SQRDMULH V3.4S, V4.4S, V5.S[1]", DisassembleAndCheckMnemonic(0x4FA5D083, Arm64Mnemonic.SQRDMULH).ToString());
        Assert.Equal("0x00000000 SQDMULL V6.4S, V7.4H, V8.H[2]", DisassembleAndCheckMnemonic(0x0F68B0E6, Arm64Mnemonic.SQDMULL).ToString());
        Assert.Equal("0x00000000 SQDMLAL2 V9.2D, V10.4S, V11.S[0]", DisassembleAndCheckMnemonic(0x4F8B3149, Arm64Mnemonic.SQDMLAL2).ToString());
        Assert.Equal("0x00000000 SQDMLSL V12.4S, V13.4H, V14.H[6]", DisassembleAndCheckMnemonic(0x0F6E79AC, Arm64Mnemonic.SQDMLSL).ToString());
    }
}
