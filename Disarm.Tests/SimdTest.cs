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
    public void TestAdvancedSimdTwoRegisterMiscFneg2S()
    {
        var inst = DisassembleAndCheckMnemonic(0x2EA0F8A7, Arm64Mnemonic.FNEG);
        Assert.Equal("0x00000000 FNEG V7.2S, V5.2S", inst.ToString());
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
}
