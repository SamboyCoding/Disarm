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
}
