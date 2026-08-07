using Xunit.Abstractions;

namespace Disarm.Tests;

public class HintTests : BaseDisarmTest
{
    public HintTests(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }

    [Fact]
    public void TestNop() 
        => DisassembleAndCheckMnemonic(0xD503201F, Arm64Mnemonic.NOP);
    
    [Fact]
    public void TestYield() 
        => DisassembleAndCheckMnemonic(0xD503203F, Arm64Mnemonic.YIELD);
    
    [Fact]
    public void TestWfe() 
        => DisassembleAndCheckMnemonic(0xD503205F, Arm64Mnemonic.WFE);
    
    [Fact]
    public void TestWfi() 
        => DisassembleAndCheckMnemonic(0xD503207F, Arm64Mnemonic.WFI);
    
    [Fact]
    public void TestSev() 
        => DisassembleAndCheckMnemonic(0xD503209F, Arm64Mnemonic.SEV);
    
    [Fact]
    public void TestSevl() 
        => DisassembleAndCheckMnemonic(0xD50320BF, Arm64Mnemonic.SEVL);
    
    [Fact]
    public void TestDgh() 
        => DisassembleAndCheckMnemonic(0xD50320DF, Arm64Mnemonic.DGH);
    
    [Fact]
    public void TestXpaclri()
        => DisassembleAndCheckMnemonic(0xD50320FF, Arm64Mnemonic.XPACLRI);

    [Fact]
    public void TestPacAndAutHints()
    {
        DisassembleAndCheckMnemonic(0xD503211F, Arm64Mnemonic.PACIA1716);
        DisassembleAndCheckMnemonic(0xD503215F, Arm64Mnemonic.PACIB1716);
        DisassembleAndCheckMnemonic(0xD503219F, Arm64Mnemonic.AUTIA1716);
        DisassembleAndCheckMnemonic(0xD50321DF, Arm64Mnemonic.AUTIB1716);
        DisassembleAndCheckMnemonic(0xD503231F, Arm64Mnemonic.PACIAZ);
        DisassembleAndCheckMnemonic(0xD503233F, Arm64Mnemonic.PACIASP);
        DisassembleAndCheckMnemonic(0xD503235F, Arm64Mnemonic.PACIBZ);
        DisassembleAndCheckMnemonic(0xD503237F, Arm64Mnemonic.PACIBSP);
        DisassembleAndCheckMnemonic(0xD503239F, Arm64Mnemonic.AUTIAZ);
        DisassembleAndCheckMnemonic(0xD50323BF, Arm64Mnemonic.AUTIASP);
        DisassembleAndCheckMnemonic(0xD50323DF, Arm64Mnemonic.AUTIBZ);
        DisassembleAndCheckMnemonic(0xD50323FF, Arm64Mnemonic.AUTIBSP);
    }

    [Fact]
    public void TestBarrierAndConsistencyHints()
    {
        DisassembleAndCheckMnemonic(0xD503221F, Arm64Mnemonic.ESB);
        DisassembleAndCheckMnemonic(0xD503223F, Arm64Mnemonic.PSB_CSYNC);
        DisassembleAndCheckMnemonic(0xD503225F, Arm64Mnemonic.TSB_CSYNC);
        DisassembleAndCheckMnemonic(0xD503229F, Arm64Mnemonic.CSDB);
    }

    [Fact]
    public void TestBti()
    {
        DisassembleAndCheckMnemonic(0xD503241F, Arm64Mnemonic.BTI);
        DisassembleAndCheckMnemonic(0xD503245F, Arm64Mnemonic.BTI_C);
        DisassembleAndCheckMnemonic(0xD503249F, Arm64Mnemonic.BTI_J);
        DisassembleAndCheckMnemonic(0xD50324DF, Arm64Mnemonic.BTI_JC);
    }

    [Fact]
    public void TestUnallocatedHint()
    {
        var insn = DisassembleAndCheckMnemonic(0xD50325BF, Arm64Mnemonic.HINT);
        Assert.Equal("0x00000000 HINT 0x2D", insn.ToString());
    }
}