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
}