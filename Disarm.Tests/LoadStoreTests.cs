using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class LoadStoreTests : BaseDisarmTest
{
    public LoadStoreTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void LoadStoreRegisterFromImm() 
        => DisassembleAndCheckMnemonic(0x38420F59U, Arm64Mnemonic.LDRB);

    [Fact]
    public void LoadStoreRegFromRegOffset()
    {
        var instruction = DisassembleAndCheckMnemonic(0xB8697949U, Arm64Mnemonic.LDR);
        
        Assert.Equal(Arm64Register.W9, instruction.Op0Reg);
        Assert.Equal(Arm64OperandKind.Memory, instruction.Op1Kind);
        Assert.Equal(Arm64Register.X10, instruction.MemBase);
        Assert.Equal(Arm64Register.X9, instruction.MemAddendReg);
        Assert.Equal(Arm64ShiftType.LSL, instruction.MemShiftType);
        Assert.Equal(2, instruction.MemExtendOrShiftAmount);
        
        Assert.Equal("0x00000000 LDR W9, [X10, X9, LSL #2]", instruction.ToString());
    }

    [Fact]
    public void LoadRegFromMemImmPostIndex()
    {
        var instruction = DisassembleAndCheckMnemonic(0xF8420688, Arm64Mnemonic.LDR);
        
        Assert.Equal(Arm64Register.X8, instruction.Op0Reg);
        Assert.Equal(Arm64OperandKind.Memory, instruction.Op1Kind);
        Assert.Equal(Arm64Register.X20, instruction.MemBase);
        Assert.Equal(0x20, instruction.MemOffset);
        Assert.Equal(MemoryIndexMode.PostIndex, instruction.MemIndexMode);
        
        Assert.Equal("0x00000000 LDR X8, [X20], #0x20", instruction.ToString());
    }
}
