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
        Assert.Equal(Arm64MemoryIndexMode.PostIndex, instruction.MemIndexMode);
        
        Assert.Equal("0x00000000 LDR X8, [X20], #0x20", instruction.ToString());
    }

    [Fact]
    public void TestLoadStoreMemoryTags()
    {
        var insn = DisassembleAndCheckMnemonic(0xD920341F, Arm64Mnemonic.STG);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.Memory, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.X0, insn.Op0Reg);
        Assert.Equal(Arm64Register.X31, insn.MemBase);
        Assert.Equal(0x30, insn.MemOffset);
        
        Assert.Equal(Arm64MemoryIndexMode.PostIndex, insn.MemIndexMode);
        
        Assert.Equal("0x00000000 STG X0, [X31], #0x30", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD920041F, Arm64Mnemonic.STZGM);
        Assert.Equal("0x00000000 STZGM X0, X31", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD960341F, Arm64Mnemonic.STZG);
        Assert.Equal("0x00000000 STZG X0, [X31], #0x30", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD960001F, Arm64Mnemonic.LDG);
        Assert.Equal("0x00000000 LDG X0, X31", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD9A0001F, Arm64Mnemonic.STGM);
        Assert.Equal("0x00000000 STGM X0, X31", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD9A0341F, Arm64Mnemonic.ST2G);
        Assert.Equal("0x00000000 ST2G X0, [X31], #0x30", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD9E0341F, Arm64Mnemonic.STZ2G);
        Assert.Equal("0x00000000 STZ2G X0, [X31], #0x30", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0xD9E0001F, Arm64Mnemonic.LDGM);
        Assert.Equal("0x00000000 LDGM X0, X31", insn.ToString());
    }
}
