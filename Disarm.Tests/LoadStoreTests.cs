using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class LoadStoreTests : BaseDisarmTest
{
    public LoadStoreTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void LoadStoreRegisterFromImm()
    {
        DisassembleAndCheckMnemonic(0x38420F59U, Arm64Mnemonic.LDRB);
        
        var instruction = DisassembleAndCheckMnemonic(0xFD41C100U, Arm64Mnemonic.LDR);
        
        Assert.Equal("0x00000000 LDR D0, [X8 + 0x380]", instruction.ToString());
    }

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

    [Fact]
    public void TestLoadRegisterLiteral()
    {
        var insn = DisassembleAndCheckMnemonic(0x18000101, Arm64Mnemonic.LDR); //LDR, 32-bit variant
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.ImmediatePcRelative, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.W1, insn.Op0Reg);
        Assert.Equal(0x20u, insn.Op1PcRelImm);
        
        Assert.Equal("0x00000000 LDR W1, 0x20", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x58000101, Arm64Mnemonic.LDR); //LDR, 64-bit variant
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        
        Assert.Equal(Arm64Register.X1, insn.Op0Reg);
        
        Assert.Equal("0x00000000 LDR X1, 0x20", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x98000101, Arm64Mnemonic.LDRSW);
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.ImmediatePcRelative, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.X1, insn.Op0Reg);
        Assert.Equal(0x20u, insn.Op1PcRelImm);
        
        Assert.Equal("0x00000000 LDRSW X1, 0x20", insn.ToString());
        
        //TODO Better tests for PRFM when we support the prefetch operand type
        DisassembleAndCheckMnemonic(0xD8000101, Arm64Mnemonic.PRFM);

        insn = DisassembleAndCheckMnemonic(0x1C000101, Arm64Mnemonic.LDR); //LDR, 32-bit SIMD variant
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.ImmediatePcRelative, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.S1, insn.Op0Reg);
        Assert.Equal(0x20u, insn.Op1PcRelImm);
        
        Assert.Equal("0x00000000 LDR S1, 0x20", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x5C000101, Arm64Mnemonic.LDR); //LDR, 64-bit SIMD variant
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.ImmediatePcRelative, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.D1, insn.Op0Reg);
        Assert.Equal(0x20u, insn.Op1PcRelImm);
        
        Assert.Equal("0x00000000 LDR D1, 0x20", insn.ToString());
        
        insn = DisassembleAndCheckMnemonic(0x9C000101, Arm64Mnemonic.LDR); //LDR, 128-bit SIMD variant
        
        Assert.Equal(Arm64OperandKind.Register, insn.Op0Kind);
        Assert.Equal(Arm64OperandKind.ImmediatePcRelative, insn.Op1Kind);
        
        Assert.Equal(Arm64Register.V1, insn.Op0Reg);
        Assert.Equal(0x20u, insn.Op1PcRelImm);
        
        Assert.Equal("0x00000000 LDR V1, 0x20", insn.ToString());
    }

    [Fact]
    public void TestLoadStoredOrdered()
    {
        var insn = DisassembleAndCheckMnemonic(0xC8DFFE88,  Arm64Mnemonic.LDAR);
        Assert.Equal("0x00000000 LDAR X8, [X20]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x08DFFC41, Arm64Mnemonic.LDARB);
        Assert.Equal("0x00000000 LDARB W1, [X2]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x089FFC83, Arm64Mnemonic.STLRB);
        Assert.Equal("0x00000000 STLRB W3, [X4]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x48DFFCC5, Arm64Mnemonic.LDARH);
        Assert.Equal("0x00000000 LDARH W5, [X6]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x489FFD07, Arm64Mnemonic.STLRH);
        Assert.Equal("0x00000000 STLRH W7, [X8]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x88DFFD49, Arm64Mnemonic.LDAR);
        Assert.Equal("0x00000000 LDAR W9, [X10]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x889FFD8B, Arm64Mnemonic.STLR);
        Assert.Equal("0x00000000 STLR W11, [X12]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xC89FFE0F, Arm64Mnemonic.STLR);
        Assert.Equal("0x00000000 STLR X15, [X16]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xC8DF7E51, Arm64Mnemonic.LDLAR);
        Assert.Equal("0x00000000 LDLAR X17, [X18]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x889F7E93, Arm64Mnemonic.STLLR);
        Assert.Equal("0x00000000 STLLR W19, [X20]", insn.ToString());
    }

    [Fact]
    public void TestLoadRegExtended()
    {
        var insn = DisassembleAndCheckMnemonic(0xF8685928, Arm64Mnemonic.LDR);

        Assert.Equal("0x00000000 LDR X8, [X9, W8, UXTW #3]", insn.ToString());
    }

    [Fact]
    public void TestVector128RegOffset()
    {
        //STR Q1, [X2, X3, LSL #4]
        var insn = DisassembleAndCheckMnemonic(0x3CA37841, Arm64Mnemonic.STR);

        Assert.Equal(Arm64Register.V1, insn.Op0Reg);
        Assert.Equal(Arm64Register.X2, insn.MemBase);
        Assert.Equal(Arm64Register.X3, insn.MemAddendReg);
        Assert.Equal(Arm64ShiftType.LSL, insn.MemShiftType);
        Assert.Equal(4, insn.MemExtendOrShiftAmount);

        Assert.Equal("0x00000000 STR V1, [X2, X3, LSL #4]", insn.ToString());

        //LDR Q30, [X5, W6, UXTW #4]
        insn = DisassembleAndCheckMnemonic(0x3CE658BE, Arm64Mnemonic.LDR);

        Assert.Equal(Arm64Register.V30, insn.Op0Reg);
        Assert.Equal(Arm64ExtendType.UXTW, insn.MemExtendType);
        Assert.Equal(4, insn.MemExtendOrShiftAmount);

        Assert.Equal("0x00000000 LDR V30, [X5, W6, UXTW #4]", insn.ToString());
    }

    [Fact]
    public void TestVectorRegOffset()
    {
        var insn = DisassembleAndCheckMnemonic(0x3C256883, Arm64Mnemonic.STR);
        Assert.Equal("0x00000000 STR B3, [X4, X5]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x7C25D883, Arm64Mnemonic.STR);
        Assert.Equal("0x00000000 STR H3, [X4, W5, SXTW #1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xBC627829, Arm64Mnemonic.LDR);
        Assert.Equal("0x00000000 LDR S9, [X1, X2, LSL #2]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xFC645867, Arm64Mnemonic.LDR);
        Assert.Equal("0x00000000 LDR D7, [X3, W4, UXTW #3]", insn.ToString());
    }

    [Fact]
    public void TestGpRegOffset()
    {
        var insn = DisassembleAndCheckMnemonic(0xF82CD96A, Arm64Mnemonic.STR);
        Assert.Equal("0x00000000 STR X10, [X11, W12, SXTW #3]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB863C841, Arm64Mnemonic.LDR);
        Assert.Equal("0x00000000 LDR W1, [X2, W3, SXTW]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x38296907, Arm64Mnemonic.STRB);
        Assert.Equal("0x00000000 STRB W7, [X8, X9]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x38294907, Arm64Mnemonic.STRB);
        Assert.Equal("0x00000000 STRB W7, [X8, W9, UXTW]", insn.ToString());

        //LSL #0 with the S flag set is encoded distinctly from a plain register offset
        insn = DisassembleAndCheckMnemonic(0x38697907, Arm64Mnemonic.LDRB);
        Assert.Equal("0x00000000 LDRB W7, [X8, X9, LSL #0]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x782778C5, Arm64Mnemonic.STRH);
        Assert.Equal("0x00000000 STRH W5, [X6, X7, LSL #1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x7867D8C5, Arm64Mnemonic.LDRH);
        Assert.Equal("0x00000000 LDRH W5, [X6, W7, SXTW #1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xF876FAB4, Arm64Mnemonic.LDR);
        Assert.Equal("0x00000000 LDR X20, [X21, X22, SXTX #3]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xF876EAB4, Arm64Mnemonic.LDR);
        Assert.Equal("0x00000000 LDR X20, [X21, X22, SXTX]", insn.ToString());
    }

    [Fact]
    public void TestSignedLoadRegOffset()
    {
        var insn = DisassembleAndCheckMnemonic(0x38A36841, Arm64Mnemonic.LDRSB);
        Assert.Equal("0x00000000 LDRSB X1, [X2, X3]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x38E34841, Arm64Mnemonic.LDRSB);
        Assert.Equal("0x00000000 LDRSB W1, [X2, W3, UXTW]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x78AB7949, Arm64Mnemonic.LDRSH);
        Assert.Equal("0x00000000 LDRSH X9, [X10, X11, LSL #1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x78EBD949, Arm64Mnemonic.LDRSH);
        Assert.Equal("0x00000000 LDRSH W9, [X10, W11, SXTW #1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB8A57883, Arm64Mnemonic.LDRSW);
        Assert.Equal("0x00000000 LDRSW X3, [X4, X5, LSL #2]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB8A55883, Arm64Mnemonic.LDRSW);
        Assert.Equal("0x00000000 LDRSW X3, [X4, W5, UXTW #2]", insn.ToString());
    }

    [Fact]
    public void TestSignedLoadFromImm()
    {
        var insn = DisassembleAndCheckMnemonic(0x39801441, Arm64Mnemonic.LDRSB);
        Assert.Equal("0x00000000 LDRSB X1, [X2 + 0x5]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x39C01441, Arm64Mnemonic.LDRSB);
        Assert.Equal("0x00000000 LDRSB W1, [X2 + 0x5]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x79800C83, Arm64Mnemonic.LDRSH);
        Assert.Equal("0x00000000 LDRSH X3, [X4 + 0x6]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x79C00C83, Arm64Mnemonic.LDRSH);
        Assert.Equal("0x00000000 LDRSH W3, [X4 + 0x6]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB9804107, Arm64Mnemonic.LDRSW);
        Assert.Equal("0x00000000 LDRSW X7, [X8 + 0x40]", insn.ToString());

        //LDRSB X5, [X6], #-16 (post-index)
        insn = DisassembleAndCheckMnemonic(0x389F04C5, Arm64Mnemonic.LDRSB);
        Assert.Equal("0x00000000 LDRSB X5, [X6], #-0x10", insn.ToString());

        //LDRSB W5, [X6, #-16]! (pre-index)
        insn = DisassembleAndCheckMnemonic(0x38DF0CC5, Arm64Mnemonic.LDRSB);
        Assert.Equal("0x00000000 LDRSB W5, [X6 - 0x10]!", insn.ToString());
    }

    [Fact]
    public void TestUnscaledLoadsStores()
    {
        var insn = DisassembleAndCheckMnemonic(0x3C1FD041, Arm64Mnemonic.STUR);
        Assert.Equal("0x00000000 STUR B1, [X2 - 0x3]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x7C4070A4, Arm64Mnemonic.LDUR);
        Assert.Equal("0x00000000 LDUR H4, [X5 + 0x7]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xBC1F70E6, Arm64Mnemonic.STUR);
        Assert.Equal("0x00000000 STUR S6, [X7 - 0x9]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xFC40B128, Arm64Mnemonic.LDUR);
        Assert.Equal("0x00000000 LDUR D8, [X9 + 0xB]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x3C9F316A, Arm64Mnemonic.STUR);
        Assert.Equal("0x00000000 STUR V10, [X11 - 0xD]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x3CC0F1AC, Arm64Mnemonic.LDUR);
        Assert.Equal("0x00000000 LDUR V12, [X13 + 0xF]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB81EF1EE, Arm64Mnemonic.STUR);
        Assert.Equal("0x00000000 STUR W14, [X15 - 0x11]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xF8413230, Arm64Mnemonic.LDUR);
        Assert.Equal("0x00000000 LDUR X16, [X17 + 0x13]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x381EB272, Arm64Mnemonic.STURB);
        Assert.Equal("0x00000000 STURB W18, [X19 - 0x15]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x784172B4, Arm64Mnemonic.LDURH);
        Assert.Equal("0x00000000 LDURH W20, [X21 + 0x17]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x389E72F6, Arm64Mnemonic.LDURSB);
        Assert.Equal("0x00000000 LDURSB X22, [X23 - 0x19]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x38DE72F6, Arm64Mnemonic.LDURSB);
        Assert.Equal("0x00000000 LDURSB W22, [X23 - 0x19]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x7881B338, Arm64Mnemonic.LDURSH);
        Assert.Equal("0x00000000 LDURSH X24, [X25 + 0x1B]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x78C1B338, Arm64Mnemonic.LDURSH);
        Assert.Equal("0x00000000 LDURSH W24, [X25 + 0x1B]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB89E337A, Arm64Mnemonic.LDURSW);
        Assert.Equal("0x00000000 LDURSW X26, [X27 - 0x1D]", insn.ToString());
    }

    [Fact]
    public void TestLoadStorePairs()
    {
        var insn = DisassembleAndCheckMnemonic(0x29010861, Arm64Mnemonic.STP);
        Assert.Equal("0x00000000 STP W1, W2, [X3 + 0x8]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xA97F14C4, Arm64Mnemonic.LDP);
        Assert.Equal("0x00000000 LDP X4, X5, [X6 - 0x10]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x2D01A127, Arm64Mnemonic.STP);
        Assert.Equal("0x00000000 STP S7, S8, [X9 + 0xC]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x6D7EAD8A, Arm64Mnemonic.LDP);
        Assert.Equal("0x00000000 LDP D10, D11, [X12 - 0x18]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xAD0139ED, Arm64Mnemonic.STP);
        Assert.Equal("0x00000000 STP V13, V14, [X15 + 0x20]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x697FC650, Arm64Mnemonic.LDPSW);
        Assert.Equal("0x00000000 LDPSW X16, X17, [X18 - 0x4]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xA9C152B3, Arm64Mnemonic.LDP);
        Assert.Equal("0x00000000 LDP X19, X20, [X21 + 0x10]!", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xA8BE5F16, Arm64Mnemonic.STP);
        Assert.Equal("0x00000000 STP X22, X23, [X24], #-0x20", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x69008861, Arm64Mnemonic.STGP);
        Assert.Equal("0x00000000 STGP X1, X2, [X3 + 0x10]", insn.ToString());
    }

    [Fact]
    public void TestLoadStoreNoAllocatePairs()
    {
        var insn = DisassembleAndCheckMnemonic(0x28010861, Arm64Mnemonic.STNP);
        Assert.Equal("0x00000000 STNP W1, W2, [X3 + 0x8]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xA87F14C4, Arm64Mnemonic.LDNP);
        Assert.Equal("0x00000000 LDNP X4, X5, [X6 - 0x10]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x2C01A127, Arm64Mnemonic.STNP);
        Assert.Equal("0x00000000 STNP S7, S8, [X9 + 0xC]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x6C7EAD8A, Arm64Mnemonic.LDNP);
        Assert.Equal("0x00000000 LDNP D10, D11, [X12 - 0x18]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xAC4139ED, Arm64Mnemonic.LDNP);
        Assert.Equal("0x00000000 LDNP V13, V14, [X15 + 0x20]", insn.ToString());
    }

    [Fact]
    public void TestLoadStoreExclusive()
    {
        var insn = DisassembleAndCheckMnemonic(0xC85F7C20, Arm64Mnemonic.LDXR);
        Assert.Equal("0x00000000 LDXR X0, [X1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x085F7C62, Arm64Mnemonic.LDXRB);
        Assert.Equal("0x00000000 LDXRB W2, [X3]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x485F7CA4, Arm64Mnemonic.LDXRH);
        Assert.Equal("0x00000000 LDXRH W4, [X5]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x885FFCE6, Arm64Mnemonic.LDAXR);
        Assert.Equal("0x00000000 LDAXR W6, [X7]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xC8087D49, Arm64Mnemonic.STXR);
        Assert.Equal("0x00000000 STXR W8, X9, [X10]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x080B7DAC, Arm64Mnemonic.STXRB);
        Assert.Equal("0x00000000 STXRB W11, W12, [X13]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x880EFE0F, Arm64Mnemonic.STLXR);
        Assert.Equal("0x00000000 STLXR W14, W15, [X16]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4811FE72, Arm64Mnemonic.STLXRH);
        Assert.Equal("0x00000000 STLXRH W17, W18, [X19]", insn.ToString());
    }

    [Fact]
    public void TestLoadStoreMultipleStructures()
    {
        var insn = DisassembleAndCheckMnemonic(0x4CDF7000, Arm64Mnemonic.LD1);
        Assert.Equal("0x00000000 LD1 V0.16B, [X0], #0x10", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x0C407041, Arm64Mnemonic.LD1);
        Assert.Equal("0x00000000 LD1 V1.8B, [X2]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4C86A8A3, Arm64Mnemonic.ST1);
        Assert.Equal("0x00000000 ST1 V3.4S, V4.4S, [X5], X6", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4C408527, Arm64Mnemonic.LD2);
        Assert.Equal("0x00000000 LD2 V7.8H, V8.8H, [X9]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x0CDF4881, Arm64Mnemonic.LD3);
        Assert.Equal("0x00000000 LD3 V1.2S, V2.2S, V3.2S, [X4], #0x18", insn.ToString());

        //register lists wrap around v31
        insn = DisassembleAndCheckMnemonic(0x4C00803F, Arm64Mnemonic.ST2);
        Assert.Equal("0x00000000 ST2 V31.16B, V0.16B, [X1]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x0C407CC5, Arm64Mnemonic.LD1);
        Assert.Equal("0x00000000 LD1 V5.1D, [X6]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4C400800, Arm64Mnemonic.LD4);
        Assert.Equal("0x00000000 LD4 V0.4S, V1.4S, V2.4S, V3.4S, [X0]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4C9F0024, Arm64Mnemonic.ST4);
        Assert.Equal("0x00000000 ST4 V4.16B, V5.16B, V6.16B, V7.16B, [X1], #0x40", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4CC30448, Arm64Mnemonic.LD4);
        Assert.Equal("0x00000000 LD4 V8.8H, V9.8H, V10.8H, V11.8H, [X2], X3", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x4C402C8C, Arm64Mnemonic.LD1);
        Assert.Equal("0x00000000 LD1 V12.2D, V13.2D, V14.2D, V15.2D, [X4]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x0C9F20BE, Arm64Mnemonic.ST1);
        Assert.Equal("0x00000000 ST1 V30.8B, V31.8B, V0.8B, V1.8B, [X5], #0x20", insn.ToString());
    }

    [Fact]
    public void TestVector128FromImmUnsigned()
    {
        //the imm12 for q registers scales by 16
        var insn = DisassembleAndCheckMnemonic(0x3D800BE0, Arm64Mnemonic.STR);
        Assert.Equal("0x00000000 STR V0, [X31 + 0x20]", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x3DC05441, Arm64Mnemonic.LDR);
        Assert.Equal("0x00000000 LDR V1, [X2 + 0x150]", insn.ToString());
    }

    [Fact]
    public void TestRegOffsetUndefinedOption()
    {
        //option<1> == 0 is unallocated for register offset loads/stores
        Assert.Throws<Arm64UndefinedInstructionException>(() => Disassembler.DisassembleSingleInstruction(0xB8638841));
    }
}
