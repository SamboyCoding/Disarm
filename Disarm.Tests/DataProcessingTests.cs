using Disarm.InternalDisassembly;
using Xunit.Abstractions;

namespace Disarm.Tests;

public class DataProcessingTests : BaseDisarmTest
{
    public DataProcessingTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }
    
    [Fact]
    public void DisassemblingBitfieldsWorks()
    {
        var insn = DisassembleAndCheckMnemonic(0x93407E95, Arm64Mnemonic.SXTW);
        Assert.Equal(Arm64Register.X21, insn.Op0Reg);
        Assert.Equal(Arm64Register.W20, insn.Op1Reg);
    }
    
    [Fact]
    public void DataProcessing1Source()
    {
        //Mostly just mnemonic checks but with some register checks sprinkled in
        DisassembleAndCheckMnemonic(0x5AC00914, Arm64Mnemonic.REV);
        DisassembleAndCheckMnemonic(0xDAC00D14, Arm64Mnemonic.REV); //but 64-bit
        DisassembleAndCheckMnemonic(0xDAC00914, Arm64Mnemonic.REV32);
        DisassembleAndCheckMnemonic(0xDAC00514, Arm64Mnemonic.REV16);

        Assert.Equal(Arm64Register.X8, DisassembleAndCheckMnemonic(0xDAC01114, Arm64Mnemonic.CLZ).Op1Reg);
        DisassembleAndCheckMnemonic(0xDAC01514, Arm64Mnemonic.CLS);
        
        Assert.Equal(Arm64Register.W20, DisassembleAndCheckMnemonic(0x5AC00114, Arm64Mnemonic.RBIT).Op0Reg);
    }

    [Fact]
    public void DataProcessing2Source() 
        => DisassembleAndCheckMnemonic(0x1AC80D2AU, Arm64Mnemonic.SDIV);

    [Fact]
    public void ConditionalCompareImmediate()
    {
        var insn = DisassembleAndCheckMnemonic(0x7A49B102U, Arm64Mnemonic.CCMP);
        
        Assert.Equal(Arm64Register.W8, insn.Op0Reg);
        Assert.Equal(Arm64Register.W9, insn.Op1Reg);
        Assert.Equal(2, insn.Op2Imm);
        Assert.Equal(Arm64ConditionCode.LT, insn.FinalOpConditionCode);
    }

    [Fact]
    public void AddSubWithCarry()
    {
        //These are all one code path except for the mnemonic. So we validate the registers on one and then check only the mnemonic on the others.
        var ins = DisassembleAndCheckMnemonic(0x9A020020, Arm64Mnemonic.ADC);
        
        Assert.Equal(Arm64Register.X0, ins.Op0Reg);
        Assert.Equal(Arm64Register.X1, ins.Op1Reg);
        Assert.Equal(Arm64Register.X2, ins.Op2Reg);
        
        DisassembleAndCheckMnemonic(0xBA020020, Arm64Mnemonic.ADCS);
        DisassembleAndCheckMnemonic(0xDA020020, Arm64Mnemonic.SBC);
        DisassembleAndCheckMnemonic(0xFA020020, Arm64Mnemonic.SBCS);
        
        //And 32-bit
        DisassembleAndCheckMnemonic(0x1A020020, Arm64Mnemonic.ADC);
        DisassembleAndCheckMnemonic(0x3A020020, Arm64Mnemonic.ADCS);
        DisassembleAndCheckMnemonic(0x5A020020, Arm64Mnemonic.SBC);
        DisassembleAndCheckMnemonic(0x7A020020, Arm64Mnemonic.SBCS);
    }

    [Fact]
    public void DataProcessing3Source()
    {
        var insn = DisassembleAndCheckMnemonic(0x9BC27C20, Arm64Mnemonic.UMULH);
        Assert.Equal("0x00000000 UMULH X0, X1, X2", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9B457C83, Arm64Mnemonic.SMULH);
        Assert.Equal("0x00000000 SMULH X3, X4, X5", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9B2824E6, Arm64Mnemonic.SMADDL);
        Assert.Equal("0x00000000 SMADDL X6, W7, W8, X9", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9BACB56A, Arm64Mnemonic.UMSUBL);
        Assert.Equal("0x00000000 UMSUBL X10, W11, W12, X13", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x1B1045EE, Arm64Mnemonic.MADD);
        Assert.Equal("0x00000000 MADD W14, W15, W16, W17", insn.ToString());
    }

    [Fact]
    public void DataProcessingImmediateScaleIsRight()
    {
        var insn = DisassembleAndCheckMnemonic(0x927D0108, Arm64Mnemonic.AND);

        Assert.Equal("0x00000000 AND X8, X8, 0x8", insn.ToString());
    }

    [Fact]
    public void LogicalImmediates()
    {
        var insn = DisassembleAndCheckMnemonic(0x92407C20, Arm64Mnemonic.AND);
        Assert.Equal("0x00000000 AND X0, X1, 0xFFFFFFFF", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xB200CC62, Arm64Mnemonic.ORR);
        Assert.Equal("0x00000000 ORR X2, X3, 0xF0F0F0F0F0F0F0F", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x520100A4, Arm64Mnemonic.EOR);
        Assert.Equal("0x00000000 EOR W4, W5, 0x80000000", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xF24004E6, Arm64Mnemonic.ANDS);
        Assert.Equal("0x00000000 ANDS X6, X7, 0x3", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x927FF949, Arm64Mnemonic.AND);
        Assert.Equal("0x00000000 AND X9, X10, 0xFFFFFFFFFFFFFFFE", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x3200018B, Arm64Mnemonic.ORR);
        Assert.Equal("0x00000000 ORR W11, W12, 0x1", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9240F9CD, Arm64Mnemonic.AND);
        Assert.Equal("0x00000000 AND X13, X14, 0x7FFFFFFFFFFFFFFF", insn.ToString());
    }

    [Fact]
    public void BitfieldAliases()
    {
        var insn = DisassembleAndCheckMnemonic(0xD37CEC20, Arm64Mnemonic.LSL);
        Assert.Equal("0x00000000 LSL X0, X1, 0x4", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x53144C62, Arm64Mnemonic.LSL);
        Assert.Equal("0x00000000 LSL W2, W3, 0xC", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xD351FCA4, Arm64Mnemonic.LSR);
        Assert.Equal("0x00000000 LSR X4, X5, 0x11", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x53037CE6, Arm64Mnemonic.LSR);
        Assert.Equal("0x00000000 LSR W6, W7, 0x3", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xD37B1528, Arm64Mnemonic.UBFIZ);
        Assert.Equal("0x00000000 UBFIZ X8, X9, 0x5, 0x6", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x5307396A, Arm64Mnemonic.UBFX);
        Assert.Equal("0x00000000 UBFX W10, W11, 0x7, 0x8", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x53001DAC, Arm64Mnemonic.UXTB);
        Assert.Equal("0x00000000 UXTB W12, W13", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x53003DEE, Arm64Mnemonic.UXTH);
        Assert.Equal("0x00000000 UXTH W14, W15", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9349FE30, Arm64Mnemonic.ASR);
        Assert.Equal("0x00000000 ASR X16, X17, 0x9", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x13027E72, Arm64Mnemonic.ASR);
        Assert.Equal("0x00000000 ASR W18, W19, 0x2", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x937D0EB4, Arm64Mnemonic.SBFIZ);
        Assert.Equal("0x00000000 SBFIZ X20, X21, 0x3, 0x4", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x934022F6, Arm64Mnemonic.SBFX);
        Assert.Equal("0x00000000 SBFX X22, X23, 0x0, 0x9", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x93401F38, Arm64Mnemonic.SXTB);
        Assert.Equal("0x00000000 SXTB X24, W25", insn.ToString());

        //32-bit with imms 31 is asr, not sxtw (sxtw only exists for x destinations)
        insn = DisassembleAndCheckMnemonic(0x13007C20, Arm64Mnemonic.ASR);
        Assert.Equal("0x00000000 ASR W0, W1, 0x0", insn.ToString());
    }

    [Fact]
    public void LogicalShiftedRegisterPreservesShiftType()
    {
        var insn = DisassembleAndCheckMnemonic(0x8A823020, Arm64Mnemonic.AND);
        Assert.Equal(Arm64ShiftType.ASR, insn.Op3ShiftType);
        Assert.Equal(12, insn.Op3Imm);
        Assert.Equal("0x00000000 AND X0, X1, X2, ASR 0xC", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x0AA87D08, Arm64Mnemonic.BIC);
        Assert.Equal("0x00000000 BIC W8, W8, W8, ASR 0x1F", insn.ToString());

        //a shifted zr source is not a plain mov
        insn = DisassembleAndCheckMnemonic(0xAA060FE5, Arm64Mnemonic.ORR);
        Assert.Equal("0x00000000 ORR X5, X31, X6, LSL 0x3", insn.ToString());
    }

    [Fact]
    public void MoveWideAliases()
    {
        var insn = DisassembleAndCheckMnemonic(0xD28000A1, Arm64Mnemonic.MOV);
        Assert.Equal("0x00000000 MOV X1, 0x5", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0xD2A000A1, Arm64Mnemonic.MOV);
        Assert.Equal("0x00000000 MOV X1, 0x50000", insn.ToString());

        //movn resolves to the inverted value
        insn = DisassembleAndCheckMnemonic(0x928003F8, Arm64Mnemonic.MOV);
        Assert.Equal(Arm64Register.X24, insn.Op0Reg);
        Assert.Equal(-32, insn.Op1Imm);

        insn = DisassembleAndCheckMnemonic(0x12800000, Arm64Mnemonic.MOV);
        Assert.Equal(0xFFFFFFFFL, insn.Op1Imm);
        Assert.Equal("0x00000000 MOV W0, 0xFFFFFFFF", insn.ToString());

        //movk keeps its identity, with the immediate shifted into place
        insn = DisassembleAndCheckMnemonic(0xF2C24683, Arm64Mnemonic.MOVK);
        Assert.Equal(0x123400000000L, insn.Op1Imm);
    }

    [Fact]
    public void LogicalImmediateMovAlias()
    {
        //a bitmask immediate no movz/movn could encode displays as mov
        var insn = DisassembleAndCheckMnemonic(0xB2009FE2, Arm64Mnemonic.MOV);
        Assert.Equal("0x00000000 MOV X2, 0xFF00FF00FF00FF", insn.ToString());

        //but a movz-able immediate keeps the orr form
        insn = DisassembleAndCheckMnemonic(0x320003E0, Arm64Mnemonic.ORR);
        Assert.Equal("0x00000000 ORR W0, W31, 0x1", insn.ToString());
    }

    [Fact]
    public void VariableShiftAliases()
    {
        var insn = DisassembleAndCheckMnemonic(0x9AC22020, Arm64Mnemonic.LSL);
        Assert.Equal("0x00000000 LSL X0, X1, X2", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x1AC52483, Arm64Mnemonic.LSR);
        Assert.Equal("0x00000000 LSR W3, W4, W5", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9AC828E6, Arm64Mnemonic.ASR);
        Assert.Equal("0x00000000 ASR X6, X7, X8", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x1ACB2D49, Arm64Mnemonic.ROR);
        Assert.Equal("0x00000000 ROR W9, W10, W11", insn.ToString());
    }

    [Fact]
    public void CnegAlias()
    {
        var insn = DisassembleAndCheckMnemonic(0x5A811420, Arm64Mnemonic.CNEG);
        Assert.Equal("0x00000000 CNEG W0, W1, EQ", insn.ToString());
    }

    [Fact]
    public void MultiplyAliases()
    {
        var insn = DisassembleAndCheckMnemonic(0x9B287CE6, Arm64Mnemonic.SMULL);
        Assert.Equal("0x00000000 SMULL X6, W7, W8", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9BAB7D49, Arm64Mnemonic.UMULL);
        Assert.Equal("0x00000000 UMULL X9, W10, W11", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9B2EFDAC, Arm64Mnemonic.SMNEGL);
        Assert.Equal("0x00000000 SMNEGL X12, W13, W14", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x9BB1FE0F, Arm64Mnemonic.UMNEGL);
        Assert.Equal("0x00000000 UMNEGL X15, W16, W17", insn.ToString());
    }

    [Fact]
    public void BitfieldInsertAliases()
    {
        var insn = DisassembleAndCheckMnemonic(0xB3783C41, Arm64Mnemonic.BFI);
        Assert.Equal("0x00000000 BFI X1, X2, 0x8, 0x10", insn.ToString());

        insn = DisassembleAndCheckMnemonic(0x33043C83, Arm64Mnemonic.BFXIL);
        Assert.Equal("0x00000000 BFXIL W3, W4, 0x4, 0xC", insn.ToString());

        //rn == zr would be bfc, but llvm prints it as bfi with the zr visible so we do too
        insn = DisassembleAndCheckMnemonic(0xB3701FE5, Arm64Mnemonic.BFI);
        Assert.Equal("0x00000000 BFI X5, X31, 0x10, 0x8", insn.ToString());
    }

    [Fact]
    public void AdrIsPcRelative()
    {
        var insn = Disassembler.Disassemble(new byte[] { 0x8A, 0x00, 0x00, 0x10 }, 0x1C73FA0).Single();

        Assert.Equal(Arm64Mnemonic.ADR, insn.Mnemonic);
        Assert.Equal(Arm64Register.X10, insn.Op0Reg);
        Assert.Equal(Arm64OperandKind.ImmediatePcRelative, insn.Op1Kind);
        Assert.Equal(0x10, insn.Op1Imm);
        Assert.Equal(0x1C73FB0UL, insn.Op1PcRelImm);
        Assert.Equal("0x01C73FA0 ADR X10, 0x1C73FB0", insn.ToString());

        insn = Disassembler.Disassemble(new byte[] { 0xA0, 0xFE, 0xFF, 0x10 }, 0x1C67FA4).Single();

        Assert.Equal(Arm64Mnemonic.ADR, insn.Mnemonic);
        Assert.Equal(-0x2C, insn.Op1Imm);
        Assert.Equal(0x1C67F78UL, insn.Op1PcRelImm);
        Assert.Equal("0x01C67FA4 ADR X0, 0x1C67F78", insn.ToString());
    }
}
