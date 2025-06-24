using System.Globalization;
using System.Text;
using Disarm.InternalDisassembly;

namespace Disarm;

public struct Arm64Instruction
{
    public Arm64Instruction()
    {
        //Default initializer
        Address = 0;
        Mnemonic = Arm64Mnemonic.INVALID;
        MnemonicCategory = Arm64MnemonicCategory.Unspecified;
        Op0Kind = Arm64OperandKind.None;
        Op1Kind = Arm64OperandKind.None;
        Op2Kind = Arm64OperandKind.None;
        Op3Kind = Arm64OperandKind.None;
        Op4Kind = Arm64OperandKind.None;
        Op0Reg = Arm64Register.INVALID;
        Op1Reg = Arm64Register.INVALID;
        Op2Reg = Arm64Register.INVALID;
        Op3Reg = Arm64Register.INVALID;
        Op4Reg = Arm64Register.INVALID;
        Op0Imm = 0;
        Op1Imm = 0;
        Op2Imm = 0;
        Op3Imm = 0;
        Op4Imm = 0;
        Op0FpImm = double.NaN;
        Op1FpImm = double.NaN;
        Op2FpImm = double.NaN;
        Op3FpImm = double.NaN;
        Op4FpImm = double.NaN;
        Op0Arrangement = Arm64ArrangementSpecifier.None;
        Op1Arrangement = Arm64ArrangementSpecifier.None;
        Op2Arrangement = Arm64ArrangementSpecifier.None;
        Op3Arrangement = Arm64ArrangementSpecifier.None;
        Op4Arrangement = Arm64ArrangementSpecifier.None;
        MemBase = Arm64Register.INVALID;
        MemAddendReg = Arm64Register.INVALID;
        MemIndexMode = Arm64MemoryIndexMode.Offset;
        MemOffset = 0;
        MemExtendOrShiftAmount = 0;
        Op0VectorElement = default;
        Op1VectorElement = default;
        Op2VectorElement = default;
        Op3VectorElement = default;
        Op4VectorElement = default;
        
        //These lines are the ONLY reason this constructor needs to exist because they define 0 as a valid value.
        MnemonicConditionCode = Arm64ConditionCode.NONE;
        FinalOpConditionCode = Arm64ConditionCode.NONE;
        FinalOpExtendType = Arm64ExtendType.NONE;
        FinalOpShiftType = Arm64ShiftType.NONE;
        MemExtendType = Arm64ExtendType.NONE;
        MemShiftType = Arm64ShiftType.NONE;
        Op0ShiftType = Arm64ShiftType.NONE;
        Op1ShiftType = Arm64ShiftType.NONE;
        Op2ShiftType = Arm64ShiftType.NONE;
        Op3ShiftType = Arm64ShiftType.NONE;
        Op4ShiftType = Arm64ShiftType.NONE;
    }

    public ulong Address { get; internal set; }
    public Arm64Mnemonic Mnemonic { get; internal set; }
    public Arm64MnemonicCategory MnemonicCategory { get; internal set; }
    public Arm64ConditionCode MnemonicConditionCode { get; internal set; }

    public Arm64OperandKind Op0Kind { get; internal set; }
    public Arm64OperandKind Op1Kind { get; internal set; }
    public Arm64OperandKind Op2Kind { get; internal set; }
    public Arm64OperandKind Op3Kind { get; internal set; }
    public Arm64OperandKind Op4Kind { get; internal set; }

    public Arm64Register Op0Reg { get; internal set; }
    public Arm64Register Op1Reg { get; internal set; }
    public Arm64Register Op2Reg { get; internal set; }
    public Arm64Register Op3Reg { get; internal set; }
    public Arm64Register Op4Reg { get; internal set; }
    public Arm64VectorElement Op0VectorElement { get; internal set; }
    public Arm64VectorElement Op1VectorElement { get; internal set; }
    public Arm64VectorElement Op2VectorElement { get; internal set; }
    public Arm64VectorElement Op3VectorElement { get; internal set; }
    public Arm64VectorElement Op4VectorElement { get; internal set; }
    public long Op0Imm { get; internal set; }
    public long Op1Imm { get; internal set; }
    public long Op2Imm { get; internal set; }
    public long Op3Imm { get; internal set; }
    public long Op4Imm { get; internal set; }
    public double Op0FpImm { get; internal set; }
    public double Op1FpImm { get; internal set; }
    public double Op2FpImm { get; internal set; }
    public double Op3FpImm { get; internal set; }
    public double Op4FpImm { get; internal set; }
    public Arm64ArrangementSpecifier Op0Arrangement { get; internal set; }
    public Arm64ArrangementSpecifier Op1Arrangement { get; internal set; }
    public Arm64ArrangementSpecifier Op2Arrangement { get; internal set; }
    public Arm64ArrangementSpecifier Op3Arrangement { get; internal set; }
    public Arm64ArrangementSpecifier Op4Arrangement { get; internal set; }
    public Arm64ShiftType Op0ShiftType { get; internal set; }
    public Arm64ShiftType Op1ShiftType { get; internal set; }
    public Arm64ShiftType Op2ShiftType { get; internal set; }
    public Arm64ShiftType Op3ShiftType { get; internal set; }
    public Arm64ShiftType Op4ShiftType { get; internal set; }

    public Arm64Register MemBase { get; internal set; }
    public Arm64Register MemAddendReg { get; internal set; }
    public Arm64MemoryIndexMode MemIndexMode { get; internal set; }
    public bool MemIsPreIndexed => MemIndexMode == Arm64MemoryIndexMode.PreIndex;
    public long MemOffset { get; internal set; }
    public Arm64ExtendType MemExtendType { get; internal set; }
    public Arm64ShiftType MemShiftType { get; internal set; }
    public int MemExtendOrShiftAmount { get; internal set; }
    
    public Arm64ExtendType FinalOpExtendType { get; internal set; }
    public Arm64ShiftType FinalOpShiftType { get; internal set; }
    public Arm64ConditionCode FinalOpConditionCode { get; internal set; }
    
    public ulong BranchTarget => Mnemonic is Arm64Mnemonic.B or Arm64Mnemonic.BL 
        ? Op0PcRelImm
        : throw new("Branch target not available for this instruction, must be a B or BL");
    
    public ulong Op0PcRelImm => Op0Kind == Arm64OperandKind.ImmediatePcRelative
        ? (ulong) ((long) Address + Op0Imm) //Casting is a bit weird here because we want to return an unsigned long (can't jump to negative), but the immediate needs to be signed.
        : throw new("Operand 0 is not a PC-relative immediate");
    
    public ulong Op1PcRelImm => Op1Kind == Arm64OperandKind.ImmediatePcRelative
        ? (ulong) ((long) Address + Op1Imm)
        : throw new("Operand 1 is not a PC-relative immediate");

    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append("0x");
        sb.Append(Address.ToString("X8"));
        sb.Append(' ');
        sb.Append(Mnemonic);

        if (MnemonicConditionCode != Arm64ConditionCode.NONE)
            sb.Append('.').Append(MnemonicConditionCode);
        
        if(Op0Kind == Arm64OperandKind.None)
            goto doneops;
        
        sb.Append(' ');

        //Ew yes I'm using goto.
        if (!AppendOperand(sb, Op0Kind, Op0Reg, Op0VectorElement, Op0Arrangement, Op0ShiftType, Op0Imm, Op0FpImm, false, MemExtendOrShiftAmount))
            goto doneops;
        if (!AppendOperand(sb, Op1Kind, Op1Reg, Op1VectorElement, Op1Arrangement, Op1ShiftType, Op1Imm, Op1FpImm, true, MemExtendOrShiftAmount))
            goto doneops;
        if (!AppendOperand(sb, Op2Kind, Op2Reg, Op2VectorElement, Op2Arrangement, Op2ShiftType, Op2Imm, Op2FpImm, true, MemExtendOrShiftAmount))
            goto doneops;
        if (!AppendOperand(sb, Op3Kind, Op3Reg, Op3VectorElement, Op3Arrangement, Op3ShiftType, Op3Imm, Op3FpImm, true, MemExtendOrShiftAmount))
            goto doneops;
        
        doneops:
        if (FinalOpExtendType != Arm64ExtendType.NONE)
            sb.Append(", ").Append(FinalOpExtendType);
        else if (FinalOpShiftType != Arm64ShiftType.NONE)
            sb.Append(", ").Append(FinalOpShiftType);
        else if (FinalOpConditionCode != Arm64ConditionCode.NONE)
            sb.Append(", ").Append(FinalOpConditionCode);

        return sb.ToString();
    }

    private bool AppendOperand(StringBuilder sb, Arm64OperandKind kind, Arm64Register reg, Arm64VectorElement vectorElement, Arm64ArrangementSpecifier regArrangement, Arm64ShiftType shiftType, long imm, double fpImm, bool comma = false, int shiftAmount = 0)
    {
        if (kind == Arm64OperandKind.None)
            return false;

        if (comma)
            sb.Append(", ");

        if (kind == Arm64OperandKind.Register)
        {
            sb.Append(reg);

            if (regArrangement != Arm64ArrangementSpecifier.None)
                sb.Append('.').Append(regArrangement.ToDisassemblyString());
        } else if (kind == Arm64OperandKind.VectorRegisterElement)
        {
            sb.Append(reg)
                .Append('.')
                .Append(vectorElement);
        }
        else if (kind == Arm64OperandKind.Immediate)
        {
            sb.Append("#0x").Append(imm.ToString("X"));
            if (shiftType != Arm64ShiftType.NONE)
                sb.Append(",").Append(shiftType).Append("#").Append(shiftAmount);
        } else if (kind == Arm64OperandKind.FloatingPointImmediate)
        {
            sb.Append("#");
            sb.Append(fpImm.ToString(CultureInfo.InvariantCulture));
            
        }
        else if(kind == Arm64OperandKind.ImmediatePcRelative)
            sb.Append("0x").Append(((long) Address + imm).ToString("X"));
        else if (kind == Arm64OperandKind.Memory) 
            AppendMemory(sb);

        return true;
    }

    private void AppendMemory(StringBuilder sb)
    {
        sb.Append('[').Append(MemBase.ToString());
        
        if(MemAddendReg != Arm64Register.INVALID)
            sb.Append(", ").Append(MemAddendReg.ToString());

        if (MemOffset != 0 && MemIndexMode != Arm64MemoryIndexMode.PostIndex)
        {
            sb.Append(' ')
                .Append(MemOffset < 0 ? '-' : '+')
                .Append(" 0x")
                .Append(Math.Abs(MemOffset).ToString("X"));
        }
        
        if(MemExtendType != Arm64ExtendType.NONE)
            sb.Append(", ").Append(MemExtendType.ToString());
        else if(MemShiftType != Arm64ShiftType.NONE)
            sb.Append(", ").Append(MemShiftType.ToString());
        
        if(MemExtendOrShiftAmount != 0)
            sb.Append(" #").Append(MemExtendOrShiftAmount);

        sb.Append(']');

        if (MemIndexMode == Arm64MemoryIndexMode.PreIndex)
            sb.Append('!');
        else if(MemIndexMode == Arm64MemoryIndexMode.PostIndex && MemOffset != 0)
            sb.Append(", #0x").Append(MemOffset.ToString("X"));
    }
}
