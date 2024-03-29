﻿namespace Disarm.InternalDisassembly;

internal static class Arm64Aliases
{
    public static void CheckForAlias(ref Arm64Instruction instruction)
    {
        if (instruction.Mnemonic == Arm64Mnemonic.ORR && instruction.Op2Imm == 0 && instruction.Op1Reg is Arm64Register.X31 or Arm64Register.W31)
        {
            //Change ORR R1, X31, R2, 0 to MOV R1, R2
            instruction.Mnemonic = Arm64Mnemonic.MOV;
            
            //Clear immediate
            instruction.Op3Imm = 0;
            instruction.Op3Kind = Arm64OperandKind.None;
            
            //Copy op2 to op1
            instruction.Op1Reg = instruction.Op2Reg;
            instruction.Op2Reg = Arm64Register.INVALID;
            
            //Clear op2
            instruction.Op2Kind = Arm64OperandKind.None;
            
            instruction.MnemonicCategory = Arm64MnemonicCategory.Move;
            
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.ORR && instruction.Op1Kind == Arm64OperandKind.Register && instruction.Op2Kind == Arm64OperandKind.Register && instruction.Op1Reg == instruction.Op2Reg)
        {
            //Change ORR R0, R1, R1 => MOV R0, R1
            instruction.Mnemonic = Arm64Mnemonic.MOV;
            
            //Clear op2
            instruction.Op2Kind = Arm64OperandKind.None;
            instruction.Op2Reg = Arm64Register.INVALID;
            
            instruction.MnemonicCategory = Arm64MnemonicCategory.Move;
            
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.SUBS && instruction.Op0Kind == Arm64OperandKind.Register && instruction.Op0Reg is Arm64Register.W31 or Arm64Register.X31 && instruction.Op1Kind == Arm64OperandKind.Register && instruction.Op2Kind is Arm64OperandKind.Immediate or Arm64OperandKind.Register)
        {
            //SUBS W31, WXX, [IMM|RXX] => CMP WXX, [IMM|RXX]
            
            //Convert mnemonic
            instruction.Mnemonic = Arm64Mnemonic.CMP;
            
            //Shift operands down
            instruction.Op0Reg = instruction.Op1Reg;
            instruction.Op1Kind = instruction.Op2Kind;
            instruction.Op2Kind = Arm64OperandKind.None;
            instruction.Op1Imm = instruction.Op2Imm;
            instruction.Op1Reg = instruction.Op2Reg;
            
            //Null op2
            instruction.Op2Imm = 0;
            
            instruction.MnemonicCategory = Arm64MnemonicCategory.Comparison;
            
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.MADD && instruction.Op3Reg is Arm64Register.X31 or Arm64Register.W31)
        {
            //MADD Rd, Rn, Rm, ZR => MUL Rd, Rn, Rm
            //because MADD is (Rd = Rn * Rm + Ra) so when Ra = ZR => Rd = Rn * Rm
            
            //Simply clear the last operand
            instruction.Mnemonic = Arm64Mnemonic.MUL;
            instruction.Op3Kind = Arm64OperandKind.None;
            instruction.Op3Reg = Arm64Register.INVALID;
            
            //Category doesn't change (math => math)

            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.CSINC && instruction.FinalOpConditionCode is not Arm64ConditionCode.AL and not Arm64ConditionCode.NV && instruction.Op2Kind == Arm64OperandKind.Register && instruction.Op1Kind == Arm64OperandKind.Register)
        {
            if(instruction.Op2Reg.IsSp() && instruction.Op1Reg.IsSp())
            {
                //CSINC Rd, SP, SP, COND => CSET Rd, !COND
                instruction.FinalOpConditionCode = instruction.FinalOpConditionCode.Invert();
                instruction.Op1Kind = Arm64OperandKind.None;
                instruction.Op1Reg = Arm64Register.INVALID;
                instruction.Op2Kind = Arm64OperandKind.None;
                instruction.Op2Reg = Arm64Register.INVALID;
                instruction.Mnemonic = Arm64Mnemonic.CSET;
                return;
            }
            else if(!instruction.Op2Reg.IsSp() && !instruction.Op1Reg.IsSp() && instruction.Op1Reg == instruction.Op2Reg)
            {
                //CSINC Rd, Rn, Rn, COND => CINC Rd, Rn, !COND
                instruction.FinalOpConditionCode = instruction.FinalOpConditionCode.Invert();
                instruction.Op2Kind = Arm64OperandKind.None;
                instruction.Op2Reg = Arm64Register.INVALID;
                instruction.Mnemonic = Arm64Mnemonic.CINC;
                return;
            }
            
        }

        if (instruction.Mnemonic == Arm64Mnemonic.SBFM && instruction.Op2Kind == Arm64OperandKind.Immediate && instruction.Op3Kind == Arm64OperandKind.Immediate && instruction.Op2Imm == 0)
        {
            //Check imm3
            var imm3 = instruction.Op3Imm;
            
            if(imm3 is > 0b11111 or < 0b111)
                return;

            var newMnemonic = imm3 switch
            {
                0b111 => Arm64Mnemonic.SXTB,
                0b1111 => Arm64Mnemonic.SXTH,
                0b11111 => Arm64Mnemonic.SXTW,
                _ => throw new("Impossible imm3")
            };
            
            //SBFM Rd, Rn, 0, imm3 => SXT{B|H|W} Rd, Rn
            instruction.Mnemonic = newMnemonic;
            instruction.Op2Kind = Arm64OperandKind.None;
            instruction.Op2Reg = Arm64Register.INVALID;
            instruction.Op3Kind = Arm64OperandKind.None;
            instruction.Op3Reg = Arm64Register.INVALID;
            
            //Second reg has to be remapped to a W reg not an X one, if the first reg is an X one
            if (instruction.Op0Reg is >= Arm64Register.X0 and <= Arm64Register.X31)
                instruction.Op1Reg = Arm64Register.W0 + (instruction.Op1Reg - Arm64Register.X0);
            
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.INS && instruction.Op0Kind == Arm64OperandKind.VectorRegisterElement && instruction.Op1Kind == Arm64OperandKind.VectorRegisterElement)
        {
            //INS Vd.Ts[i1], Vn.Ts[i2] => MOV Vd.Ts[i1], Vn.Ts[i2]
            //i.e. just change INS to MOV
            instruction.Mnemonic = Arm64Mnemonic.MOV;
            
            //Category remains SimdRegisterToRegister
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.DUP && instruction.Op0Kind == Arm64OperandKind.Register && instruction.Op1Kind == Arm64OperandKind.VectorRegisterElement)
        {
            //DUP Rd, Vn.Ts[i] => MOV Rd, Vn.Ts[i]
            //i.e. just change DUP to MOV
            instruction.Mnemonic = Arm64Mnemonic.MOV;
            return;
        }
    }
}
