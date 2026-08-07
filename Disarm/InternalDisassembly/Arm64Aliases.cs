namespace Disarm.InternalDisassembly;

internal static class Arm64Aliases
{
    public static void CheckForAlias(ref Arm64Instruction instruction)
    {
        if (instruction.Mnemonic == Arm64Mnemonic.ORR && instruction.Op2Kind == Arm64OperandKind.Register && instruction.Op3Imm == 0 && instruction.Op1Reg is Arm64Register.X31 or Arm64Register.W31)
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

        if (instruction.Mnemonic == Arm64Mnemonic.ORR && instruction.Op2Kind == Arm64OperandKind.Immediate && instruction.Op1Reg is Arm64Register.X31 or Arm64Register.W31)
        {
            var is64Bit = instruction.Op0Reg is >= Arm64Register.X0 and <= Arm64Register.X31;
            var value = (ulong)instruction.Op2Imm;
            if (!is64Bit)
                value &= uint.MaxValue;

            //ORR Rd, ZR, #imm => MOV Rd, #imm, but only for immediates a movz/movn couldn't encode (canonical form keeps orr otherwise)
            if (!IsMovWideEncodable(value, is64Bit))
            {
                instruction.Mnemonic = Arm64Mnemonic.MOV;

                instruction.Op1Kind = Arm64OperandKind.Immediate;
                instruction.Op1Reg = Arm64Register.INVALID;
                instruction.Op1Imm = unchecked((long)value);

                instruction.Op2Kind = Arm64OperandKind.None;
                instruction.Op2Imm = 0;

                instruction.MnemonicCategory = Arm64MnemonicCategory.Move;

                return;
            }
        }

        if (instruction.Mnemonic is Arm64Mnemonic.MOVZ or Arm64Mnemonic.MOVN && instruction.Op1Kind == Arm64OperandKind.Immediate)
        {
            //MOVZ/MOVN Rd, #imm16, LSL #s => MOV Rd, #resolved
            if (instruction.Mnemonic == Arm64Mnemonic.MOVN)
            {
                var mask = instruction.Op0Reg is >= Arm64Register.X0 and <= Arm64Register.X31 ? ulong.MaxValue : uint.MaxValue;
                instruction.Op1Imm = unchecked((long)(~(ulong)instruction.Op1Imm & mask));
            }

            instruction.Mnemonic = Arm64Mnemonic.MOV;

            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.ORR && instruction.Op1Kind == Arm64OperandKind.Register && instruction.Op2Kind == Arm64OperandKind.Register && instruction.Op1Reg == instruction.Op2Reg && instruction.Op3Imm == 0)
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

        if (instruction.Mnemonic is Arm64Mnemonic.MADD or Arm64Mnemonic.MSUB or Arm64Mnemonic.SMADDL or Arm64Mnemonic.UMADDL or Arm64Mnemonic.SMSUBL or Arm64Mnemonic.UMSUBL && instruction.Op3Reg is Arm64Register.X31 or Arm64Register.W31)
        {
            //multiply-accumulates with a zr accumulator are plain multiplies (or negated ones)
            instruction.Mnemonic = instruction.Mnemonic switch
            {
                Arm64Mnemonic.MADD => Arm64Mnemonic.MUL,
                Arm64Mnemonic.MSUB => Arm64Mnemonic.MNEG,
                Arm64Mnemonic.SMADDL => Arm64Mnemonic.SMULL,
                Arm64Mnemonic.UMADDL => Arm64Mnemonic.UMULL,
                Arm64Mnemonic.SMSUBL => Arm64Mnemonic.SMNEGL,
                _ => Arm64Mnemonic.UMNEGL,
            };
            instruction.Op3Kind = Arm64OperandKind.None;
            instruction.Op3Reg = Arm64Register.INVALID;

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

        if (instruction.Mnemonic == Arm64Mnemonic.CSNEG && instruction.FinalOpConditionCode is not Arm64ConditionCode.AL and not Arm64ConditionCode.NV
            && instruction.Op1Kind == Arm64OperandKind.Register && instruction.Op2Kind == Arm64OperandKind.Register
            && !instruction.Op1Reg.IsSp() && instruction.Op1Reg == instruction.Op2Reg)
        {
            //CSNEG Rd, Rn, Rn, COND => CNEG Rd, Rn, !COND
            instruction.FinalOpConditionCode = instruction.FinalOpConditionCode.Invert();
            instruction.Op2Kind = Arm64OperandKind.None;
            instruction.Op2Reg = Arm64Register.INVALID;
            instruction.Mnemonic = Arm64Mnemonic.CNEG;
            return;
        }

        if (instruction.Mnemonic is Arm64Mnemonic.LSLV or Arm64Mnemonic.LSRV or Arm64Mnemonic.ASRV or Arm64Mnemonic.RORV)
        {
            //the variable shifts are always displayed by their plain shift names
            instruction.Mnemonic = instruction.Mnemonic switch
            {
                Arm64Mnemonic.LSLV => Arm64Mnemonic.LSL,
                Arm64Mnemonic.LSRV => Arm64Mnemonic.LSR,
                Arm64Mnemonic.ASRV => Arm64Mnemonic.ASR,
                _ => Arm64Mnemonic.ROR,
            };
            return;
        }

        if (instruction.Mnemonic is Arm64Mnemonic.SBFM or Arm64Mnemonic.UBFM && instruction.Op2Kind == Arm64OperandKind.Immediate && instruction.Op3Kind == Arm64OperandKind.Immediate)
        {
            var isSigned = instruction.Mnemonic == Arm64Mnemonic.SBFM;
            var immr = instruction.Op2Imm;
            var imms = instruction.Op3Imm;
            var is64Bit = instruction.Op0Reg is >= Arm64Register.X0 and <= Arm64Register.X31;
            var regSize = is64Bit ? 64 : 32;

            //shift left, only exists for ubfm. encoded as immr = -shift MOD regsize, imms = regsize-1-shift
            if (!isSigned && imms != regSize - 1 && imms + 1 == immr)
            {
                //UBFM Rd, Rn, #(imms+1), #imms => LSL Rd, Rn, #(regsize-1-imms)
                instruction.Mnemonic = Arm64Mnemonic.LSL;
                instruction.Op2Imm = regSize - 1 - imms;
                instruction.Op3Kind = Arm64OperandKind.None;
                instruction.Op3Imm = 0;
                return;
            }

            if (imms == regSize - 1)
            {
                //[SU]BFM Rd, Rn, #immr, #(regsize-1) => LSR/ASR Rd, Rn, #immr
                instruction.Mnemonic = isSigned ? Arm64Mnemonic.ASR : Arm64Mnemonic.LSR;
                instruction.Op3Kind = Arm64OperandKind.None;
                instruction.Op3Imm = 0;
                return;
            }

            //the extends are only valid as sign extension for both widths, or zero extension of a w reg
            if (immr == 0 && (isSigned || !is64Bit) && (imms == 0b111 || imms == 0b1111 || (imms == 0b1_1111 && is64Bit)))
            {
                //[SU]BFM Rd, Rn, #0, #(7|15|31) => [SU]XT{B|H|W} Rd, Wn
                instruction.Mnemonic = imms switch
                {
                    0b111 => isSigned ? Arm64Mnemonic.SXTB : Arm64Mnemonic.UXTB,
                    0b1111 => isSigned ? Arm64Mnemonic.SXTH : Arm64Mnemonic.UXTH,
                    _ => Arm64Mnemonic.SXTW,
                };
                instruction.Op2Kind = Arm64OperandKind.None;
                instruction.Op2Imm = 0;
                instruction.Op3Kind = Arm64OperandKind.None;
                instruction.Op3Imm = 0;

                //Second reg has to be remapped to a W reg not an X one, if the first reg is an X one
                if (is64Bit)
                    instruction.Op1Reg = Arm64Register.W0 + (instruction.Op1Reg - Arm64Register.X0);

                return;
            }

            if (imms < immr)
            {
                //[SU]BFM Rd, Rn, #immr, #imms => [SU]BFIZ Rd, Rn, #(regsize-immr), #(imms+1)
                instruction.Mnemonic = isSigned ? Arm64Mnemonic.SBFIZ : Arm64Mnemonic.UBFIZ;
                instruction.Op2Imm = regSize - immr;
                instruction.Op3Imm = imms + 1;
                return;
            }

            //every case bfxpreferred() excludes is handled above, so anything left is [SU]BFX Rd, Rn, #immr, #(imms-immr+1)
            instruction.Mnemonic = isSigned ? Arm64Mnemonic.SBFX : Arm64Mnemonic.UBFX;
            instruction.Op3Imm = imms - immr + 1;
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.BFM && instruction.Op2Kind == Arm64OperandKind.Immediate && instruction.Op3Kind == Arm64OperandKind.Immediate)
        {
            var immr = instruction.Op2Imm;
            var imms = instruction.Op3Imm;
            var regSize = instruction.Op0Reg is >= Arm64Register.X0 and <= Arm64Register.X31 ? 64 : 32;

            if (imms >= immr)
            {
                //BFM Rd, Rn, #immr, #imms => BFXIL Rd, Rn, #immr, #(imms-immr+1)
                instruction.Mnemonic = Arm64Mnemonic.BFXIL;
                instruction.Op3Imm = imms - immr + 1;
            }
            else
            {
                //BFM Rd, Rn, #immr, #imms => BFI Rd, Rn, #(regsize-immr), #(imms+1)
                instruction.Mnemonic = Arm64Mnemonic.BFI;
                instruction.Op2Imm = regSize - immr;
                instruction.Op3Imm = imms + 1;
            }

            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.INS && instruction.Op0Kind == Arm64OperandKind.VectorRegisterElement && instruction.Op1Kind is Arm64OperandKind.VectorRegisterElement or Arm64OperandKind.Register)
        {
            //INS Vd.Ts[i1], (Vn.Ts[i2]|Rn) => MOV Vd.Ts[i1], (Vn.Ts[i2]|Rn)
            //i.e. just change INS to MOV
            instruction.Mnemonic = Arm64Mnemonic.MOV;

            //Category remains SimdRegisterToRegister
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.UMOV && instruction.Op1Kind == Arm64OperandKind.VectorRegisterElement && instruction.Op1VectorElement.Width is Arm64VectorElementWidth.S or Arm64VectorElementWidth.D)
        {
            //the word and doubleword umov forms are plain movs, the narrow ones keep their name to show the zero extension
            instruction.Mnemonic = Arm64Mnemonic.MOV;
            return;
        }

        if (instruction.Mnemonic == Arm64Mnemonic.DUP && instruction.Op0Kind == Arm64OperandKind.Register && instruction.Op0Arrangement == Arm64ArrangementSpecifier.None && instruction.Op1Kind == Arm64OperandKind.VectorRegisterElement)
        {
            //DUP Rd, Vn.Ts[i] => MOV Rd, Vn.Ts[i], but only the scalar form (the vector broadcast stays dup)
            instruction.Mnemonic = Arm64Mnemonic.MOV;
            return;
        }
    }

    //true if a single movz or movn could produce this value, i.e. it or its inverse fits in one 16-bit aligned halfword
    private static bool IsMovWideEncodable(ulong value, bool is64Bit)
    {
        var inverse = is64Bit ? ~value : ~value & uint.MaxValue;

        for (var shiftBy = 0; shiftBy < (is64Bit ? 64 : 32); shiftBy += 16)
        {
            if ((value & ~(0xFFFFUL << shiftBy)) == 0 || (inverse & ~(0xFFFFUL << shiftBy)) == 0)
                return true;
        }

        return false;
    }
}
