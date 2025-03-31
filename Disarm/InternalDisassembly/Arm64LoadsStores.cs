namespace Disarm.InternalDisassembly;

internal static class Arm64LoadsStores
{
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op0 = instruction >> 28; //Bits 28-31
        var op1 = (instruction >> 26) & 1; //Bit 26
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; //Bits 10-11

        //As can perhaps be imagined, this is by far the most deeply-nested tree of instructions
        //At this level, despite having 5 separate operands to differentiate which path we take, most of these paths are defined by masks, not by values.
        //Unfortunately, this makes the code a bit ugly.

        //They are, at least, *somewhat* grouped by category using op0
        if ((op0 & 0b1011) == 0)
            //Mostly undefined instructions, but a couple of them are defined
            return DisassembleAdvancedLoadStore(instruction);

        if (op0 == 0b1101 && op1 == 0 && op2 >> 1 == 1 && op3 >> 5 == 1)
            //Literally the only concretely defined value for op0, but it still needs others to match conditions - load/store memory tags
            return DisassembleLoadStoreMemoryTags(instruction);

        //Five more categories for op0

        if ((op0 & 0b1011) == 0b1000)
        {
            //Load/store exclusive pair, or undefined
            if (op1 == 0 && op2 == 0 && op3.TestBit(5))
                return LoadStoreExclusivePair(instruction);
            
            throw new Arm64UndefinedInstructionException($"Load/store: Undefined instruction - op0={op0}, op1={op1}, op2={op2}, op3={op3}");
        }

        //The last 4 categories look only at the last 2 bits of op0, so we can switch now
        op0 &= 0b11;

        //Ok i lied half of these are barely grouped at all in any way that makes sense to me 
        return op0 switch
        {
            0b00 => DisassembleLoadStoreExclusiveRegOrderedOrCompareSwap(instruction), //load/store exclusive reg, load/store ordered, or compare + swap 
            0b01 => DisassembleLdAprRegisterLiteralOrMemoryCopySet(instruction), //ldapr/stlr unscaled immediate, load register literal, or memory copy/set
            0b10 => DisassembleLoadStorePairs(instruction), //actual group! load/store pairs
            0b11 => DisassembleLoadStoreRegisterOrAtomic(instruction), //various kinds of load/store register, or atomic memory operations
            _ => throw new("Loads/stores: Impossible op0 value")
        };
    }

    private static Arm64Instruction DisassembleAdvancedLoadStore(uint instruction)
    {
        //Most of these are actually unimplemented. Only two categories are defined, and they are both SIMD, so we can shunt over to that class.

        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21

        if (op2 == 0b11)
            //Post-indexed simd load/store structure
            return Arm64Simd.LoadStoreSingleStructurePostIndexed(instruction);

        //Doesn't matter what op2 is at this point, unless the bottom 5 bits of op3 are zeroed, this is unimplemented.
        if ((op3 & 0b1_1111) == 0)
            return Arm64Simd.LoadStoreSingleStructure(instruction);

        throw new Arm64UndefinedInstructionException($"Advanced load/store: Congrats, you hit the minefield of undefined instructions. op2: {op2}, op3: {op3}");
    }

    private static Arm64Instruction DisassembleLoadStoreMemoryTags(uint instruction)
    {
        var opc = (instruction >> 22) & 0b11; // Bits 22-23
        var imm9 = (long) (instruction >> 12) & 0b1_1111_1111; // Bits 12-20
        var op2 = (instruction >> 10) & 0b11; // Bits 10-11
        var rn = (int)(instruction >> 5) & 0b1_1111; // Bits 5-9
        var rt = (int)instruction & 0b1_1111; // Bits 0-5

        imm9 = Arm64CommonUtils.SignExtend(imm9, 9, 64);
        var offset = imm9 << Arm64CommonUtils.LOG2_TAG_GRANULE;
        
        return opc switch
        {
            0b00 when offset != 0 => new()
            {
                Mnemonic = Arm64Mnemonic.STG,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b00 when offset == 0 => new()
            {
                Mnemonic = Arm64Mnemonic.STZGM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            0b01 when op2 == 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.LDG,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            0b01 when op2 != 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.STZG,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b10 when offset != 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.ST2G,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b10 when offset == 0 && op2 == 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.STGM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            0b11 when offset != 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.STZ2G,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                MemIndexMode = op2 switch
                {
                    0b01 => Arm64MemoryIndexMode.PostIndex,
                    0b10 => Arm64MemoryIndexMode.Offset,
                    0b11 => Arm64MemoryIndexMode.PreIndex,
                    _ => throw new Arm64UndefinedInstructionException("Bad memory index mode")
                },
                MemOffset = offset,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.X0 + rn,
                MemBase = Arm64Register.X0 + rt
            },
            0b11 when offset == 0 && op2 == 0 =>  new()
            {
                Mnemonic = Arm64Mnemonic.LDGM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryTagging,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op0Reg = Arm64Register.X0 + rn,
                Op1Reg = Arm64Register.X0 + rt
            },
            _ => throw new Arm64UndefinedInstructionException("Unallocated")
        };
    }

    private static Arm64Instruction DisassembleLoadStoreExclusiveRegOrderedOrCompareSwap(uint instruction)
    {
        //Load/store exclusive register, load/store ordered, or compare + swap
        var op0 = (instruction >> 28) & 0b1111; //Bits 28-31
        var op1 = instruction.TestBit(26); //Bit 26
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; // Bits 10-11
        
        if(op1)
            throw new Arm64UndefinedInstructionException("Load/store (exclusive register|ordered)|compare/swap: op1 set");
        
        if(op2 == 0 && op3.TestBit(6))
            throw new Arm64UndefinedInstructionException("Load/store (exclusive register|ordered)|compare/swap: op2=0, op3 hi bit set");

        // op0 xx00 | op1 0 | op2 0x | op3 empty | op4 empty | Load/store exclusive
        if ((op0 & 0b11) == 0 && !op1 && !op2.TestBit(1)) 
            return LoadStoreExclusive(instruction);
        
        if(op2 != 1)
            throw new Arm64UndefinedInstructionException("Load/store (exclusive register|ordered)|compare/swap: op2 was not 0 or 1");

        if (op3.TestBit(6))
            return CompareAndSwap(instruction);

        return LoadStoreOrdered(instruction);
    }
    
    private static Arm64Instruction LoadStoreExclusive(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
        };
    }
    
    private static Arm64Instruction CompareAndSwap(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Comparison, 
        };
    }
    
    private static Arm64Instruction LoadStoreOrdered(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
        };
    }

    private static Arm64Instruction DisassembleLdAprRegisterLiteralOrMemoryCopySet(uint instruction)
    {
        //LDAPR/STLR, load/store register literal, memory copy, or memory set
        var op1 = instruction.TestBit(26); //Bit 26
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; //Bits 10-11

        if (!op2.TestBit(1))
            return LoadRegisterLiteral(instruction);
        
        if(op3.TestBit(5))
            throw new Arm64UndefinedInstructionException("LdAprRegisterLiteralOrMemoryCopySet: op3 hi bit set");

        return op4.TestBit(0)
            ? MemoryCopyOrSet(instruction)
            : LdarpOrStlr(instruction);
    }
    
    private static Arm64Instruction LoadRegisterLiteral(uint instruction)
    {
        var opc = (instruction >> 30) & 0b11; // Bits 30-31
        var v = instruction.TestBit(26);
        var imm19 = (instruction >> 5) & 0b111_1111_1111_1111_1111; // Bits 5-23
        imm19 <<= 2; //4-byte aligned
        var label = Arm64CommonUtils.SignExtend(imm19, 21, 64); //21 is 19 + 2 for the left shift
        var rt = (int)instruction & 0b1_1111;
        
        return opc switch
        {
            (0b00 or 0b01) when !v => new()
            {
                Mnemonic = Arm64Mnemonic.LDR,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt,
                Op1Imm = label
            },
            0b10 when !v =>  new()
            {
                Mnemonic = Arm64Mnemonic.LDRSW,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Reg = Arm64Register.X0 + rt,
                Op1Imm = label
            },
            0b11 when !v =>  new()
            {
                Mnemonic = Arm64Mnemonic.PRFM,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Immediate,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Imm = rt, //TODO Prefetch isn't just a raw imm, it's a combination of well-defined type | cache level | cache policy
                Op1Imm = label
            },
            (0b00 or 0b01 or 0b10) when v => new()
            {
                Mnemonic = Arm64Mnemonic.LDR,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.ImmediatePcRelative,
                Op0Reg = (opc == 0b00 ? Arm64Register.S0 : opc == 0b01 ? Arm64Register.D0 : Arm64Register.V0) + rt,
                Op1Imm = label
            },
            _ => throw new Arm64UndefinedInstructionException("Unallocated")
        };
    }
    
    private static Arm64Instruction MemoryCopyOrSet(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.Move, 
        };
    }
    
    private static Arm64Instruction LdarpOrStlr(uint instruction)
    {
        // FEAT_LRCPC2
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
        };
    }

    private static Arm64Instruction DisassembleLoadStorePairs(uint instruction)
    {
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24

        return op2 switch
        {
            0b00 => LoadStoreNoAllocatePairs(instruction), //load/store no-allocate pairs
            0b01 => LoadStoreRegisterPair(instruction, Arm64MemoryIndexMode.PostIndex), //load/store register pair (post-indexed)
            0b10 => LoadStoreRegisterPair(instruction, Arm64MemoryIndexMode.Offset), //load/store register pair (offset)
            0b11 => LoadStoreRegisterPair(instruction, Arm64MemoryIndexMode.PreIndex), //load/store register pair (pre-indexed)
            _ => throw new("Loads/store pairs: Impossible op2 value")
        };
    }

    //The 'xx11' category of loads/stores
    private static Arm64Instruction DisassembleLoadStoreRegisterOrAtomic(uint instruction)
    {
        var op2 = (instruction >> 23) & 0b11; //Bits 23-24
        var op3 = (instruction >> 16) & 0b11_1111; //Bits 16-21
        var op4 = (instruction >> 10) & 0b11; //Bits 10-11

        //Bottom bit of op2 is irrelevant
        op2 >>= 1;

        if (op2 == 1)
            //Load/store reg unsigned immediate
            return LoadStoreRegFromImmUnsigned(instruction);

        //Check top bit of op3
        if (op3 >> 5 == 1)
            //Atomic, or load/store reg with non-immediate, depending on op1
            return op4 switch
            {
                0b00 => AtomicMemoryOperation(instruction), //Atomic
                0b10 => LoadStoreRegisterFromRegisterOffset(instruction), //Load/store (reg), (reg + x)
                _ => LoadStoreRegisterFromPac(instruction), //Load store (reg), (pac)
            };

        //Some kind of load/store reg with an immediate
        return op4 switch
        {
            0b00 => LoadStoreRegisterFromImmUnscaled(instruction), //Load/store (reg), (unscaled immediate)
            0b01 => LoadStoreRegisterFromImm(instruction, Arm64MemoryIndexMode.PostIndex), //Load/store (reg), (post-indexed immediate)
            0b10 => LoadStoreRegisterUnprivileged(instruction), //Load/store (reg), (unprivileged)
            0b11 => LoadStoreRegisterFromImm(instruction, Arm64MemoryIndexMode.PreIndex), //Load/Store (reg), (pre-indexed immediate)
            _ => throw new("Impossible op4"),
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromImm(uint instruction, Arm64MemoryIndexMode memoryIndexMode)
    {
        // Load/store immediate pre-indexed

        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26); //Bit 26
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var imm9 = (instruction >> 12) & 0b1_1111_1111; //Bits 12-20
        var rn = (int)(instruction >> 5) & 0b11111; //Bits 5-9
        var rt = (int)(instruction & 0b11111); //Bits 0-4

        if (size is 0b10 or 0b11)
        {
            var invalid = isVector ? opc is 0b10 or 0b11 : opc is 0b11;
            
            if (invalid)
                throw new Arm64UndefinedInstructionException($"Load/store immediate pre-indexed: Invalid size/opc combination. size: {size}, opc: {opc}");
        }
        
        //Note to self - this logic is copied from further down but has had some minor adjustments made, it may still be incorrect in places
        //so if something seems wrong, it probably is!
        var mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.STRB,
                0b01 when !isVector => Arm64Mnemonic.STRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.STR,
                _ when isVector => Arm64Mnemonic.STR,
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRB,
                0b01 when !isVector => Arm64Mnemonic.LDRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.LDR,
                _ when isVector => Arm64Mnemonic.LDR,
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //64-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //64-bit variant
                0b10 when !isVector => Arm64Mnemonic.LDRSW,
                0b00 when isVector => Arm64Mnemonic.STR, //128-bit store
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //32-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //32-bit variant
                0b00 when isVector => Arm64Mnemonic.LDR, //128-bit load
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };
        
        var baseReg = mnemonic switch
        {
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector && opc is 0 => size switch
            {
                0 => Arm64Register.B0,
                1 => Arm64Register.H0,
                2 => Arm64Register.S0,
                3 => Arm64Register.D0,
                _ => throw new("Impossible size")
            },
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector => Arm64Register.V0, //128-bit vector
            Arm64Mnemonic.STRB or Arm64Mnemonic.LDRB or Arm64Mnemonic.STRH or Arm64Mnemonic.LDRH => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR => Arm64Register.X0,
            Arm64Mnemonic.LDRSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDRSH => Arm64Register.W0,
            Arm64Mnemonic.LDRSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };
        
        var regT = baseReg + rt;
        var regN = Arm64Register.X0 + rn;
        
        var offset = Arm64CommonUtils.SignExtend(imm9, 9, 64);

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            MemIndexMode = memoryIndexMode,
            Op0Reg = regT,
            MemBase = regN,
            MemOffset = offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreNoAllocatePairs(uint instruction)
    {
        var opc = (instruction >> 30) & 0b11; // Bits 30-31
        var v = instruction.TestBit(26);
        var l = instruction.TestBit(22);

        var imm7 = (instruction >> 15) & 0b111_1111; // Bits - 15-21
        var rt2 = (int)(instruction >> 10) & 0b1_1111; // Bits - 10-14
        var rn = (int)(instruction >> 5) & 0b1_1111; // Bits - 5-9
        var rt = (int)instruction & 0b1_1111; // Bits - 0-14

        var offset = Arm64CommonUtils.SignExtend(imm7, 7, 64) << (2 + (l ? 1 : 0));
        
        return opc switch
        {
            (0b00 or 0b10) when !v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt,
                Op1Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt2
            },
            (0b00 or 0b10) when !v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt,
                Op1Reg = (opc == 0b00 ? Arm64Register.W0 : Arm64Register.X0) + rt2
            },
            0b00 when v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.S0 + rt,
                Op1Reg = Arm64Register.S0 + rt2
            },
            0b01 when v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.D0 + rt,
                Op1Reg = Arm64Register.D0 + rt2
            },
            0b10 when v && !l => new()
            {
                Mnemonic = Arm64Mnemonic.STNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.V0 + rt, // aka Q0
                Op1Reg = Arm64Register.V0 + rt2 // aka Q0
            },
            0b00 when v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.S0 + rt,
                Op1Reg = Arm64Register.S0 + rt2
            },
            0b01 when v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.D0 + rt,
                Op1Reg = Arm64Register.D0 + rt2
            },
            0b10 when v && l => new()
            {
                Mnemonic = Arm64Mnemonic.LDNP,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MemOffset = offset,
                MemBase = Arm64Register.X0 + rn,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Register,
                Op2Kind = Arm64OperandKind.Memory,
                Op0Reg = Arm64Register.V0 + rt, // aka Q0
                Op1Reg = Arm64Register.V0 + rt2 // aka Q0
            },
            _ => throw new Arm64UndefinedInstructionException("Unallocated")
        };
    }

    private static Arm64Instruction LoadStoreRegisterPair(uint instruction, Arm64MemoryIndexMode mode)
    {
        //Page C4-559

        var opc = (instruction >> 30) & 0b11; //Bits 30-31
        var imm7 = (instruction >> 15) & 0b111_1111; //Bits 15-21
        var rt2 = (int)(instruction >> 10) & 0b1_1111; //Bits 10-14
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4

        var isVector = instruction.TestBit(26);
        var isLoad = instruction.TestBit(22);

        //opc: 
        //00 - stp/ldp (32-bit + 32-bit fp)
        //01 - stgp, ldpsw, stp/ldp (64-bit fp)
        //10 - stp/ldp (64-bit + 128-bit fp)
        //11 - reserved

        if (opc == 0b11)
            throw new Arm64UndefinedInstructionException("Load/store register pair (pre-indexed): opc == 0b11");

        var mnemonic = isLoad ? Arm64Mnemonic.LDP : Arm64Mnemonic.STP;

        if (opc == 1 && !isVector)
            mnemonic = isLoad ? Arm64Mnemonic.LDPSW : Arm64Mnemonic.STGP; //Store Allocation taG (64-bit) and Pair/LoaD Pair of registers Signed Ward (32-bit) 

        var destBaseReg = opc switch
        {
            0b00 when isVector => Arm64Register.S0, //32-bit vector
            0b00 => Arm64Register.W0, //32-bit
            0b01 when mnemonic == Arm64Mnemonic.STGP => Arm64Register.W0, //32-bit
            0b01 => Arm64Register.D0, //All other group 1 is 64-bit vector
            0b10 when isVector => Arm64Register.V0, //128-bit vector
            0b10 => Arm64Register.X0, //64-bit
            _ => throw new("Impossible opc value")
        };

        var dataSizeBits = opc switch
        {
            0b00 => 32,
            0b01 when mnemonic == Arm64Mnemonic.STGP => 32,
            0b01 => 64,
            0b10 when isVector => 128,
            0b10 => 64,
            _ => throw new("Impossible opc value")
        };

        var dataSizeBytes = dataSizeBits / 8;

        //The offset must be aligned to the size of the data so is stored in imm7 divided by this factor
        //So we multiply by the size of the data to get the offset
        //It is stored signed.
        var realImm7 = Arm64CommonUtils.CorrectSignBit(imm7, 7);

        var reg1 = destBaseReg + rt;
        var reg2 = destBaseReg + rt2;
        var regN = Arm64Register.X0 + rn;

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Memory,
            Op0Reg = reg1,
            Op1Reg = reg2,
            MemBase = regN,
            MemOffset = realImm7 * dataSizeBytes,
            MemIndexMode = mode,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegFromImmUnsigned(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26);
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var imm12 = (instruction >> 10) & 0b1111_1111_1111; //Bits 10-21
        var rn = (int)(instruction >> 5) & 0b11111; //Bits 5-9
        var rt = (int)(instruction & 0b11111); //Bits 0-4
        
        //Zero extend imm12 to 64-bit
        var immediate = (long)imm12;
        immediate <<= (int) size; //Shift left by the size... apparently?

        Arm64Register baseReg;
        Arm64Mnemonic mnemonic;
        
        if (isVector)
        {
            //For once, SIMD/FP is the simple path. It's always LDR or STR, and for all but the 128-bit version, the register depends on size
            //Let's get the 128-bit check out first
            if (opc is 0b10 or 0b11)
            {
                //128-bit. Ensure size is 00
                if (size != 0)
                    throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc 0b10/0b11 unallocated for size > 0");
                
                mnemonic = opc == 0b10 ? Arm64Mnemonic.STR : Arm64Mnemonic.LDR;
                baseReg = Arm64Register.V0; //128-bit variant
            }
            else
            {
                mnemonic = opc == 0b00 ? Arm64Mnemonic.STR : Arm64Mnemonic.LDR;
                baseReg = size switch
                {
                    0b00 => Arm64Register.B0, //8-bit variant
                    0b01 => Arm64Register.H0, //16-bit variant
                    0b10 => Arm64Register.S0, //32-bit variant
                    0b11 => Arm64Register.D0, //64-bit variant
                    _ => throw new("Impossible size")
                };
            }
            
            return new()
            {
                Mnemonic = mnemonic,
                Op0Kind = Arm64OperandKind.Register,
                Op1Kind = Arm64OperandKind.Memory,
                Op0Reg = baseReg + rt,
                MemBase = Arm64Register.X0 + rn,
                MemOffset = immediate,
                MemIndexMode = Arm64MemoryIndexMode.Offset,
                MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
            };
        }
        
        //Now we have to deal with the non-SIMD/FP case.

        //This is considerably less clean than it perhaps could be because they don't stick to patterns and 
        //the mnemonics are different for different sizes.
        //Example - in general, even opc is a store, odd is a load. But opc == 11 && !v && size = 0 => LDRSB. :(
        mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 => Arm64Mnemonic.STRB,
                0b01 => Arm64Mnemonic.STRH,
                0b10 or 0b11 => Arm64Mnemonic.STR, //32 or 64-bit
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 => Arm64Mnemonic.LDRB,
                0b01 => Arm64Mnemonic.LDRH,
                0b10 or 0b11 => Arm64Mnemonic.LDR, //32 or 64-bit
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                //These all break the rules, they are loads but they are even opc
                0b00 => Arm64Mnemonic.LDRSB, //64-bit variant
                0b01 => Arm64Mnemonic.LDRSH, //64-bit variant
                0b10 => Arm64Mnemonic.LDRSW,
                0b11 => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc 0b10 unallocated for size 0b11"), 
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 => Arm64Mnemonic.LDRSB, //32-bit variant
                0b01 => Arm64Mnemonic.LDRSH, //32-bit variant
                0b10 => Arm64Mnemonic.PRFM, //TODO?
                0b11 => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc 0b11 unallocated for size 0b11"),
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };

        if (mnemonic == Arm64Mnemonic.PRFM)
            throw new NotImplementedException("If you're seeing this, reach out, because PRFM is not implemented.");

        baseReg = mnemonic switch
        {
            Arm64Mnemonic.STRB or Arm64Mnemonic.LDRB or Arm64Mnemonic.STRH or Arm64Mnemonic.LDRH => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR => Arm64Register.X0,
            Arm64Mnemonic.LDRSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDRSH => Arm64Register.W0,
            Arm64Mnemonic.LDRSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };

        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = baseReg + rt,
            MemBase = Arm64Register.X0 + rn,
            MemOffset = immediate,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction AtomicMemoryOperation(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromRegisterOffset(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26);
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var rm = (int)(instruction >> 16) & 0b1_1111; //Bits 16-20
        var option = (instruction >> 13) & 0b111; //Bits 13-15
        var sFlag = instruction.TestBit(12);
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4
        
        var mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.STRB,
                0b01 when !isVector => Arm64Mnemonic.STRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.STR,
                _ when isVector => Arm64Mnemonic.STR,
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRB,
                0b01 when !isVector => Arm64Mnemonic.LDRH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.LDR,
                _ when isVector => Arm64Mnemonic.LDR,
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //64-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //64-bit variant
                0b10 when !isVector => Arm64Mnemonic.LDRSW,
                0b11 when !isVector => Arm64Mnemonic.PRFM,
                0b00 when isVector => Arm64Mnemonic.STR, 
                _ when isVector => throw new Arm64UndefinedInstructionException("Load/store register from register offset: opc 0b10 unallocated for vectors when size > 0"),
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDRSB, //32-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDRSH, //32-bit variant
                0b00 when isVector => Arm64Mnemonic.LDR, //128-bit load
                0b10 or 0b11 => throw new Arm64UndefinedInstructionException("Load/store register from register offset: opc 0b11 unallocated for size 0b1x"),
                _ when isVector => throw new Arm64UndefinedInstructionException("Load/store register from register offset: opc 0b11 unallocated for vectors when size > 0"),
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };

        var isShiftedRegister = option == 0b011;
        
        if (mnemonic == Arm64Mnemonic.PRFM)
            throw new NotImplementedException("If you're seeing this, reach out, because PRFM is not implemented.");

        var baseReg = mnemonic switch
        {
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector && opc is 0 => size switch
            {
                0 => Arm64Register.B0,
                1 => Arm64Register.H0,
                2 => Arm64Register.S0,
                3 => Arm64Register.D0,
                _ => throw new("Impossible size")
            },
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when isVector => Arm64Register.V0, //128-bit vector
            Arm64Mnemonic.STRB or Arm64Mnemonic.LDRB or Arm64Mnemonic.STRH or Arm64Mnemonic.LDRH => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STR or Arm64Mnemonic.LDR => Arm64Register.X0,
            Arm64Mnemonic.LDRSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDRSH => Arm64Register.W0,
            Arm64Mnemonic.LDRSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };

        var secondReg64Bit = option.TestBit(0);
        var secondRegBase = secondReg64Bit ? Arm64Register.X0 : Arm64Register.W0;
        var extendKind = (Arm64ExtendType)option;
        //Extended register: Mnemonic Wt, [Xn, Xm|Wm, ExtendKind Amount]
        //Shifted register: Mnemonic Wt, [Xn, Xm|Wm, LSL Amount]

        var shiftAmount = 0;
        if (sFlag && isShiftedRegister)
        {
            //Shift set, amount is size-dependent
            shiftAmount = size switch
            {
                0b00 when isVector && opc == 0b11 => 4, //128-bit variant
                0b00 => 0, //8-bit variant, vector or otherwise
                0b01 => 1,
                0b10 => 2,
                0b11 => 3,
                _ => throw new("Impossible size")
            };
        }
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = baseReg + rt,
            MemBase = Arm64Register.X0 + rn,
            MemAddendReg = secondRegBase + rm,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MemExtendType = isShiftedRegister ? Arm64ExtendType.NONE : extendKind,
            MemShiftType = isShiftedRegister ? Arm64ShiftType.LSL : Arm64ShiftType.NONE,
            MemExtendOrShiftAmount = shiftAmount,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromPac(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.PointerAuthentication,
        };
    }

    private static Arm64Instruction LoadStoreRegisterFromImmUnscaled(uint instruction)
    {
        var size = (instruction >> 30) & 0b11; //Bits 30-31
        var isVector = instruction.TestBit(26);
        var opc = (instruction >> 22) & 0b11; //Bits 22-23
        var imm9 = (instruction >> 12) & 0b1_1111_1111; //Bits 12-20
        var rn = (int)(instruction >> 5) & 0b1_1111; //Bits 5-9
        var rt = (int)(instruction & 0b1_1111); //Bits 0-4
        
        if(size is 1 or 3 && isVector && opc > 1)
            throw new Arm64UndefinedInstructionException("Load/store register from immediate (unsigned): opc > 1 unallocated for vectors when size > 1");
        
        //Here we go with this dance again...
        var mnemonic = opc switch
        {
            0b00 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.STURB,
                0b01 when !isVector => Arm64Mnemonic.STURH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.STUR,
                _ when isVector => Arm64Mnemonic.STUR,
                _ => throw new($"Impossible size: {size}")
            },
            0b01 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDURB,
                0b01 when !isVector => Arm64Mnemonic.LDURH,
                0b10 or 0b11 when !isVector => Arm64Mnemonic.LDUR,
                _ when isVector => Arm64Mnemonic.LDUR,
                _ => throw new($"Impossible size: {size}")
            },
            0b10 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDURSB, //64-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDURSH, //64-bit variant
                0b10 when !isVector => Arm64Mnemonic.LDURSW,
                0b00 when isVector => Arm64Mnemonic.STUR, //128-bit store
                _ when isVector => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unscaled): opc 0b10 unallocated for vectors when size > 0"),
                _ => throw new($"Impossible size: {size}")
            },
            0b11 => size switch
            {
                0b00 when !isVector => Arm64Mnemonic.LDURSB, //32-bit variant
                0b01 when !isVector => Arm64Mnemonic.LDURSH, //32-bit variant
                0b10 when !isVector => Arm64Mnemonic.PRFUM, //TODO?
                0b00 when isVector => Arm64Mnemonic.LDUR, //128-bit store
                0b11 => throw new Arm64UndefinedInstructionException("Load/store register from immediate (unscaled): opc 0b11 unallocated for size 0b11"),
                _ => throw new($"Impossible size: {size}")
            },
            _ => throw new("Impossible opc value")
        };
        
        if (mnemonic == Arm64Mnemonic.PRFUM)
            throw new NotImplementedException("If you're seeing this, reach out, because PRFUM is not implemented.");
        
        var baseReg = mnemonic switch
        {
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR when isVector && opc is 0 => size switch
            {
                0 => Arm64Register.B0,
                1 => Arm64Register.H0,
                2 => Arm64Register.S0,
                3 => Arm64Register.D0,
                _ => throw new("Impossible size")
            },
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR when isVector => Arm64Register.V0, //128-bit vector
            Arm64Mnemonic.STURB or Arm64Mnemonic.LDURB or Arm64Mnemonic.STURH or Arm64Mnemonic.LDURH => Arm64Register.W0,
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR when size is 0b10 => Arm64Register.W0,
            Arm64Mnemonic.STUR or Arm64Mnemonic.LDUR => Arm64Register.X0,
            Arm64Mnemonic.LDURSH when opc is 0b10 => Arm64Register.X0,
            Arm64Mnemonic.LDURSH => Arm64Register.W0,
            Arm64Mnemonic.LDURSW => Arm64Register.X0,
            _ => throw new("Impossible mnemonic")
        };
        
        var regT = baseReg + rt;
        var regN = Arm64Register.X0 + rn;
        
        //Sign extend imm9 to 64-bit
        var immediate = Arm64CommonUtils.SignExtend(imm9, 9, 64);
        
        return new()
        {
            Mnemonic = mnemonic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Memory,
            Op0Reg = regT,
            MemBase = regN,
            MemOffset = immediate,
            MemIndexMode = Arm64MemoryIndexMode.Offset,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreRegisterUnprivileged(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister,
        };
    }

    private static Arm64Instruction LoadStoreExclusivePair(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.MemoryToOrFromRegister, 
        };
    }
}
