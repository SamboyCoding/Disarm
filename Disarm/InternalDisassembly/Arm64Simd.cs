namespace Disarm.InternalDisassembly;

internal static class Arm64Simd
{
    //I hate this entire table.
    
    public static Arm64Instruction Disassemble(uint instruction)
    {
        var op0 = (instruction >> 28) & 0b1111; //Bits 28-31
        //25-27 must be 111
        var op1 = (instruction >> 23) & 0b11; //Bits 23-24
        var op2 = (instruction >> 19) & 0b1111; //Bits 19-22
        var op3 = (instruction >> 10) & 0b1_1111_1111; //Bits 10-18

        var op1Hi = op1 >> 1;

        //Concrete values or one-masked-bit for op0
        switch (op0)
        {
            case 0b0100 when op1Hi == 0 && op2.TestPattern(0b111, 0b101) && op3.TestPattern(0b110000011, 0b10):
                return CryptoAes(instruction);
            case 0b0101 when op1Hi == 0 && op2.TestPattern(0b111, 0b101) && op3.TestPattern(0b110000011, 0b10):
                return CryptoTwoRegSha(instruction);
            case 0b0101 when op1Hi == 0 && op2.TestPattern(0b0100, 0) && op3.TestPattern(0b100011, 0):
                return CryptoThreeRegSha(instruction);
            case 0b0101 or 0b0111 when op1 == 0 && op2.TestPattern(0b1100, 0) && op3.TestPattern(0b100001, 1):
                return AdvancedSimdScalarCopy(instruction);
        }

        //Masks for op0
        if (op0.TestPattern(0b1001, 0))
        {
            //0xx0 family: Advanced SIMD (non-scalar)
            return Arm64NonScalarAdvancedSimd.Disassemble(instruction);
        }

        if (op0.TestPattern(0b1101, 0b0101))
        {
            //01x1 family: Advanced SIMD (scalar)
            return Arm64ScalarAdvancedSimd.Disassemble(instruction);
        }

        if (op0 == 0b1100)
        {
            //TODO Cryptographic two, three, or four reg
            return new()
            {
                Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
                MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic, 
            };
        }

        if (op0.TestPattern(0b0101, 0b0001))
        {
            //x0x1: Floating point family - either conversion two/from integer/fixed-point, or some general floating-point instruction
            
            if (op1.TestBit(1))
                //Only one with bit 24 set
                return Arm64FloatingPoint.DataProcessingThreeSource(instruction);

            //Get the two conversion types out first
            
            if (!op2.TestBit(2))
                //Only one with bit 20 clear
                return Arm64FloatingPoint.ConversionToAndFromFixedPoint(instruction);

            if ((op3 & 0b11_1111) == 0)
                return Arm64FloatingPoint.ConversionToAndFromInteger(instruction);

            if ((op3 & 0b1_1111) == 0b1_0000)
                return Arm64FloatingPoint.DataProcessingOneSource(instruction);
            
            if((op3 & 0b1111) == 0b1000)
                return Arm64FloatingPoint.Compare(instruction);

            if ((op3 & 0b111) == 0b100)
                return Arm64FloatingPoint.Immediate(instruction);

            return (op3 & 0b11) switch
            {
                0b01 => Arm64FloatingPoint.ConditionalCompare(instruction),
                0b10 => Arm64FloatingPoint.DataProcessingTwoSource(instruction),
                0b11 => Arm64FloatingPoint.ConditionalSelect(instruction),
                _ => throw new("Impossible op3"),
            };
        }

        throw new Arm64UndefinedInstructionException($"Unimplemented SIMD instruction. Op0: {op0}, Op1: {op1}, Op2: {op2}, Op3: {op3}");
    }


    private static Arm64Instruction CryptoAes(uint instruction)
    {
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; // Bits 12-16
        var rn = (int) (instruction >> 5) & 0b11111; // Bits 5-9
        var rd = (int) instruction & 0b11111; // Bits 0-4
        
        if(size != 0)
            throw new Arm64UndefinedInstructionException("AES instruction with size != 0");

        if (opcode.TestBit(3) || instruction.TestBit(4) || (instruction >> 2) == 0)
            throw new Arm64UndefinedInstructionException($"AES: Reserved opcode 0x{opcode:X}");

        return new()
        {
            Mnemonic = opcode switch
            {
                0b00100 => Arm64Mnemonic.AESE,
                0b00101 => Arm64Mnemonic.AESD,
                0b00110 => Arm64Mnemonic.AESMC,
                0b00111 => Arm64Mnemonic.AESIMC,
                _ => throw new Arm64UndefinedInstructionException($"AES: bad opcode {opcode}")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic,
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rd,
            Op1Reg = Arm64Register.V0 + rn,
        };
    }

    private static Arm64Instruction CryptoTwoRegSha(uint instruction)
    {
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var opcode = (instruction >> 12) & 0b1_1111; // Bits 12-16
        var rn = (int) (instruction >> 5) & 0b11111; // Bits 5-9
        var rd = (int) instruction & 0b11111; // Bits 0-4
        
        if(size != 0)
            throw new Arm64UndefinedInstructionException("SHA instruction with size != 0");
        
        return new()
        {
            Mnemonic = opcode switch
            {
                0b00000 => Arm64Mnemonic.SHA1H,
                0b00001 => Arm64Mnemonic.SHA1SU1,
                0b00010 => Arm64Mnemonic.SHA256SU0,
                _ => throw new Arm64UndefinedInstructionException($"SHA: bad opcode {opcode}")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op0Reg = opcode switch
            {
                0b00001 => Arm64Register.V0 + rd,
                _ => Arm64Register.S0 + rd,
            },
            Op1Reg = opcode switch
            {
                0b00001 => Arm64Register.V0 + rn,
                _ => Arm64Register.S0 + rn,
            },
        };
    }

    private static Arm64Instruction CryptoThreeRegSha(uint instruction)
    {
        var size = (instruction >> 22) & 0b11; // Bits 22-23
        var opcode = (instruction >> 12) & 0b111; // Bits 12-14
        var rm = (int) (instruction >> 16) & 0b11111; // Bits 16-20
        var rn = (int) (instruction >> 5) & 0b11111; // Bits 5-9
        var rd = (int) instruction & 0b11111; // Bits 0-4
        
        if(size != 0)
            throw new Arm64UndefinedInstructionException("SHA instruction with size != 0");
        
        return new()
        {
            Mnemonic = opcode switch
            {
                0b000 => Arm64Mnemonic.SHA1C,
                0b001 => Arm64Mnemonic.SHA1P,
                0b010 => Arm64Mnemonic.SHA1M,
                0b011 => Arm64Mnemonic.SHA1SU0,
                0b100 => Arm64Mnemonic.SHA256H,
                0b101 => Arm64Mnemonic.SHA256H2,
                0b110 => Arm64Mnemonic.SHA256SU1,
                _ => throw new Arm64UndefinedInstructionException("Bad opcode")
            },
            MnemonicCategory = Arm64MnemonicCategory.SimdCryptographic, 
            Op0Kind = Arm64OperandKind.Register,
            Op1Kind = Arm64OperandKind.Register,
            Op2Kind = Arm64OperandKind.Register,
            Op0Reg = Arm64Register.V0 + rd,
            Op1Reg = opcode switch
            {
                0b000 or 0b001 or 0b010 => Arm64Register.S0 + rn,
                _ => Arm64Register.V0 + rn,
            },
            Op3Reg = Arm64Register.V0 + rm,
        };
    }

    internal static Arm64Instruction LoadStoreSingleStructure(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdStructureLoadOrStore, 
        };
    }

    internal static Arm64Instruction LoadStoreSingleStructurePostIndexed(uint instruction)
    {
        return new()
        {
            Mnemonic = Arm64Mnemonic.UNIMPLEMENTED,
            MnemonicCategory = Arm64MnemonicCategory.SimdStructureLoadOrStore, 
        };
    }
    
    public static Arm64Instruction AdvancedSimdScalarCopy(uint instruction)
    {
        var op = instruction.TestBit(29);
        var imm5 = (instruction >> 16) & 0b1_1111;
        var imm4 = (instruction >> 11) & 0b1111;
        var rn = (int) (instruction >> 5) & 0b1_1111;
        var rd = (int) instruction & 0b1_1111;
        
        if(op)
            throw new Arm64UndefinedInstructionException("Advanced SIMD: scalar copy: op flag is reserved");
        
        if(imm4 != 0)
            throw new Arm64UndefinedInstructionException("Advanced SIMD: scalar copy: all bits of imm4 are reserved");
        
        //There's actually only one instruction here lol, DUP (element)
        //Which in turn is actually just an alias of MOV (scalar)
        //Still, I'll disassemble it as DUP and implement the alias properly
        
        var baseDestReg = imm5.TestBit(0) 
            ? Arm64Register.B0 : imm5.TestBit(1)
            ? Arm64Register.H0 : imm5.TestBit(2)
            ? Arm64Register.S0 : imm5.TestBit(3)
            ? Arm64Register.D0 : throw new Arm64UndefinedInstructionException("Advanced SIMD: scalar copy: high bit of imm5 is reserved");

        var destReg = baseDestReg + rd;
        var srcReg = Arm64Register.V0 + rn;

        var srcVectorElementWidth = baseDestReg switch
        {
            Arm64Register.B0 => Arm64VectorElementWidth.B,
            Arm64Register.H0 => Arm64VectorElementWidth.H,
            Arm64Register.S0 => Arm64VectorElementWidth.S,
            Arm64Register.D0 => Arm64VectorElementWidth.D,
            _ => throw new("Impossible baseDestReg")
        };

        var srcElementIndex = srcVectorElementWidth switch
        {
            Arm64VectorElementWidth.B => imm5 >> 1,
            Arm64VectorElementWidth.H => imm5 >> 2,
            Arm64VectorElementWidth.S => imm5 >> 3,
            Arm64VectorElementWidth.D => imm5 >> 4,
            _ => throw new("Impossible srcVectorElementWidth")
        };

        return new()
        {
            Mnemonic = Arm64Mnemonic.DUP,
            Op0Kind = Arm64OperandKind.Register,
            Op0Reg = destReg,
            Op1Kind = Arm64OperandKind.VectorRegisterElement,
            Op1Reg = srcReg,
            Op1VectorElement = new(srcVectorElementWidth, (int)srcElementIndex),
            MnemonicCategory = Arm64MnemonicCategory.SimdRegisterToRegister,
        };
    }
}
