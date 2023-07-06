using System.Buffers.Binary;
using System.Collections;
using Disarm.InternalDisassembly;

namespace Disarm;

public static class Disassembler
{
    /// <param name="RemapAliases">True to map aliased encodings to their preferred disassembly as specified by ARM. You almost always want this.</param>
    /// <param name="ContinueOnError">True to continue attempting to disassemble if a bad instruction is encountered. Note that due to the fact that this swallows exceptions, many bad instructions may slow down disassembly.</param>
    /// <param name="ThrowOnUnimplemented">Throw an exception if an unimplemented instruction is encountered (rather than returning an instruction with mnemonic UNIMPLEMENTED and potentially a category)</param>
    public readonly record struct Options(bool RemapAliases, bool ContinueOnError, bool ThrowOnUnimplemented)
    {
        public static Options Default { get; } = new(true, false, true);
        public static Options IgnoreErrors { get; } = Default with { ContinueOnError = true, ThrowOnUnimplemented = false };
    }

    /// <summary>
    /// Disassembles all instructions in the specified <paramref name="input"/>. The length of the input span must be a multiple of 4 bytes, as each instruction is 4 bytes.
    /// </summary>
    /// <param name="input">The assembly code to disassemble</param>
    /// <param name="virtualAddress">The virtual address of the first instruction, used to get correct values for PC-relative reads/writes/jumps</param>
    /// <param name="endVirtualAddress">The end virtual address after all instructions are read</param>
    /// <param name="options">The disassembly options</param>
    /// <returns>A <see cref="List{T}"/> containing disassembled instructions</returns>
    /// <exception cref="Exception">If an undefined instruction is encountered or if an unexpected error occurs, unless <see cref="Options.ContinueOnError"/> is set.</exception>
    public static List<Arm64Instruction> Disassemble(ReadOnlySpan<byte> input, ulong virtualAddress, out ulong endVirtualAddress, Options? options = null)
    {
        endVirtualAddress = virtualAddress + (ulong)input.Length;

        if (input.Length % 4 != 0)
            throw new("Arm64 instructions are 4 bytes, therefore the assembly to disassemble must be a multiple of 4 bytes");

        var ret = new List<Arm64Instruction>(input.Length / 4);

        foreach (var instruction in Disassemble(input, virtualAddress, options))
        {
            ret.Add(instruction);
        }

        return ret;
    }

    /// <summary>
    /// Iteratively disassembles instructions in the specified <paramref name="input"/>.
    /// </summary>
    /// <param name="input">The assembly code to disassemble</param>
    /// <param name="virtualAddress">The virtual address of the first instruction, used to get correct values for PC-relative reads/writes/jumps</param>
    /// <param name="options">The disassembly options</param>
    /// <returns>An enumerable which disassembles each instruction in turn as it is enumerated, returning an <see cref="Arm64Instruction"/> for each one.</returns>
    /// <exception cref="Exception">If an undefined instruction is encountered or if an unexpected error occurs, unless <see cref="Options.ContinueOnError"/> is set.</exception>
    public static IEnumerable<Arm64Instruction> Disassemble(byte[] input, ulong virtualAddress, Options? options = null)
    {
        for (var i = 0; i < input.Length; i += 4)
        {
            var rawBytes = input.AsSpan(i, 4);
            yield return DisassembleSingleInstruction(rawBytes, i, virtualAddress, options ?? Options.Default);
        }
    }

    /// <inheritdoc cref="Disassemble(byte[],ulong,System.Nullable{Disarm.Disassembler.Options})"/>
    public static IEnumerable<Arm64Instruction> Disassemble(ReadOnlyMemory<byte> input, ulong virtualAddress, Options? options = null)
    {
        for (var i = 0; i < input.Length; i += 4)
        {
            var rawBytes = input.Slice(i, 4).Span;
            yield return DisassembleSingleInstruction(rawBytes, i, virtualAddress, options ?? Options.Default);
        }
    }

    /// <inheritdoc cref="Disassemble(byte[],ulong,System.Nullable{Disarm.Disassembler.Options})"/>
    public static unsafe IEnumerable<Arm64Instruction> Disassemble(byte* input, int inputLength, ulong virtualAddress, Options? options = null)
    {
        return new NativeMemoryEnumerator(input, inputLength, virtualAddress, options ?? Options.Default);
    }

    private unsafe class NativeMemoryEnumerator : IEnumerable<Arm64Instruction>, IEnumerator<Arm64Instruction>
    {
        private readonly byte* _input;
        private readonly int _inputLength;
        private readonly ulong _virtualAddress;
        private readonly Options _options;

        private int _offset;
        private Arm64Instruction _current;

        internal NativeMemoryEnumerator(byte* input, int inputLength, ulong virtualAddress, Options options)
        {
            _input = input;
            _inputLength = inputLength;
            _virtualAddress = virtualAddress;
            _options = options;
        }

        public bool MoveNext()
        {
            if (_offset < _inputLength)
            {
                _current = DisassembleSingleInstruction(new ReadOnlySpan<byte>(_input + _offset, 4), _offset, _virtualAddress, _options);
                _offset += 4;
                return true;
            }

            _current = default;
            return false;
        }

        public void Reset()
        {
            _offset = 0;
            _current = default;
        }

        public Arm64Instruction Current => _current;
        object IEnumerator.Current => Current;

        public void Dispose()
        {
        }

        public NativeMemoryEnumerator GetEnumerator() => this;
        IEnumerator<Arm64Instruction> IEnumerable<Arm64Instruction>.GetEnumerator() => this;
        IEnumerator IEnumerable.GetEnumerator() => this;
    }

    /// <inheritdoc cref="Disassemble(byte[],ulong,System.Nullable{Disarm.Disassembler.Options})"/>
    public static SpanEnumerator Disassemble(ReadOnlySpan<byte> input, ulong virtualAddress, Options? options = null)
    {
        return new SpanEnumerator(input, virtualAddress, options ?? Options.Default);
    }

    public ref struct SpanEnumerator
    {
        private readonly ReadOnlySpan<byte> _input;
        private readonly ulong _virtualAddress;
        private readonly Options _options;

        private int _offset = 0;
        private Arm64Instruction _current = default;

        internal SpanEnumerator(ReadOnlySpan<byte> input, ulong virtualAddress, Options options)
        {
            _input = input;
            _virtualAddress = virtualAddress;
            _options = options;
        }

        public bool MoveNext()
        {
            if (_offset < _input.Length)
            {
                _current = DisassembleSingleInstruction(_input.Slice(_offset, 4), _offset, _virtualAddress, _options);
                _offset += 4;
                return true;
            }

            _current = default;
            return false;
        }

        public void Reset()
        {
            _offset = 0;
            _current = default;
        }

        public Arm64Instruction Current => _current;

        public void Dispose()
        {
        }

        public SpanEnumerator GetEnumerator() => this;
    }

    private static Arm64Instruction DisassembleSingleInstruction(ReadOnlySpan<byte> rawBytes, int offset, ulong virtualAddress, Options options)
    {
        var rawInstruction = BinaryPrimitives.ReadUInt32LittleEndian(rawBytes);

        Arm64Instruction instruction;

        try
        {
            instruction = DisassembleSingleInstruction(rawInstruction, offset, options.RemapAliases);
            instruction.Address = virtualAddress + (ulong)offset;
        }
        catch (Arm64UndefinedInstructionException e)
        {
            if (!options.ContinueOnError)
                throw new($"Encountered undefined instruction 0x{rawInstruction:X8} at offset {offset}. Undefined reason: {e.Message}", e);

            instruction = new() { Mnemonic = Arm64Mnemonic.INVALID };
        }
        catch (Exception e)
        {
            if (!options.ContinueOnError)
                throw new($"Unhandled and unexpected exception disassembling instruction 0x{rawInstruction:X8} at offset {offset}", e);

            instruction = new() { Mnemonic = Arm64Mnemonic.INVALID };
        }

        if (options.ThrowOnUnimplemented && instruction.Mnemonic == Arm64Mnemonic.UNIMPLEMENTED)
        {
            throw new NotImplementedException($"Encountered an unimplemented instruction belonging to category {instruction.MnemonicCategory}: 0x{rawInstruction:X8} at offset {offset} (0x{offset:X}) (va 0x{virtualAddress + (ulong)offset:X8})");
        }

        return instruction;
    }

    internal static Arm64Instruction DisassembleSingleInstruction(uint instruction, int offset = 0, bool remapAliases = true)
    {
        //Top bit splits into reserved/normal instruction
        var isReserved = instruction >> 31 == 0;

        //Bits 25-28 define the kind of instruction
        var type = (instruction >> 25) & 0b1111;

        if (isReserved && type == 0)
            throw new Arm64UndefinedInstructionException($"Encountered reserved group of instructions");

        if (type is 0b0001 or 0b0011)
            throw new Arm64UndefinedInstructionException($"Unallocated instruction type (bits 25-28 are 0b0001 or 0b0011)");

        var decoded = type switch
        {
            //SME (Scalable Matrix Extension, Arm V9 only)
            0 => throw new($"SME instruction encountered at offset {offset}: 0x{instruction:X} - they are not implemented because Arm V9 is not supported"),

            0b0010 => Arm64Sve.Disassemble(instruction), //SVE (Scalable Vector Extension, ARM v8.2)

            //For these two the last bit is irrelevant here
            0b1000 or 0b1001 => Arm64DataProcessingImmediate.Disassemble(instruction), //Data processing: immediate  
            0b1010 or 0b1011 => DisassembleBranchExceptionSystemInstruction(instruction), //Branches/Exceptions/System instructions

            //Just need to be 0100, ignoring odd bits (X1X0) - so last bit must be 0 and 2nd from left must be 1, other two are irrelevant
            0b1110 or 0b1100 or 0b0110 or 0b0100 => Arm64LoadsStores.Disassemble(instruction), //Loads/Stores 

            //For these two the first bit is irrelevant here
            0b1101 or 0b0101 => Arm64DataProcessingRegister.Disassemble(instruction), //Data processing: register
            _ => Arm64Simd.Disassemble(instruction), //Advanced SIMD data processing
        };

        if (remapAliases)
            Arm64Aliases.CheckForAlias(ref decoded);

        return decoded;
    }

    //These methods are here because some of them are branches but some are various other kinds so we can't really delegate to one class
    private static Arm64Instruction DisassembleBranchExceptionSystemInstruction(uint instruction)
    {
        var op0 = (instruction >> 29) & 0b111; //Bits 29-31
        var op1 = (instruction >> 12) & 0b11_1111_1111_1111; //Bits 12-25

        return op0 switch
        {
            0b010 => Arm64Branches.ConditionalBranchImmediate(instruction), //Conditional branch - immediate
            0b000 or 0b100 => Arm64Branches.UnconditionalBranchImmediate(instruction), //x00 -> unconditional branch, immediate

            //x01 -> compare and branch or test and branch, depending on high bit of op1
            0b001 or 0b101 when op1 >> 13 == 0b1 => Arm64Branches.TestAndBranch(instruction), //Test and branch
            0b001 or 0b101 => Arm64Branches.CompareAndBranch(instruction), //Compare and branch

            0b110 when op1 >> 13 == 0b1 => Arm64Branches.UnconditionalBranchRegister(instruction), //One more category of branches: Unconditional - register
            _ => DisassembleSystemHintExceptionBarrierOrPstate(instruction), //110 without bit 13 set -> system instruction
        };
    }

    /// <summary>
    /// Handles the '110' family of C4.1.65 - Branches, exceptions, and system instructions
    /// </summary>
    private static Arm64Instruction DisassembleSystemHintExceptionBarrierOrPstate(uint instruction)
    {
        var op1 = (instruction >> 12) & 0b11_1111_1111_1111; //Bits 12-25
        var op2 = instruction & 0b1_1111; //Bits 0-4

        //each subcategory has a unique op1 value or mask
        //the Hints subcategory stipulates that op2 should be all 1s - and in fact is the only use of op2. Seems a little redundant.

        //Bit 13 of op1 has to be 0 or we'd have gone to an "unconditional branch - register"
        //Bit 12 being 0 means exceptions
        if (op1 >> 12 == 0)
            return Arm64ExceptionGeneration.Disassemble(instruction);

        //A couple other masked values to get out of the way:
        var upperHalf = op1 >> 7 & 0b1111111;

        if (upperHalf == 0b010_0000 && (op1 & 0b1111) == 0b0100)
            //Pstate
            return Arm64Pstate.Disassemble(instruction);

        if (upperHalf == 0b010_0100)
            //System, with result
            return Arm64System.WithResult(instruction);

        if (upperHalf is 0b0100001 or 0b0100101)
            //General system
            return Arm64System.General(instruction);

        //Discard last bit of upperHalf
        upperHalf >>= 1;

        if (upperHalf is 0b010001 or 0b010011)
            return Arm64System.RegisterMove(instruction);

        //Now just switch
        return op1 switch
        {
            0b01000000110001 => Arm64System.WithRegisterArgument(instruction),
            0b01000000110010 when op2 != 0b11111 => throw new Arm64UndefinedInstructionException($"Hint instructions require op2 to be all 1s. Got {op2:X}"),
            0b01000000110010 => Arm64Hints.Disassemble(instruction),
            0b01000000110011 => Arm64Barriers.Disassemble(instruction),
            _ => throw new Arm64UndefinedInstructionException($"Undefined op1 in system instruction processor: {op1:X}")
        };
    }
}
