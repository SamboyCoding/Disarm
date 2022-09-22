namespace Disarm;

public enum Arm64OperandKind
{
    /// <summary>
    /// There is no operand in this slot.
    /// </summary>
    None,
    /// <summary>
    /// The operand in this slot is a register.
    /// <br/>
    /// The OpXReg property is relevant in this scenario.
    /// </summary>
    Register,
    /// <summary>
    /// The operand in this slot is an element of a vector register (e.g. V6.D[1]).
    /// <br/>
    /// The OpXReg and OpXVectorElement properties are relevant in this scenario.
    /// </summary>
    VectorRegisterElement,
    /// <summary>
    /// The operand in this slot is a raw immediate value.
    /// <br/>
    /// The OpXImm property is relevant in this scenario.
    /// </summary>
    Immediate,
    /// <summary>
    /// The operand in this slot is an immediate value but it is intended to be added to the PC (<see cref="Arm64Instruction.Address"/>). Bear in mind the immediate can be negative
    /// <br/>
    /// The OpXImm property is relevant in this scenario.
    /// </summary>
    ImmediatePcRelative,
    /// <summary>
    /// The operand in this slot is a memory operand. Use the <see cref="Arm64Instruction.MemBase"/>, <see cref="Arm64Instruction.MemOffset"/>, and <see cref="Arm64Instruction.MemIsPreIndexed"/> properties to access the operand.
    /// </summary>
    Memory
}
