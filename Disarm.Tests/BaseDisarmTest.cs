using Xunit.Abstractions;

namespace Disarm.Tests;

public abstract class BaseDisarmTest
{
    protected ITestOutputHelper OutputHelper;

    protected BaseDisarmTest(ITestOutputHelper outputHelper)
    {
        OutputHelper = outputHelper;
    }

    protected Arm64Instruction DisassembleAndCheckMnemonic(uint raw, Arm64Mnemonic mnemonic)
    {
        var instruction = Disassembler.DisassembleSingleInstruction(raw);
        OutputHelper.WriteLine(instruction.ToString());
        Assert.Equal(mnemonic, instruction.Mnemonic);
        return instruction;
    }
}