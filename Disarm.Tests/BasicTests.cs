using Xunit.Abstractions;

namespace Disarm.Tests;

public class BasicTests : BaseDisarmTest
{
    public BasicTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestDisassembleEntireBody()
    {
        var result = Disassembler.DisassembleOnDemand(TestBodies.IncludesPcRelAddressing, 0);

        foreach (var instruction in result)
        {
            OutputHelper.WriteLine(instruction.ToString());
        }
    }

    [Fact]
    public void TestLongerBody()
    {
        var result = Disassembler.DisassembleOnDemand(TestBodies.HasABadBitMask, 0);

        foreach (var instruction in result)
        {
            OutputHelper.WriteLine(instruction.ToString());
        }
    }
}
