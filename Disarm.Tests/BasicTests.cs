using Xunit.Abstractions;

namespace Disarm.Tests;

public class BasicTests
{
    private readonly ITestOutputHelper _testOutputHelper;

    public BasicTests(ITestOutputHelper testOutputHelper)
    {
        _testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void TestDisassembleEntireBody()
    {
        var result = Disassembler.DisassembleOnDemand(TestBodies.IncludesPcRelAddressing, 0);

        foreach (var instruction in result)
        {
            _testOutputHelper.WriteLine(instruction.ToString());
        }
    }

    [Fact]
    public void TestLongerBody()
    {
        var result = Disassembler.DisassembleOnDemand(TestBodies.HasABadBitMask, 0);

        foreach (var instruction in result)
        {
            _testOutputHelper.WriteLine(instruction.ToString());
        }
    }
}
