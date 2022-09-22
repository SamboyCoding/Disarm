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
    public void LongTestForProfile()
    {
        var body = Enumerable.Repeat(TestBodies.CaGenBody, 1000000).SelectMany(b => b).ToArray();

        var result = Disassembler.Disassemble(body, 0);
        
        Assert.Equal(body.Length / 4, result.Instructions.Count);
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
