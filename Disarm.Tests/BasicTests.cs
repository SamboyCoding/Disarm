using Xunit.Abstractions;

namespace Disarm.Tests;

public class BasicTests : BaseDisarmTest
{
    public BasicTests(ITestOutputHelper testOutputHelper) : base(testOutputHelper) { }

    [Fact]
    public void TestDisassembleEntireBody()
    {
        var result = Disassembler.Disassemble(TestBodies.IncludesPcRelAddressing, 0);

        foreach (var instruction in result)
        {
            OutputHelper.WriteLine(instruction.ToString());
        }
    }

    [Fact]
    public void TestLongerBody()
    {
        var result = Disassembler.Disassemble(TestBodies.HasABadBitMask, 0);

        foreach (var instruction in result)
        {
            OutputHelper.WriteLine(instruction.ToString());
        }
    }

    [Fact]
    public unsafe void TestOverloads()
    {
        byte[] byteArray = TestBodies.HasABadBitMask;
        ReadOnlySpan<byte> span = byteArray;
        ReadOnlyMemory<byte> memory = byteArray;
        fixed (byte* bytePointer = byteArray)
        {
            using var byteArrayEnumerator = Disassembler.Disassemble(byteArray, 0).GetEnumerator();
            using var spanEnumerator = Disassembler.Disassemble(span, 0).GetEnumerator();
            using var spanListEnumerator = Disassembler.Disassemble(span, 0, out _).GetEnumerator();
            using var memoryEnumerator = Disassembler.Disassemble(memory, 0).GetEnumerator();
            using var bytePointerEnumerator = Disassembler.Disassemble(bytePointer, byteArray.Length, 0).GetEnumerator();

            while (byteArrayEnumerator.MoveNext())
            {
                Assert.True(spanEnumerator.MoveNext());
                Assert.True(spanListEnumerator.MoveNext());
                Assert.True(memoryEnumerator.MoveNext());
                Assert.True(bytePointerEnumerator.MoveNext());
                
                var expected = byteArrayEnumerator.Current;
                Assert.Equal(expected, spanEnumerator.Current);
                Assert.Equal(expected, spanListEnumerator.Current);
                Assert.Equal(expected, memoryEnumerator.Current);
                Assert.Equal(expected, bytePointerEnumerator.Current);
            }
            
            Assert.False(spanEnumerator.MoveNext());
            Assert.False(spanListEnumerator.MoveNext());
            Assert.False(memoryEnumerator.MoveNext());
            Assert.False(bytePointerEnumerator.MoveNext());
        }
    }
}
