namespace Disarm;

public readonly struct Arm64VectorElement
{
    public readonly Arm64VectorElementWidth Width;
    public readonly int Index;
    
    public Arm64VectorElement(Arm64VectorElementWidth width, int index)
    {
        Width = width;
        Index = index;
    }

    public override string ToString()
    {
        return $"{Width}[{Index}]";
    }
}