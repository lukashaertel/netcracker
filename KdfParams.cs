namespace netcracker;

class KdfParams
{
    public int N { get; set; }
    public int R { get; set; }
    public int P { get; set; }
    public int DkLen { get; set; }
    public string Salt { get; set; }
}