namespace netcracker;

class Crypto
{
    public string Kdf { get; set; }
    public KdfParams KdfParams { get; set; }
    public string Cipher { get; set; }
    public string CipherText { get; set; }
    public string Mac { get; set; }
}