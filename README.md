## Arc.Crypto
C# library of hash functions (XXHash, FarmHash, SHA).



## Quick Start

```
Install-Package Arc.Crypto
```

Sample code

```csharp
using Arc.Crypto;
```

```csharp
var data = new byte[100];
ulong hash64;
uint hash32;
byte[] array;

hash64 = Arc.Crypto.FarmHash.Hash64(data.AsSpan()); // The fastest and best algorithm.
hash64 = Arc.Crypto.XXHash64.Hash64(data.AsSpan()); // As fast as FarmHash.
hash32 = Arc.Crypto.FarmHash.Hash32(data.AsSpan()); // 32 bit version is slower than 64 bit version.
hash32 = Arc.Crypto.XXHash32.Hash32(data.AsSpan()); // Same as above.
hash32 = unchecked((uint)Arc.Crypto.FarmHash.Hash64(data.AsSpan())); // I recommend getting 64 bit and discarding half.
hash32 = Arc.Crypto.Adler32.Hash32(data.AsSpan()); // Slow
hash32 = Arc.Crypto.CRC32.Hash32(data.AsSpan()); // Slowest

// IHash is an interface to get a hash of large data.
// For XXHash64, IHash version is a bit slower than static method version.
// For FarmHash64, IHash version is twice as slow. XXHash64 is recommended.
var ihash = new Arc.Crypto.XXHash64();
ihash.HashInitialize();
ihash.HashUpdate(data);
Assert.True(ihash.HashFinal().SequenceEqual(ihash.GetHash(data)));

// Secure Hash Algorithm (SHA1, SHA2, SHA3 supported)
var sha3_512 = new Arc.Crypto.SHA3_512();
array = sha3_512.GetHash(data.AsSpan());

sha3_512.HashInitialize(); // Another way
sha3_512.HashUpdate(data.AsSpan());
Assert.True(sha3_512.HashFinal().SequenceEqual(array));
```


