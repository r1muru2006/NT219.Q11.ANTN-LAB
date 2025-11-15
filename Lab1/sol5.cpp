#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <bits/stdc++.h>

using namespace CryptoPP;
using namespace std;

int main() {
    cout << "Bai 5: \n";
    string plain, plain_hex;
    cout <<"Enter Plaintext: ";
    getline(cin, plain);
    StringSource(plain, true, new HexEncoder(new StringSink(plain_hex)));
    cout << "Plaintext (hex): " << plain_hex << '\n';

    AutoSeededRandomPool prng;

    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::byte iv[DES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string encodedKey, encodedIV;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encodedKey)));
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));
    cout << "Key: " << encodedKey << "\nIV: " << encodedIV << '\n';

    CBC_Mode<DES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    string cipher, cipher_hex;
    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    StringSource(cipher, true, new HexEncoder(new StringSink(cipher_hex)));
    cout << "Ciphertext (text): " << cipher << " (hex): " << cipher_hex << '\n';

    CBC_Mode<DES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    string recovered, recovered_hex;
    StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
    StringSource(recovered, true, new HexEncoder(new StringSink(recovered_hex)));
    cout << "Recovered (text): " << recovered << " (hex): " << recovered_hex;
    
    return 0;
}
