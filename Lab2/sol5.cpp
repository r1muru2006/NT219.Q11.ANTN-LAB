#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
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

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    CryptoPP::byte iv[AES::BLOCKSIZE];
    string keyHex, ivHex;
    cout <<"Enter key (in hex): "; cin >> keyHex;
    cout<<"Enter IV (in hex): "; cin >> ivHex;
    StringSource(keyHex, true, new HexDecoder(new ArraySink(key, sizeof(key))));
    StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, sizeof(iv))));
    cout << "Plaintext (hex): " << plain_hex << '\n';
    cout << "Key: " << keyHex << "\nIV: " << ivHex << '\n';

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    string cipher, cipher_hex;
    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    StringSource(cipher, true, new HexEncoder(new StringSink(cipher_hex)));
    cout << "Ciphertext (text): " << cipher << " (hex): " << cipher_hex << '\n';

    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    string recovered, recovered_hex;
    StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
    StringSource(recovered, true, new HexEncoder(new StringSink(recovered_hex)));
    cout << "Recovered (text): " << recovered << " (hex): " << recovered_hex;
    
    return 0;
}
