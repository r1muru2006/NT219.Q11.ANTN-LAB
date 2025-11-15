#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <bits/stdc++.h>
#include <codecvt>

using namespace CryptoPP;
using namespace std;

int main() {
    cout << "Bai 3: \n";
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string encodedKey, encodedIV;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encodedKey)));
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));
    cout << "Key: " << encodedKey << "\nIV: " << encodedIV << '\n';
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> convert;
    string input;
    cout << "Nhap plaintext (ví dụ Hello world 🌏🤭🌏): ";
    getline(cin, input);  // đọc UTF-8

    u16string u16_plain = convert.from_bytes(input);
    string plain(reinterpret_cast<const char*>(u16_plain.data()), u16_plain.size() * sizeof(char16_t));
    cout << "Plaintext size (bytes): " << plain.size() << endl;

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    string cipher, cipher_hex;
    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    StringSource(cipher, true, new HexEncoder(new StringSink(cipher_hex)));
    cout << "Ciphertext (hex): " << cipher_hex << endl;

    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);
    string recovered;
    StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
    u16string u16_recovered(reinterpret_cast<const char16_t*>(recovered.data()), recovered.size() / sizeof(char16_t));
    recovered = convert.to_bytes(u16_recovered);
    cout << "Recovered: " << recovered << endl;
    return 0;
}
