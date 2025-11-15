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
    cout << "Bai 2+3: \n";
    AutoSeededRandomPool prng;
    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::byte iv[DES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string encodedKey, encodedIV;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(encodedKey)));
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encodedIV)));

    cout << "Key: " << encodedKey << endl;
    cout << "IV : " << encodedIV << endl;

    string plain = "This is my homework in Lab 1";
    string cipher;

    CBC_Mode<DES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));

    string encodedCipher;
    StringSource(cipher, true, new HexEncoder(new StringSink(encodedCipher)));
    cout << "Plaintext: " << plain << endl;
    cout << "Ciphertext (hex): " << encodedCipher << endl;
    
    vector<unsigned char> cipherVec(cipher.begin(), cipher.end());
    
    DES::Decryption d;
    d.SetKey(key, key.size());

    vector<unsigned char> prev_block(iv, iv + DES::BLOCKSIZE);
    string recovered;

    for (size_t i = 0; i < cipherVec.size(); i += DES::BLOCKSIZE) {
        unsigned char current_block[DES::BLOCKSIZE];
        memcpy(current_block, cipherVec.data() + i, DES::BLOCKSIZE);
        cout << "\nBLOCK " << (i / DES::BLOCKSIZE) + 1 << endl;
        
        string current_block_hex;
        StringSource(current_block, DES::BLOCKSIZE, true, new HexEncoder(new StringSink(current_block_hex)));
        cout << "Cipher block " << (i / DES::BLOCKSIZE) + 1 << ": " << current_block_hex << endl;

        vector<unsigned char> original_cipher_block(current_block, current_block + DES::BLOCKSIZE);
        d.ProcessBlock(current_block);

        current_block_hex.clear();
        StringSource(current_block, DES::BLOCKSIZE, true, new HexEncoder(new StringSink(current_block_hex)));
        cout << "Sau decrypt: " << current_block_hex << endl;

        for (size_t j = 0; j < DES::BLOCKSIZE; j++)
            current_block[j] ^= prev_block[j];

        current_block_hex.clear();
        StringSource(current_block, DES::BLOCKSIZE, true, new HexEncoder(new StringSink(current_block_hex)));
        cout << "Sau XOR voi khoi truoc: "<< current_block_hex << endl;

        recovered.append((char*)current_block, DES::BLOCKSIZE);
        prev_block = original_cipher_block;
    }
    size_t padLen = recovered.back();
    recovered.resize(recovered.size() - padLen);
    cout << "Recovered plaintext: " << recovered;
    
    return 0;
}