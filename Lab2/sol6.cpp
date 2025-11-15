// aes_modes_demo.cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/xts.h>

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using namespace CryptoPP;
using namespace std;

static vector<CryptoPP::byte> hexToBytes(const string &hex) {
    string decoded;
    StringSource(hex, true, new HexDecoder(new StringSink(decoded)));
    return vector<CryptoPP::byte>(decoded.begin(), decoded.end());
}

static string bytesToHex(const vector<CryptoPP::byte> &v) {
    string out;
    StringSource(v.data(), v.size(), true, new HexEncoder(new StringSink(out)));
    return out;
}

static string bytesToText(const vector<CryptoPP::byte> &v) {
    return string(v.begin(), v.end());
}

static vector<CryptoPP::byte> textToBytes(const string &s) {
    return vector<CryptoPP::byte>(s.begin(), s.end());
}

int main() {
    cout << "AES modes demo (ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM)\n";

    string plain;
    cout << "Enter Plaintext: ";
    getline(cin, plain);

    string keyHex, ivHex;
    cout << "Enter key (in hex): ";
    getline(cin, keyHex);
    cout << "Enter IV / Tweak (in hex) (press Enter to use zeros): ";
    getline(cin, ivHex);

    vector<CryptoPP::byte> keyv = hexToBytes(keyHex);
    vector<CryptoPP::byte> ivv = ivHex.empty() ? vector<CryptoPP::byte>(AES::BLOCKSIZE, 0) : hexToBytes(ivHex);
    vector<CryptoPP::byte> plainv = textToBytes(plain);

    auto print_result = [&](const string &mode,
                            const vector<CryptoPP::byte> &cipher,
                            const vector<CryptoPP::byte> &recovered,
                            const vector<CryptoPP::byte> &tag = {}) {
        cout << "\n--- " << mode << " ---\n";
        cout << "Ciphertext (hex): " << bytesToHex(cipher) << "\n";
        if (!tag.empty())
            cout << "Auth Tag (hex):   " << bytesToHex(tag) << "\n";
        cout << "Recovered text:   " << bytesToText(recovered) << "\n";
    };

    // 1) ECB
    {
        vector<CryptoPP::byte> cipher, recovered;
        ECB_Mode<AES>::Encryption enc;
        SecByteBlock key(keyv.data(), keyv.size());
        enc.SetKey(key, key.size());
        StringSource(plainv.data(), plainv.size(), true,
            new StreamTransformationFilter(enc, new VectorSink(cipher)));
        // decrypt
        ECB_Mode<AES>::Decryption dec;
        dec.SetKey(key, key.size());
        StringSource(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(recovered)));
        print_result("ECB", cipher, recovered);
    }

    // 2) CBC
    if (ivv.size() < AES::BLOCKSIZE) ivv.resize(AES::BLOCKSIZE, 0);
    {
        vector<CryptoPP::byte> cipher, recovered;
        CBC_Mode<AES>::Encryption enc;
        SecByteBlock key(keyv.data(), keyv.size());
        CryptoPP::byte iv[AES::BLOCKSIZE];
        memcpy(iv, ivv.data(), AES::BLOCKSIZE);
        enc.SetKeyWithIV(key, key.size(), iv);
        StringSource(plainv.data(), plainv.size(), true,
            new StreamTransformationFilter(enc, new VectorSink(cipher)));
        // decrypt
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);
        StringSource(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(recovered)));
        print_result("CBC", cipher, recovered);
    }

    // 3) OFB
    if (ivv.size() < AES::BLOCKSIZE) ivv.resize(AES::BLOCKSIZE, 0);
    {
        vector<CryptoPP::byte> cipher, recovered;
        OFB_Mode<AES>::Encryption enc;
        SecByteBlock key(keyv.data(), keyv.size());
        CryptoPP::byte iv[AES::BLOCKSIZE]; memcpy(iv, ivv.data(), AES::BLOCKSIZE);
        enc.SetKeyWithIV(key, key.size(), iv);
        StringSource(plainv.data(), plainv.size(), true,
            new StreamTransformationFilter(enc, new VectorSink(cipher)));
        // OFB decrypt is same as encrypt
        OFB_Mode<AES>::Encryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);
        StringSource(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(recovered)));
        print_result("OFB", cipher, recovered);
    }

    // 4) CFB
    if (ivv.size() < AES::BLOCKSIZE) ivv.resize(AES::BLOCKSIZE, 0);
    {
        vector<CryptoPP::byte> cipher, recovered;
        CFB_Mode<AES>::Encryption enc;
        SecByteBlock key(keyv.data(), keyv.size());
        CryptoPP::byte iv[AES::BLOCKSIZE]; memcpy(iv, ivv.data(), AES::BLOCKSIZE);
        enc.SetKeyWithIV(key, key.size(), iv);
        StringSource(plainv.data(), plainv.size(), true,
            new StreamTransformationFilter(enc, new VectorSink(cipher)));
        // decrypt
        CFB_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);
        StringSource(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(recovered)));
        print_result("CFB", cipher, recovered);
    }

    // 5) CTR
    if (ivv.size() < AES::BLOCKSIZE) ivv.resize(AES::BLOCKSIZE, 0);
    {
        vector<CryptoPP::byte> cipher, recovered;
        CTR_Mode<AES>::Encryption enc;
        SecByteBlock key(keyv.data(), keyv.size());
        CryptoPP::byte iv[AES::BLOCKSIZE]; memcpy(iv, ivv.data(), AES::BLOCKSIZE);
        enc.SetKeyWithIV(key, key.size(), iv);
        StringSource(plainv.data(), plainv.size(), true,
            new StreamTransformationFilter(enc, new VectorSink(cipher)));
        // decrypt (same as encrypt)
        CTR_Mode<AES>::Encryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);
        StringSource(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(recovered)));
        print_result("CTR", cipher, recovered);
    }

    // 6) XTS
    {
        // XTS requires 2x key. If provided key is single, duplicate it.
        vector<CryptoPP::byte> xtsKey = keyv;
        if (xtsKey.size() == AES::DEFAULT_KEYLENGTH) {
            xtsKey.insert(xtsKey.end(), keyv.begin(), keyv.end()); // duplicate
        }
        if (xtsKey.size() < 2 * AES::DEFAULT_KEYLENGTH) {
            // pad zeros if still short
            xtsKey.resize(2 * AES::DEFAULT_KEYLENGTH, 0);
        }
        vector<CryptoPP::byte> cipher, recovered;
        SecByteBlock keyXTS(xtsKey.data(), xtsKey.size());

        XTS_Mode<AES>::Encryption enc;
        // tweak (16 CryptoPP::bytes)
        SecByteBlock tweak(AES::BLOCKSIZE);
        if (ivv.size() >= AES::BLOCKSIZE) memcpy(tweak, ivv.data(), AES::BLOCKSIZE);
        else memset(tweak, 0, AES::BLOCKSIZE);
        enc.SetKeyWithIV(keyXTS, keyXTS.size(), tweak);
        StringSource(plainv.data(), plainv.size(), true,
            new StreamTransformationFilter(enc, new VectorSink(cipher)));
        // decrypt
        XTS_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(keyXTS, keyXTS.size(), tweak);
        StringSource(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(recovered)));
        print_result("XTS", cipher, recovered);
    }

    // 7) CCM (AEAD) - use AuthenticatedEncryptionFilter / AuthenticatedDecryptionFilter
    {
        vector<CryptoPP::byte> cipherAndTag, recovered;
        // choose tag size 16
        const unsigned int TAG_SIZE = 16;
        CCM<AES, TAG_SIZE>::Encryption enc;
        SecByteBlock keyC(keyv.data(), keyv.size());
        // CCM requires nonce (IV) length typically 7..13; Crypto++ allows any but set to ivv.size()
        if (ivv.size() == 0) ivv.assign(12, 0); // default nonce length 12
        enc.SetKeyWithIV(keyC, keyC.size(), ivv.data(), ivv.size());
        // no associated data in this demo
        AuthenticatedEncryptionFilter ef(enc, new VectorSink(cipherAndTag), 0, TAG_SIZE);
        ef.ChannelPut(nullptr, plainv.data(), plainv.size());
        ef.ChannelMessageEnd(nullptr);

        // separate ciphertext and tag for printing
        size_t csize = cipherAndTag.size() - TAG_SIZE;
        vector<CryptoPP::byte> cipher(cipherAndTag.begin(), cipherAndTag.begin() + csize);
        vector<CryptoPP::byte> tag(cipherAndTag.begin() + csize, cipherAndTag.end());

        // decrypt
        CCM<AES, TAG_SIZE>::Decryption dec;
        SecByteBlock keyD(keyv.data(), keyv.size());
        dec.SetKeyWithIV(keyD, keyD.size(), ivv.data(), ivv.size());
        AuthenticatedDecryptionFilter df(dec, new VectorSink(recovered), 0);
        df.ChannelPut(nullptr, cipherAndTag.data(), cipherAndTag.size());
        df.ChannelMessageEnd(nullptr);

        print_result("CCM", cipher, recovered, tag);
    }

    // 8) GCM (AEAD)
    {
        vector<CryptoPP::byte> cipherAndTag, recovered;
        const unsigned int TAG_SIZE = 16;
        GCM<AES>::Encryption enc;
        SecByteBlock keyG(keyv.data(), keyv.size());
        if (ivv.size() == 0) ivv.assign(12, 0);
        enc.SetKeyWithIV(keyG, keyG.size(), ivv.data(), ivv.size());
        AuthenticatedEncryptionFilter ef(enc, new VectorSink(cipherAndTag), 0, TAG_SIZE);
        ef.ChannelPut(nullptr, plainv.data(), plainv.size());
        ef.ChannelMessageEnd(nullptr);

        size_t csize = cipherAndTag.size() - TAG_SIZE;
        vector<CryptoPP::byte> cipher(cipherAndTag.begin(), cipherAndTag.begin() + csize);
        vector<CryptoPP::byte> tag(cipherAndTag.begin() + csize, cipherAndTag.end());

        // decrypt
        GCM<AES>::Decryption dec;
        SecByteBlock keyD(keyv.data(), keyv.size());
        dec.SetKeyWithIV(keyD, keyD.size(), ivv.data(), ivv.size());
        AuthenticatedDecryptionFilter df(dec, new VectorSink(recovered), 0);
        df.ChannelPut(nullptr, cipherAndTag.data(), cipherAndTag.size());
        df.ChannelMessageEnd(nullptr);

        print_result("GCM", cipher, recovered, tag);
    }

    cout << "\nDone.\n";
    return 0;
}
