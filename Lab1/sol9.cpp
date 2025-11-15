#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <bits/stdc++.h>

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;
using std::runtime_error;

bool is_likely_english_text(const string& text) {
    if (text.empty()) return false;
    int printable_chars = 0;
    for (char c : text) {
        if (isprint(static_cast<unsigned char>(c)) || isspace(static_cast<unsigned char>(c))) {
            printable_chars++;
        }
    }
    return (static_cast<double>(printable_chars) / text.length()) > 0.9;
}


void build_des_key(unsigned long long k, SecByteBlock& key) {
    key.resize(DES::DEFAULT_KEYLENGTH);
    for (int i = 0; i < 8; ++i) {
        key[i] = (k >> (i * 8)) & 0xFF;
    }
}


int main() {
    cout << "Bai 9: \n";
    string plain, plain_hex;
    cout <<"Enter Plaintext: ";
    getline(cin, plain);
    StringSource(plain, true, new HexEncoder(new StringSink(plain_hex)));
    cout << "Plaintext (hex): " << plain_hex << '\n';

    AutoSeededRandomPool prng;

    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());
    CryptoPP::byte iv[DES::BLOCKSIZE];
    string ivHex = "AC45B01CF62D8285";
    StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, sizeof(iv))));

    CBC_Mode<DES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    string cipher, cipher_hex;
    StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    StringSource(cipher, true, new HexEncoder(new StringSink(cipher_hex)));
    cout << "Ciphertext (text): " << cipher << " (hex): " << cipher_hex << '\n';

    // Starting Brute-Force
    SecByteBlock candidate_key(DES::DEFAULT_KEYLENGTH);
    string decrypted_text;
        string secret_plaintext = "This is a long and fixed secret message used for transactions.";
        string iv_hex = "0123456789ABCDEF";

        // Khóa bí mật (chọn giá trị nhỏ để demo tấn công thành công nhanh chóng)
        unsigned long long secret_key_val = 9999;
        SecByteBlock secret_key;
        build_des_key(secret_key_val, secret_key);
        
        byte iv[DES::BLOCKSIZE];
        StringSource(iv_hex, true, new HexDecoder(new ArraySink(iv, sizeof(iv))));

        // Kẻ tấn công thu được bản mã này
        string target_ciphertext;
        CBC_Mode<DES>::Encryption enc;
        enc.SetKeyWithIV(secret_key, secret_key.size(), iv);
        StringSource(secret_plaintext, true, new StreamTransformationFilter(enc, new StringSink(target_ciphertext)));

        cout << "\n--- Attacker has obtained the following data ---" << endl;
        string cipher_hex;
        StringSource(target_ciphertext, true, new HexEncoder(new StringSink(cipher_hex)));
        cout << "Ciphertext (hex): " << cipher_hex << endl;
        cout << "IV (hex)        : " << iv_hex << endl;

        // --- PHẦN 2: TẤN CÔNG ---
        cout << "\n--- Brute-Force Attack Started ---" << endl;

        SecByteBlock candidate_key(DES::DEFAULT_KEYLENGTH);
        string decrypted_text;

        // Vòng lặp duyệt qua không gian khóa.
        // Trong thực tế sẽ chạy đến 2^56, ở đây chỉ cần chạy qua giá trị của khóa bí mật.
        for (unsigned long long k = 0; k <= secret_key_val + 5; ++k) {
            
            build_des_key(k, candidate_key);
            string first_blocks = target_ciphertext.substr(0, 2 * DES::BLOCKSIZE);
            decrypted_text.clear();

            CBC_Mode<DES>::Decryption dec;
            dec.SetKeyWithIV(candidate_key, candidate_key.size(), iv);
            StringSource ss(first_blocks, true,
                            new StreamTransformationFilter(dec, new StringSink(decrypted_text), StreamTransformationFilter::NO_PADDING)
            );
            
            // Sử dụng "Oracle Offline" để kiểm tra
            if (is_likely_english_text(decrypted_text)) {
                cout << "\n[SUCCESS] Found potential key at k = " << k << endl;
                
                // Giải mã toàn bộ bản mã với khóa tìm được để xác nhận
                string full_plaintext;
                CBC_Mode<DES>::Decryption final_dec;
                final_dec.SetKeyWithIV(candidate_key, candidate_key.size(), iv);
                StringSource final_ss(target_ciphertext, true, new StreamTransformationFilter(final_dec, new StringSink(full_plaintext)));

                cout << "  -> Full decrypted plaintext: " << full_plaintext << endl;
                }
            }

    return 0;
}
