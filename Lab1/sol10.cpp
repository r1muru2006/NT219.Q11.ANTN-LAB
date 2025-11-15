#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <bits/stdc++.h>

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;
using std::runtime_error;

static vector<byte> to_bytes(const string& s) {
    return vector<byte>(s.begin(), s.end());
}

static string to_string(const vector<byte>& v) {
    return string(v.begin(), v.end());
}

static string hex_encode(const vector<byte>& v) {
    string out;
    StringSource ss(v.data(), v.size(), true, new HexEncoder(new StringSink(out), false));
    return out;
}

void cbc_bitflip_attack(
    vector<byte>& ciphertext,
    vector<byte>& iv,
    size_t target_index,
    byte old_byte,
    byte new_byte
) {
    const size_t B = DES::BLOCKSIZE;
    size_t block_num = target_index / B;
    size_t offset = target_index % B;
    byte delta = old_byte ^ new_byte;

    if (block_num == 0) {
        iv[offset] ^= delta;
        cout << "[+] Tampering IV at index " << offset << endl;
    } else {
        size_t tamper_index = (block_num - 1) * B + offset;
        ciphertext[tamper_index] ^= delta;
        cout << "[+] Tampering Ciphertext block C[" << block_num - 1 << "] at index " << tamper_index << endl;
    }
}

int main() {
    AutoSeededRandomPool prng;
    SecByteBlock key(DES::DEFAULT_KEYLENGTH);
    SecByteBlock iv_sbb(DES::BLOCKSIZE);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv_sbb, iv_sbb.size());
    vector<byte> iv(iv_sbb.begin(), iv_sbb.end());

    string plain = "can_you_change_admin=0_to_another_one";
    string cipher_str;
    CBC_Mode<DES>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv.data());
    StringSource ss1(plain, true,
        new StreamTransformationFilter(enc, new StringSink(cipher_str), StreamTransformationFilter::PKCS_PADDING)
    );
    vector<byte> ciphertext = to_bytes(cipher_str);

    cout << "=== ORIGINAL DATA ===" << endl;
    cout << "Plaintext : " << plain << endl;
    cout << "IV (hex)  : " << hex_encode(iv) << endl;
    cout << "Cipher(hex): " << hex_encode(ciphertext) << endl;

    const string target_str = "admin=0";
    size_t pos = plain.find(target_str);
    if (pos == string::npos) throw runtime_error("Target string not found in plaintext.");
    
    size_t target_index = pos + target_str.length() - 1;
    byte old_byte = '0';
    byte new_byte = '1';

    cout << "\n=== PERFORMING ATTACK ===" << endl;
    cout << "Target : Change '" << (char)old_byte << "' to '" << (char)new_byte << "' at plaintext index " << target_index << endl;

    vector<byte> tampered_ciphertext = ciphertext;
    vector<byte> tampered_iv = iv;
    cbc_bitflip_attack(tampered_ciphertext, tampered_iv, target_index, old_byte, new_byte);
    
    cout << "\n=== TAMPERED DATA ===" << endl;
    cout << "New IV(hex)  : " << hex_encode(tampered_iv) << endl;
    cout << "New Ciphertext(hex): " << hex_encode(tampered_ciphertext) << endl;

    string recovered_str;
    CBC_Mode<DES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), tampered_iv.data());
    StringSource ss2(tampered_ciphertext.data(), tampered_ciphertext.size(), true,
        new StreamTransformationFilter(dec, new StringSink(recovered_str), StreamTransformationFilter::PKCS_PADDING)
    );
    
    cout << "\n=== DECRYPTION RESULT ON SERVER SIDE ===" << endl;
    cout << "Recovered Plaintext: " << recovered_str << endl;

    return 0;
}