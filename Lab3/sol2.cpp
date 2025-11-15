#include "bigint.h"
#include "genRSAkey.h"

using namespace std;

int hexCharToInt(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return 0; 
}

bigint hexToBigint(string hex) {
    bigint res = bigint(0);
    bigint pow16 = bigint(1);

    for (int i = hex.length() - 1; i >= 0; i--) {
        int digit = hexCharToInt(hex[i]);
        res += (bigint(digit) * pow16);
        pow16 *= 16;
    }
    
    return res;
}


int main() {
    bigint p1 = 11, q1 = 17, e1 = 7;
    bigint p2("20079993872842322116151219"), q2("676717145751736242170789"), e2 = 17;
    bigint p3 = hexToBigint("F7E75FDC469067FFDC4E847C51F452DF"), q3 = hexToBigint("E85CED54AF57E53E092113E62F436F4F"), e3 = hexToBigint("0D88C3");
    
    cout << "Here is the RSA Key Pairs generated for (p, q, e) = (11, 17, 7): \n";
    vector<pair<bigint, bigint>> RSA_key1 = create_RSA_key(p1, q1, e1);
    cout << "Public Key: (" << RSA_key1[0].first << ", " << RSA_key1[0].second << ")\n";
    cout << "Private Key: (" << RSA_key1[1].first << ", " << RSA_key1[1].second << ")\n";

    cout << "\nHere is the RSA Key Pairs generated for (p, q, e) = (20079993872842322116151219, 676717145751736242170789, 17): \n";
    vector<pair<bigint, bigint>> RSA_key2 = create_RSA_key(p2, q2, e2);
    cout << "Public Key: (" << RSA_key2[0].first << ", "  << RSA_key2[0].second << ")\n";
    cout << "Private Key: (" << RSA_key2[1].first << ", " << RSA_key2[1].second << ")\n";

    cout << "\nHere is the RSA Key Pairs generated for (p, q, e) = (" << p3 << ", " << q3 << ", " << e3 << "): \n";
    vector<pair<bigint, bigint>> RSA_key3 = create_RSA_key(p3, q3, e3);
    cout << "Public Key: (" << RSA_key3[0].first << ", "  << RSA_key3[0].second << ")\n";
    cout << "Private Key: (" << RSA_key3[1].first << ", "  << RSA_key3[1].second << ")\n";

    bigint M = 5, n = RSA_key1[0].second, e = RSA_key1[0].first, d = RSA_key1[1].first;

    // CASE 1: CONFIDENTIALITY
    // - A use Public Key (e, n) to encrypt
    // - B use Private Key (d, n) to decrypt
    cout << "\n\nSTARTING ENCRYPTION PROCESS:\n";
    bigint C = big_pow(M, e) % n;
    cout << "A sends B the encrypted message: " << C << '\n';
    bigint M_dec = big_pow(C, d) % n;
    cout << "B decrypts the message and gets: " << M_dec << '\n';
    assert(M == M_dec);
    cout << "DECRYPTED SUCCESSFULLY!!!\n\n";

    // CASE 2: AUTHENTICATION
    // - A use Private Key (d, n) to signing
    // - B use Public Key (e, n) to verifying
    cout << "STARTING AUTHENTICATION PROCESS:\n";
    bigint S = big_pow(M, d) % n;
    cout << "A signs the message and sends B: " << S << '\n';
    bigint M_ver = big_pow(S, e) % n;
    cout << "B verifies the message and gets: " << M_ver << '\n';
    assert(M == M_ver);
    cout << "VERIFIED SUCCESSFULLY!!!\n\n";

    return 0;
}