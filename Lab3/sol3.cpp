#include "bigint.h"
#include "genPrime.h"
#include "genRSAkey.h"
#define ll long long

using namespace std;


int main() {
    bigint p, q, e;
    vector<pair<bigint, bigint>> RSA_key;

    cout << "---This is my program for lesson 3---\n";
    cout << "---Generate RSA key pair---\n";
    cout << "Enter the prime p: "; cin >> p;
    cout << "Enter the prime q: "; cin >> q;
    cout << "Enter the public exponent e: "; cin >> e;

    if(MillerRabin(p) && MillerRabin(q) && p*q > to_bigint(4294967296LL))
        RSA_key = create_RSA_key(p, q, e);
    
    if (RSA_key.empty()) {
        cout << "---Invalid input---\n";
        cout << "\n---Generate random RSA key pair---\n";
        int length_p, length_q;
        e = 65537;
        cout << "Enter your bytelength of prime p: "; cin >> length_p;
        cout << "Enter your bytelength of prime q: "; cin >> length_q;
        do {
            bigint p_rd = genPrime(length_p);
            bigint q_rd = genPrime(length_q);
            if (p_rd == q_rd) continue;

            cout << "Successfully generated random key\n";
            cout << "Random p = " << p_rd << endl;
            cout << "Random q = " << q_rd << endl;
            cout << "Set e = " << e << endl;
            RSA_key = create_RSA_key(p_rd, q_rd, e);
        } while (RSA_key.empty());
    }
    cout << "Public Key: (" << RSA_key[0].first << ", "  << RSA_key[0].second << ")\n";
    cout << "Private Key: (" << RSA_key[1].first << ", " << RSA_key[1].second << ")\n";
    bigint n = RSA_key[0].second, d = RSA_key[1].first;

    wstring_convert<codecvt_utf8<char32_t>, char32_t> convert;
    u32string msg = convert.from_bytes("I love pinanek 😘 i hate pinanek 😡");
    cout << "\nOriginal message: I love pinanek 😘 i hate pinanek 😡\n";
    
    vector<bigint> enc;
    for (char32_t c : msg){
        bigint M = to_bigint(static_cast<ll>(c));
        bigint C = pow(M, e, n);
        enc.push_back(C);
    }
    cout << "The encrypted message: ";
    for (const bigint& num : enc) {
        cout << num << " ";
    }
    cout << endl;

    u32string recovered;
    for (bigint num : enc) {
        bigint M_rec = pow(num, d, n);
        ll rec = stoll(M_rec.to_string());
        recovered += static_cast<char32_t>(rec);
    }
    string msg_rec = convert.to_bytes(recovered);
    cout << "The decrypted message: " << msg_rec << '\n';
    assert(msg_rec == "I love pinanek 😘 i hate pinanek 😡");
    cout << "---Successful encyption/decryption process---\n";

    return 0;
}