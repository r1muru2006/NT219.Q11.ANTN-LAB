#include <cryptopp/des.h>
#include <bits/stdc++.h>

using namespace CryptoPP;
using namespace std;

int main() {
    cout << "Bai 1: \n";
    cout << "DES key length: " << DES::DEFAULT_KEYLENGTH << '\n';
    cout << "Block size of DES: " << DES::BLOCKSIZE << '\n';
    return 0;
}