#include <cryptopp/aes.h>
#include <bits/stdc++.h>

using namespace CryptoPP;
using namespace std;

int main() {
    cout << "Bai 1: \n";
    cout << "AES key length: " << AES::DEFAULT_KEYLENGTH << '\n';
    cout << "Block size of AES: " << AES::BLOCKSIZE << '\n';
    return 0;
}