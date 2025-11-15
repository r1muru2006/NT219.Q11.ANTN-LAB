#include <assert.h>
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>

#include "cryptopp/pem.h"
#include "cryptopp/pem_common.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/integer.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"

using namespace CryptoPP;
using namespace std;


bool GenPrivKey(const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key);
bool GenPubKey(const ECDSA<ECP, SHA1>::PrivateKey& pkey, ECDSA<ECP, SHA1>::PublicKey& pubkey);

void SavePrivKey(const string& fname, const ECDSA<ECP, SHA1>::PrivateKey& key);
void SavePubKey(const string& fname, const ECDSA<ECP, SHA1>::PublicKey& key);
void LoadPrivKey(const string& fname, ECDSA<ECP, SHA1>::PrivateKey& key);
void LoadPubKey(const string& fname, ECDSA<ECP, SHA1>::PublicKey& key);

bool SignMsg(const ECDSA<ECP, SHA1>::PrivateKey& key, const string& msg, string& sig);
bool VerifyMsg(const ECDSA<ECP, SHA1>::PublicKey& key, const string& msg, const string& sig);

int isPemPub(string fname);
int isPemPriv(string fname);


int isPemPub(string fname) {
    ifstream f(fname);
    if (!f.is_open()) return 2;
    string line;
    getline(f, line);
    if (line.find("-----BEGIN PUBLIC KEY-----") == string::npos)
        return 0;
    while (getline(f, line)) {
        if (line.find("-----END PUBLIC KEY-----") != string::npos)
            return 1;
    }
    return 0;
}

int isPemPriv(string fname) {
    ifstream f(fname);
    if (!f.is_open()) return 2;
    string line;
    getline(f, line);
    if (line.find("-----BEGIN EC PRIVATE KEY-----") == string::npos)
        return 0;
    while (getline(f, line)) {
        if (line.find("-----END EC PRIVATE KEY-----") != string::npos)
            return 1;
    }
    return 0;
}


int main(int argc, char* argv[]) {
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc == 1) {
        cerr << "Usage: sol4 <mode>\n";
        cerr << "Mode: keygen, sign, verify\n";
        return 1;
    }

    int choice = 0;
    string mode = argv[1];
    if (mode == "keygen") choice = 1;
    else if (mode == "sign") choice = 2;
    else if (mode == "verify") choice = 3;
    else {
        cerr << "Invalid mode: " << mode << endl;
        return 1;
    }

    switch (choice) {
        case 1: {
            if (argc != 5) {
                cerr << "Usage: sol4 keygen <Private_key_filename> <Public_key_filename> <file_type>\n";
                cerr << "Supported file type: ber, pem.\n";
                return 1;
            }

            string privFile = argv[2];
            string pubFile = argv[3];
            string fType = argv[4];

            auto start = chrono::high_resolution_clock::now();

            ECDSA<ECP, SHA1>::PrivateKey pkey;
            ECDSA<ECP, SHA1>::PublicKey pubkey;

            bool res = GenPrivKey(ASN1::secp160r1(), pkey);
            assert(res);

            res = GenPubKey(pkey, pubkey);
            assert(res);

            if (fType == "ber") {
                SavePrivKey(privFile, pkey);
                SavePubKey(pubFile, pubkey);
            } else if (fType == "pem") {
                FileSink pub(pubFile.data(), true);
                PEM_Save(pub, pubkey);

                FileSink priv(privFile.data(), true);
                PEM_Save(priv, pkey);
            } else {
                cerr << "Invalid file type!!!\n";
                return 1;
            }

            auto end = chrono::high_resolution_clock::now();
            auto dur = chrono::duration_cast<chrono::milliseconds>(end - start).count();

            cout << "Successfully saved ECDSA keys.\n";
            cout << "Time for key generation: " << dur << " microsecond\n";
            break;
        }

        case 2: {
            if (argc != 5) {
                cerr << "Usage: sol4 sign <Private_key_file> <file/screen> <message>/<message_file_path>\n";
                cerr << "Example: sol4 sign priv.pem file mess.txt\n";
                return 1;
            }

            string keyFile = argv[2];
            string inType = argv[3];
            string inSrc = argv[4];

            int inputMode = (inType == "screen") ? 1 : (inType == "file") ? 2 : 0;
            if (!inputMode) {
                cerr << "Invalid option!!\n";
                return 1;
            }

            ECDSA<ECP, SHA1>::PrivateKey key;
            int fType = isPemPriv(keyFile);

            if (fType == 0)
                LoadPrivKey(keyFile, key);
            else if (fType == 1) {
                FileSource fs(keyFile.data(), true);
                PEM_Load(fs, key);
            } else {
                cerr << "Fail to load ECDSA key!!!\n";
                return 1;
            }

            cout << "Successfully loaded ECDSA key.\n";

            string msg, sig;
            if (inputMode == 1)
                msg = inSrc;
            else
                FileSource(inSrc.data(), true, new StringSink(msg));

            auto start = chrono::high_resolution_clock::now();
            SignMsg(key, msg, sig);
            auto end = chrono::high_resolution_clock::now();

            auto dur = chrono::duration_cast<chrono::microseconds>(end - start).count();
            cout << "Successfully signed message.\n";
            cout << "Time for signing: " << dur << " microsecond\n";

            string sigHex;
            StringSource(sig, true, new HexEncoder(new StringSink(sigHex)));
            cout << "Signature (hex): " << sigHex << endl;
            break;
        }

        case 3: {
            if (argc != 5) {
                cerr << "Usage: sol4 verify <Public_key_file> <file/screen> <message>/<message file path>\n";
                cerr << "Example: sol4 verify pub.pem file mess.txt\n";
                return 1;
            }

            string keyFile = argv[2];
            string inType = argv[3];
            string inSrc = argv[4];

            int inputMode = (inType == "screen") ? 1 : (inType == "file") ? 2 : 0;
            if (!inputMode) {
                cerr << "Invalid option!!\n";
                return 1;
            }

            ECDSA<ECP, SHA1>::PublicKey key;
            int fType = isPemPub(keyFile);

            if (fType == 0)
                LoadPubKey(keyFile, key);
            else if (fType == 1) {
                FileSource fs(keyFile.data(), true);
                PEM_Load(fs, key);
            } else {
                cerr << "Fail to load ECDSA key!!!\n";
                return 1;
            }

            cout << "Successfully loaded ECDSA key.\n";

            string msg, sig, sigHex;
            cout << "Enter signature to verify: ";
            cin >> sigHex;

            StringSource(sigHex, true, new HexDecoder(new StringSink(sig)));

            if (inputMode == 1)
                msg = inSrc;
            else
                FileSource(inSrc.data(), true, new StringSink(msg));

            auto start = chrono::high_resolution_clock::now();
            bool res = VerifyMsg(key, msg, sig);
            auto end = chrono::high_resolution_clock::now();

            auto dur = chrono::duration_cast<chrono::microseconds>(end - start).count();
            cout << "Time for verifying: " << dur << " microsecond\n";

            cout << (res ? "Verify successfully!!!" : "Verify fail!!!") << endl;
            break;
        }

        default:
            cerr << "Invalid option!!!\n";
            return 1;
    }

    return 0;
}


bool GenPrivKey(const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key) {
    AutoSeededRandomPool prng;
    key.Initialize(prng, oid);
    assert(key.Validate(prng, 3));
    return key.Validate(prng, 3);
}

bool GenPubKey(const ECDSA<ECP, SHA1>::PrivateKey& pkey, ECDSA<ECP, SHA1>::PublicKey& pubkey) {
    AutoSeededRandomPool prng;
    assert(pkey.Validate(prng, 3));
    pkey.MakePublicKey(pubkey);
    assert(pubkey.Validate(prng, 3));
    return pubkey.Validate(prng, 3);
}

void SavePrivKey(const string& fname, const ECDSA<ECP, SHA1>::PrivateKey& key) {
    key.Save(FileSink(fname.c_str(), true).Ref());
}

void SavePubKey(const string& fname, const ECDSA<ECP, SHA1>::PublicKey& key) {
    key.Save(FileSink(fname.c_str(), true).Ref());
}

void LoadPrivKey(const string& fname, ECDSA<ECP, SHA1>::PrivateKey& key) {
    key.Load(FileSource(fname.c_str(), true).Ref());
}

void LoadPubKey(const string& fname, ECDSA<ECP, SHA1>::PublicKey& key) {
    key.Load(FileSource(fname.c_str(), true).Ref());
}

bool SignMsg(const ECDSA<ECP, SHA1>::PrivateKey& key, const string& msg, string& sig) {
    AutoSeededRandomPool prng;
    sig.clear();

    StringSource(msg, true,
        new SignerFilter(prng,
            ECDSA<ECP, SHA1>::Signer(key),
            new StringSink(sig)
        )
    );
    return !sig.empty();
}

bool VerifyMsg(const ECDSA<ECP, SHA1>::PublicKey& key, const string& msg, const string& sig) {
    bool res = false;
    StringSource(sig + msg, true,
        new SignatureVerificationFilter(
            ECDSA<ECP, SHA1>::Verifier(key),
            new ArraySink((CryptoPP::byte*)&res, sizeof(res))
        )
    );
    return res;
}
