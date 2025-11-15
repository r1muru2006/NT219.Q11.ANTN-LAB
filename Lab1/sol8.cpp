#include <iostream>
#include <string>
#include <vector>
#include <cryptopp/osrng.h>
#include <cryptopp/des.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hrtimer.h>

using std::cout;
using std::endl;
using std::string;
using std::u16string;

const double MIN_BENCHMARK_TIME = 2.0;
const double CPU_FREQ = 2.7 * 1e9;

template <class T_BLOCK_CIPHER>
void BenchmarkCipher(const string& cipherName, const string& dataLabel, const string& input) {
    cout << "Benchmarking " << cipherName << " (" << dataLabel << ")" << endl;
    
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(T_BLOCK_CIPHER::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(T_BLOCK_CIPHER::BLOCKSIZE);
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    string buffer = input;
    {
        typename CryptoPP::CBC_Mode<T_BLOCK_CIPHER>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv);
        
        unsigned long iterations = 0;
        CryptoPP::ThreadUserTimer timer;
        timer.StartTimer();

        do {
            unsigned long runCount = (iterations == 0) ? 1 : iterations;
            for (unsigned long i = 0; i < runCount; ++i) {
                enc.ProcessData(
                    // FIX 2: Chỉ định rõ CryptoPP::byte
                    reinterpret_cast<CryptoPP::byte*>(&buffer[0]),
                    reinterpret_cast<const CryptoPP::byte*>(input.data()),
                    input.size()
                );
            }
            iterations += runCount;
        } while (timer.ElapsedTimeAsDouble() < MIN_BENCHMARK_TIME);

        double elapsed = timer.ElapsedTimeAsDouble();
        double totalBytes = static_cast<double>(input.size()) * iterations;
        double mbs = totalBytes / elapsed / (1024 * 1024);
        double cpb = elapsed * CPU_FREQ / totalBytes;

        cout << "Encryption:" << endl;
        cout << "  " << cpb << " cycles/byte" << endl;
        cout << "  " << mbs << " MiB/s" << endl;
    }


    {
        typename CryptoPP::CBC_Mode<T_BLOCK_CIPHER>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv);

        unsigned long iterations = 0;
        CryptoPP::ThreadUserTimer timer;
        timer.StartTimer();

        do {
            unsigned long runCount = (iterations == 0) ? 1 : iterations;
            for (unsigned long i = 0; i < runCount; ++i) {
                dec.ProcessData(
                    // FIX 2: Chỉ định rõ CryptoPP::byte
                    reinterpret_cast<CryptoPP::byte*>(&buffer[0]),
                    reinterpret_cast<const CryptoPP::byte*>(input.data()),
                    input.size()
                );
            }
            iterations += runCount;
        } while (timer.ElapsedTimeAsDouble() < MIN_BENCHMARK_TIME);

        double elapsed = timer.ElapsedTimeAsDouble();
        double totalBytes = static_cast<double>(input.size()) * iterations;
        double mbs = totalBytes / elapsed / (1024 * 1024);
        double cpb = elapsed * CPU_FREQ / totalBytes;

        cout << "Decryption:" << endl;
        cout << "  " << cpb << " cycles/byte" << endl;
        cout << "  " << mbs << " MiB/s" << endl << endl;
    }
}

int main() {
    cout << "Bai 8: \n";
    string case1 = "r1muru";
    u16string utf16text = u"No way home 🤜🤛";
    string case2(
        reinterpret_cast<const char*>(utf16text.data()),
        utf16text.size() * sizeof(char16_t)
    );

    string case3(1024 * 1024, '\0');
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&case3[0]), case3.size());

    BenchmarkCipher<CryptoPP::DES>("DES", "Case 1: <64-bit data", case1);
    BenchmarkCipher<CryptoPP::DES>("DES", "Case 2: UTF-16 data", case2);
    BenchmarkCipher<CryptoPP::DES>("DES", "Case 3: 1MB random data", case3);

    return 0;
}