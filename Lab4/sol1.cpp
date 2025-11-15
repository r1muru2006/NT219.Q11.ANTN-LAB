#include <bits/stdc++.h>
#include "hash-library/md5.h"
#include "hash-library/sha1.h"
#include "hash-library/sha3.h"

using namespace std;

vector<unsigned char> hex_to_bytes(const string& hex) {
    if (hex.length() % 2 != 0)
        throw invalid_argument("Chuỗi hex phải có số ký tự chẵn.");

    vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_string = hex.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(stoul(byte_string, nullptr, 16));
            bytes.push_back(byte);
        } catch (const exception& e) {
            throw invalid_argument("Ký tự hex không hợp lệ trong chuỗi.");
        }
    }
    return bytes;
}

void hash_algo(const string& alg_name, istream& is) {
    vector<char> buffer(4096); // Đọc 4KB mỗi lần

    if (alg_name == "md5") {
        MD5 hasher;
        while (is.good()) {
            is.read(buffer.data(), buffer.size());
            streamsize bytes_read = is.gcount();
            if (bytes_read > 0) {
                hasher.add(buffer.data(), bytes_read);
            }
        }
        cout << hasher.getHash() << endl;
    } 
    else if (alg_name == "sha1") {
        SHA1 hasher;
        while (is.good()) {
            is.read(buffer.data(), buffer.size());
            streamsize bytes_read = is.gcount();
            if (bytes_read > 0) {
                hasher.add(buffer.data(), bytes_read);
            }
        }
        cout << hasher.getHash() << endl;
    } 
    // Xử lý các biến thể SHA3
    else if (alg_name == "sha3") {
        SHA3 hasher;
        while (is.good()) {
            is.read(buffer.data(), buffer.size());
            streamsize bytes_read = is.gcount();
            if (bytes_read > 0) {
                hasher.add(buffer.data(), bytes_read);
            }
        }
        cout << hasher.getHash() << endl;
    }
    else {
        cerr << "Lỗi: Thuật toán "<< alg_name << " không được hỗ trợ.\n";
        cerr << "Các thuật toán được hỗ trợ: md5, sha1, sha3\n";
    }
}

void usage(const char* prog_name) {
    cerr << "Cách dùng: " << prog_name << " <thuật toán> <kiểu> <đầu vào>\n";
    cerr << "  <thuật toán>: md5, sha1, sha3\n";
    cerr << "  <kiểu>:\n";
    cerr << "    -s  Đầu vào là một chuỗi văn bản (string)\n";
    cerr << "    -h  Đầu vào là một chuỗi hex (hex string)\n";
    cerr << "    -f  Đầu vào là một đường dẫn tệp (file path)\n";
    cerr << "  Ví dụ:\n";
    cerr << "    " << prog_name << " sha3 -s \"hello world\"\n";
    cerr << "    " << prog_name << " md5 -h \"68656c6c6f20776f726c64\"\n";
    cerr << "    " << prog_name << " sha1 -f ./my_file.txt\n";
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage(argv[0]);
        return 1;
    }

    const string alg_name = argv[1];
    const string type = argv[2];
    const string input = argv[3];

    try {
        if (type == "-s") {
            stringstream ss(input);
            hash_algo(alg_name, ss);
        } else if (type == "-h") {
            vector<unsigned char> bytes = hex_to_bytes(input);
            stringstream ss;
            ss.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            hash_algo(alg_name, ss);
        } else if (type == "-f") {
            ifstream ifs(input, ios::binary);
            if (!ifs) {
                cerr << "Lỗi: Không thể mở tệp: " << input << endl;
                return 1;
            }
            hash_algo(alg_name, ifs);
        } else {
            cerr << "Lỗi: Kiểu đầu vào không xác định '" << type << "'" << endl;
            usage(argv[0]);
            return 1;
        }
    } catch (const exception& e) {
        cerr << "Đã xảy ra lỗi: " << e.what() << endl;
        return 1;
    }

    return 0;
}