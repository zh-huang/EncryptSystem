#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "crypt.h"
#include "keygen.h"
#include "sign.h"

using namespace std;

string pargs(int argv, char** argc, string name)
{
    for (int i = 1; i < argv - 1; i++) {
        if (string(argc[i]) == name) {
            return string(argc[i + 1]);
        }
    }
    return string("");
}

int keygen(int argv, char** argc)
{
    string filename = "test/key.txt";
    int keysize = 512;
    RSA rsa;
    if (pargs(argv, argc, "-o") != "") filename = pargs(argv, argc, "-o");
    if (pargs(argv, argc, "-s") != "") keysize = stoi(pargs(argv, argc, "-s"));
    cout << "Generating key..." << endl;
    cout << "Key size: " << keysize << " bits" << endl;
    cout << "Private key file: " << filename << endl;
    cout << "Public key file: " << filename << ".pub" << endl;
    rsa.keyGenreate(keysize);
    rsa.store(filename);
    cout << "Key generated." << endl;
    return 0;
}

int sign(int argv, char** argc)
{
    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/cipher.txt";
    string outfile = "test/signature.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-o") != "") outfile = pargs(argv, argc, "-o");

    // Read message
    RSA rsa;
    cout << "Reading private key \'" << keyfile << "\'..." << endl;
    rsa = RSA(keyfile);
    string message;
    cout << "Reading message \'" << infile << "\'..." << endl;
    ifstream i(infile);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    char c;
    i.read(&c, 1);
    while (!i.eof()) {
        message += c;
        i.read(&c, 1);
    }
    i.close();

    // Hash and sign message
    cout << "Signing message..." << endl;
    ofstream o(outfile);
    if (!o.is_open()) {
        cerr << "Cannot open file: " << outfile << endl;
        return 1;
    }
    string signature = rsa.sign(message);
    o << signature;
    o.close();
    cout << "Message signed. Signature: " << outfile << endl;
    return 0;
}

int verify(int argv, char** argc)
{
    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/cipher.txt";
    string sigfile = "test/signature.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-s") != "") sigfile = pargs(argv, argc, "-s");

    // Read message and signature
    RSA rsa;
    cout << "Reading public key \'" << keyfile << ".pub\'..." << endl;
    rsa = RSA(keyfile, false);
    string message;
    cout << "Reading message \'" << infile << "\'..." << endl;
    ifstream i(infile);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    char c;
    i.read(&c, 1);
    while (!i.eof()) {
        message += c;
        i.read(&c, 1);
    }
    i.close();

    // Read signature
    cout << "Reading signature \'" << sigfile << "\'..." << endl;
    string signature;
    ifstream s(sigfile);
    if (!s.is_open()) {
        cerr << "Cannot open file: " << sigfile << endl;
        return 1;
    }
    s >> signature;

    // Verify signature
    if (rsa.verify(message, signature)) {
        cout << "Signature is valid." << endl;
    } else {
        cout << "Signature is invalid." << endl;
    }
    return 0;
}

int encrypt(int argv, char** argc)
{
    // Generate random key
    cout << "Generating random key..." << endl;
    vector<unsigned char> key(16);
    for (auto& i : key) i = rand() % 256;

    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/message.txt";
    string outfile = "test/cipher.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-o") != "") outfile = pargs(argv, argc, "-o");

    // Convert key to string
    cout << "Encrypting key..." << endl;
    ZZ keyint, encryptedkey;
    keyint = 0;
    for (auto i : key) (keyint *= 256) += i;
    cout << "Reading public key \'" << keyfile << ".pub\'..." << endl;
    RSA rsa(keyfile, false);
    encryptedkey = rsa.encrypt(keyint);
    int keylen = rsa.getsize() / 256;
    vector<unsigned char> keystr(keylen * 64);
    for (int i = 0; i < (int)keystr.size(); ++i) {
        keystr[i] = encryptedkey % 256;
        encryptedkey /= 256;
    }

    // Encrypt file using key with AES
    cout << "Encrypting file..." << endl;
    AES_CBC aes;
    string plaintext, ciphertext;
    ifstream i(infile, ios::binary);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    char c;
    i.read(&c, 1);
    while (!i.eof()) {
        plaintext += c;
        i.read(&c, 1);
    }
    i.close();
    ciphertext = aes.encryptString(plaintext, key);
    ofstream o(outfile, ios::binary);
    if (!o.is_open()) {
        cerr << "Cannot open file: " << outfile << endl;
        return 1;
    }
    // o.write((char*)(&keylen), sizeof(int));
    o.write((char*)(&keystr[0]), keystr.size());
    ZZ encryptedkeyint;
    encryptedkeyint = 0;
    for (auto i : keystr) (encryptedkeyint += i) *= 256;
    o.write(ciphertext.c_str(), ciphertext.size());
    o.close();
    cout << "File encrypted. Cipher: " << outfile << endl;
    return 0;
}

int decrypt(int argv, char** argc)
{
    string ciphertext;

    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/cipher.txt";
    string outfile = "test/decryptedmessage.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-o") != "") outfile = pargs(argv, argc, "-o");

    // Read encrypted file
    cout << "Reading private key \'" << keyfile << "\'..." << endl;
    RSA rsa(keyfile, true);
    int keylen = rsa.getsize() / 256;
    vector<unsigned char> encryptedkey(keylen * 64);
    vector<unsigned char> key(16);
    cout << "Reading encrypted file \'" << infile << "\'..." << endl;
    ifstream i(infile, ios::binary);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    i.read((char*)(&encryptedkey[0]), encryptedkey.size());
    char c;
    i.read(&c, 1);
    while (!i.eof()) {
        ciphertext += c;
        i.read(&c, 1);
    }
    i.close();

    // Decrypt key using RSA
    cout << "Decrypting random key..." << endl;
    ZZ keyint, decryptedkey;
    keyint = 0;
    for (int i = (int)encryptedkey.size() - 1; i >= 0; --i) {
        keyint *= 256;
        keyint += encryptedkey[i];
    }
    decryptedkey = rsa.decrypt(keyint);
    for (int i = 15; i >= 0; --i) {
        key[i] = decryptedkey % 256;
        decryptedkey /= 256;
    }

    // Decrypt file using key with AES
    cout << "Decrypting file..." << endl;
    AES_CBC aes;
    string plaintext;
    plaintext = aes.decryptString(ciphertext, key);
    ofstream o(outfile);
    if (!o.is_open()) {
        cerr << "Cannot open file: " << outfile << endl;
        return 1;
    }
    o.write(plaintext.c_str(), plaintext.size());
    o.close();
    cout << "File decrypted. Message: " << outfile << endl;
    return 0;
}

void test(int argv, char** argc)
{
    argv = 1;
    cout << "Testing key generation..." << endl;
    keygen(argv, argc);
    cout << endl << "Testing signing..." << endl;
    sign(argv, argc);
    cout << endl << "Testing verification..." << endl;
    verify(argv, argc);
    cout << endl << "Testing encryption..." << endl;
    encrypt(argv, argc);
    cout << endl << "Testing decryption..." << endl;
    decrypt(argv, argc);
}

void usage(char* name)
{
    cout << "Usage: " << name << " [keygen|encrypt|decrypt|sign|verify]"
         << endl;
    cout << "keygen: Generate RSA key pair" << endl;
    cout << "  -o <filename>: Output file, default=./test/key.txt" << endl;
    cout << "  -s <keysize>: Key size in bits[512/1024/2048/4096], default=512"
         << endl;
    cout << "encrypt: Encrypt a file" << endl;
    cout << "  -k <filename>: Key file, default=./test/key.txt" << endl;
    cout << "  -i <filename>: Input file, default=./test/message.txt" << endl;
    cout << "  -o <filename>: Output file, default=./test/cipher.txt" << endl;
    cout << "decrypt: Decrypt a file" << endl;
    cout << "  -k <filename>: Key file, default=./test/key.txt" << endl;
    cout << "  -i <filename>: Input file, default=./test/cipher.txt" << endl;
    cout << "  -o <filename>: Output file, default=./test/decryptedmessage.txt"
         << endl;
    cout << "sign: Sign a message" << endl;
    cout << "  -k <filename>: Private key file, default=./test/key.txt" << endl;
    cout << "  -i <filename>: Input file, default=./test/cipher.txt" << endl;
    cout << "  -o <filename>: Output file, default=./test/signature.txt"
         << endl;
    cout << "verify: Verify a signature" << endl;
    cout << "  -k <filename>: Public key file, default=./test/key.txt" << endl;
    cout << "  -i <filename>: Input file, default=./test/cipher.txt" << endl;
    cout << "  -s <filename>: Signature file, default=./test/signature.txt"
         << endl;
    cout << "test: Run all tests using default settings" << endl;
}

int main(int argv, char** argc)
{
    if (argv < 2) {
        usage(argc[0]);
        return 1;
    }
    if (string(argc[1]) == "keygen") {
        return keygen(argv, argc);
    } else if (string(argc[1]) == "sign") {
        return sign(argv, argc);
    } else if (string(argc[1]) == "verify") {
        return verify(argv, argc);
    } else if (string(argc[1]) == "encrypt") {
        return encrypt(argv, argc);
    } else if (string(argc[1]) == "decrypt") {
        return decrypt(argv, argc);
    } else if (string(argc[1]) == "test") {
        test(argv, argc);
    } else {
        usage(argc[0]);
        return 1;
    }
    return 0;
}