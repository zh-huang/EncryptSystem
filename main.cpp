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
    rsa.keyGenreate(keysize);
    rsa.store(filename);
    return 0;
}

int sign(int argv, char** argc)
{
    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/message.txt";
    string outfile = "test/signature.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-o") != "") outfile = pargs(argv, argc, "-o");

    // Read message
    RSA rsa;
    rsa = RSA(keyfile);
    string message;
    ifstream i(infile);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    while (!i.eof()) {
        char c;
        i.read(&c, 1);
        message += c;
    }
    i.close();

    // Hash and sign message
    ofstream o(outfile);
    if (!o.is_open()) {
        cerr << "Cannot open file: " << outfile << endl;
        return 1;
    }
    string signature = rsa.sign(message);
    o.write(signature.c_str(), signature.size());
    o.close();
    return 0;
}

int verify(int argv, char** argc)
{
    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/message.txt";
    string sigfile = "test/signature.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-s") != "") sigfile = pargs(argv, argc, "-s");

    // Read message and signature
    RSA rsa;
    rsa = RSA(keyfile, false);
    string message;
    ifstream i(infile, ios::binary);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    while (!i.eof()) {
        char c;
        i.read(&c, 1);
        message += c;
    }
    i.close();
    string signature;
    ifstream s(sigfile);
    if (!s.is_open()) {
        cerr << "Cannot open file: " << sigfile << endl;
        return 1;
    }
    while (!s.eof()) {
        char c;
        s.read(&c, 1);
        signature += c;
    }
    s.close();

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
    while (!i.eof()) {
        char c;
        i.read(&c, 1);
        plaintext += c;
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
    RSA rsa(keyfile, true);
    int keylen = rsa.getsize() / 256;
    vector<unsigned char> encryptedkey(keylen * 64);
    vector<unsigned char> key(16);
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
    return 0;
}

int main(int argv, char** argc)
{
    if (argv < 2) {
        cout << "Usage: " << argc[0] << " [keygen|sign|verify|encrypt|decrypt]"
             << endl;
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
    } else {
        cout << "Usage: " << argc[0] << " [keygen|sign|verify|encrypt|decrypt]"
             << endl;
        return 1;
    }
    return 0;
}