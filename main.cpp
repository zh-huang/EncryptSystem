#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "crypt.h"
#include "keygen.h"
#include "sign.h"
#include "verify.h"

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
    string keyfile = "test/key.txt";
    string infile = "test/message.txt";
    string sigfile = "test/signature.txt";
    RSA rsa;
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-s") != "") sigfile = pargs(argv, argc, "-s");
    rsa = RSA(keyfile);
    string message;
    ifstream i(infile, ios::binary);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    i >> message;
    i.close();
    string signature;
    ifstream s(sigfile);
    if (!s.is_open()) {
        cerr << "Cannot open file: " << sigfile << endl;
        return 1;
    }
    s >> signature;
    s.close();
    string B, N;
    rsa.getKey(B, N);
    if (rsa.verify(message, signature, B, N)) {
        cout << "Signature is valid" << endl;
    } else {
        cout << "Signature is invalid" << endl;
    }
    return 0;
}

int encrypt(int argv, char** argc)
{
    // Generate random key
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
    string keystr, encryptedkey;
    for (auto i : key) keystr += i;
    // Encrypt key
    RSA rsa(keyfile);
    string B, N;
    rsa.getKey(B, N);
    encryptedkey = rsa.encrypt(keystr, B, N);

    // Encrypt file using key with AES
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
    o.write(encryptedkey.c_str(), 16);
    o.write(ciphertext.c_str(), ciphertext.size());
    o.close();
    return 0;
}

int decrypt(int argv, char** argc)
{
    string encryptedkey = "1234567890123456", ciphertext;
    vector<unsigned char> key(16);

    // Parse arguments
    string keyfile = "test/key.txt";
    string infile = "test/cipher.txt";
    string outfile = "test/message.txt";
    if (pargs(argv, argc, "-k") != "") keyfile = pargs(argv, argc, "-k");
    if (pargs(argv, argc, "-i") != "") infile = pargs(argv, argc, "-i");
    if (pargs(argv, argc, "-o") != "") outfile = pargs(argv, argc, "-o");

    // Decrypt key
    ifstream i(infile, ios::binary);
    if (!i.is_open()) {
        cerr << "Cannot open file: " << infile << endl;
        return 1;
    }
    i.read(&encryptedkey[0], 16);
    while (!i.eof()) {
        char c;
        i.read(&c, 1);
        ciphertext += c;
    }
    i.close();
    RSA rsa(keyfile);
    string keystr, B, N;
    rsa.getKey(B, N);
    keystr = rsa.decrypt(encryptedkey);
    for (int i = 0; i < 16; i++) key[i] = keystr[i];

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