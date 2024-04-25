#include "keygen.h"

string toString(ZZ z)
{
    std::ostringstream oss;
    oss << z;
    return oss.str();
}

NTL::ZZ ZZFromStr(const std::string &str)
{
    NTL::ZZ number;
    std::stringstream ss(str);
    ss >> number;
    return number;
}

RSA::RSA(string name, const bool privatekey)
{
    if (privatekey) {
        ifstream i = ifstream(name.c_str(), ios::in);
        if (!i.is_open()) {
            cerr << "Cannot open file: " << name << endl;
            return;
        }
        i >> a >> b >> n >> size;
        i.close();
        return;
    }
    else {
        ifstream i = ifstream(name + ".pub", ios::in);
        if (!i.is_open()) {
            cerr << "Cannot open file: " << name << ".pub" << endl;
            return;
        }
        i >> b >> n >> size;
        i.close();
        return;
    }
}

void RSA::keyGenreate(int key_size)
{
    if (key_size != 512 && key_size != 1024 && key_size != 2048 &&
        key_size != 4096) {
        cerr << "key_size should be 512/1024/2048/4096, default=512" << endl;
        return;
    }
    ZZ p, q, phi;
    size = key_size;
    GenGermainPrime(p, size);
    GenGermainPrime(q, size);
    while (p == q) GenGermainPrime(q, size);
    n = p * q;
    phi = (p - 1) * (q - 1);
    do {
        RandomBnd(b, phi);
    } while (GCD(b, phi) != 1);
    InvMod(a, b, phi);
}

ZZ RSA::encrypt(ZZ plaintext)
{
    ZZ ciphertext;
    PowerMod(ciphertext, plaintext, b, n);
    return ciphertext;
}

ZZ RSA::decrypt(ZZ ciphertext)
{
    ZZ plaintext;
    PowerMod(plaintext, ciphertext, a, n);
    return plaintext;
}

string RSA::sign(string message)
{
    ZZ s, hash;
    SHA_1 sha;
    hash = sha.sha1zz(message);
    s = PowerMod(hash, a, n);
    string signature = toString(s);
    return signature;
}

bool RSA::verify(string message, string signature)
{
    ZZ s, hash;
    SHA_1 sha;
    hash = sha.sha1zz(message);
    s = ZZFromStr(signature);
    ZZ computedSignature = PowerMod(s, b, n);
    return hash == computedSignature;
}

void RSA::store(string filename)
{
    // store private key
    ofstream o(filename, ios::out | ios::binary);
    o << a << endl;
    o << b << endl;
    o << n << endl;
    o << size << endl;
    o.close();

    // store public key
    ofstream op(filename + ".pub", ios::out | ios::binary);
    op << b << endl;
    op << n << endl;
    op << size << endl;
    op.close();
}
