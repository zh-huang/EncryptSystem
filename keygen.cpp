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

RSA::RSA(string name)
{
    ifstream i = ifstream(name.c_str(), ios::in);
    if (!i.is_open()) {
        cerr << "RSA.cpp RSA::RSA(): input error" << endl;
        return;
    }
    i >> a >> b >> n >> size;
    i.close();
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

void RSA::getKey(string &B, string &N)
{
    B = toString(b);
    N = toString(n);
}

string RSA::encrypt(string plaintext, string B, string N)
{
    ZZ pt = conv<ZZ>(plaintext.c_str());
    ZZ eb = conv<ZZ>(B.c_str());
    ZZ en = conv<ZZ>(N.c_str());
    ZZ ciphertext;
    PowerMod(ciphertext, pt, eb, en);
    return toString(ciphertext);
}

string RSA::decrypt(string ciphertext)
{
    ZZ ct = conv<ZZ>(ciphertext.c_str());
    ZZ plaintext;
    PowerMod(plaintext, ct, a, n);
    return toString(plaintext);
}

string RSA::sign(string message)
{
    ZZ s, hash;
    SHA_1 sha;
    hash = sha.sha1zz(message);
    cout << "n: " << n << endl;
    cout << "a: " << a << endl;
    s = PowerMod(hash, a, n);
    cout << "s: " << s << endl;
    string signature = toString(s);
    return signature;
}

bool RSA::verify(string message, string signature, string B, string N)
{
    ZZ m, s;
    m = ZZFromStr(message);
    s = ZZFromStr(signature);
    ZZ e = ZZFromStr(B);
    ZZ mod = ZZFromStr(N);
    ZZ computedSignature = PowerMod(s, e, mod);
    return m == computedSignature;
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
    ofstream p(filename + ".pub", ios::out | ios::binary);
    p << b << endl;
    p << n << endl;
    p.close();
}
