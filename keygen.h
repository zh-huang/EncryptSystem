#pragma once

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pXFactoring.h>

#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "sign.h"

using namespace std;

NTL_CLIENT

string toString(ZZ z);

class RSA {
   private:
    /* stores private and public key */
    ZZ a, b, n;
    /* default = 512 bit */
    int size;

   public:
    RSA(){};
    RSA(string name, const bool privatekey = true);
    void keyGenreate(int keysize = 512);
    ZZ encrypt(ZZ plaintext);
    ZZ decrypt(ZZ ciphertext);
    string sign(string message);
    bool verify(string message, string signature);
    void store(string filename);
    int getsize() { return size; }
};
