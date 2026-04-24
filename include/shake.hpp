#ifndef SHAKE_SSFTP
#define SHAKE_SSFTP

#include <openssl/evp.h>
#include <vector>
#include "utils.hpp"

/*  RYAN
    shake.cpp was created by me
    The purpose of this is to serve as a wrapper class for 
    the extendable output function SHAKE 128
*/

class XOF{
    public:
        bool Init(int size);
        bool Absorb(std::vector<Byte>& str);
        std::vector<Byte> Squeeze(size_t numBytes);
        void Free();
        
    private:
        EVP_MD_CTX* ctx;
        bool final_was_run;
        int squeezeIndex;
        std::vector<Byte> hash;
        int hashSize;
};

#endif