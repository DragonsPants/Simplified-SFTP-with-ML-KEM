#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

#include "shake.hpp"

/*  RYAN
    shake.cpp was created by me
    The purpose of this is to serve as a wrapper class for 
    the extendable output function SHAKE 128
*/

bool XOF::Init(int hashLen){
    ctx = EVP_MD_CTX_new();
    squeezeIndex = 0;
    final_was_run = false;
    hashSize = hashLen;
    int initStatus = EVP_DigestInit_ex(ctx, EVP_shake128(), NULL);
    if(ctx == nullptr || initStatus != 1)
    {
        return false;
    }
    return true;
}

bool XOF::Absorb(std::vector<Byte>& str){
    int updateStatus = EVP_DigestUpdate(ctx, str.data(), str.size());
    if (updateStatus != 1) {
        return false;
    }
    return true;
}

void XOF::Free(){
    EVP_MD_CTX_free(ctx);
}

std::vector<Byte> XOF::Squeeze(size_t numBytes){
    
    if(!final_was_run){
        std::vector<Byte> tempHash(hashSize);
        EVP_DigestFinalXOF(ctx, tempHash.data(), hashSize);
        hash = tempHash;
        final_was_run = true;
    }

    std::vector<Byte> outputHash(numBytes);
    if(squeezeIndex + numBytes <= hashSize){
        for(int i = 0; i < numBytes; i++){
            outputHash[i] = hash[squeezeIndex + i];
        }
        squeezeIndex += numBytes;
    }

    return outputHash;
}
