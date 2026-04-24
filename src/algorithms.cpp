#include <iostream>
#include <openssl/evp.h>
#include "../include/utils.hpp"
#include "../include/shake.hpp"
#include "../include/algorithms.hpp"

#include <bitset>
#include <vector>
#include <cmath>
#include <random>

/*  RYAN
    Algorithms.cpp was created entirely by me and performs all of the auxiliary functions required to run ML-KEM
    It also provides functions for printing vectors of integers, bytes, and bits to console

    The blank namespace provides some private functions to perform simple mathematical operations
    used in the Algorithms namespace
*/

namespace{
    int bitrev(int input){
        int reversed = 0;

        for(int i = 64; i > 0; i /= 2){
            reversed += i * (input % 2);
            input = input / 2;
        }
        return reversed;
    }

    //required for values which may be negative
    int mod( int input, int modulus ){
        input = input % modulus;
        while(input < 0){
            input = input + modulus;
        }
        return input;
    }
}

namespace Algorithms{

    void printInts(std::vector<int> ints){
        for(int i = 0 ; i < ints.size(); i++){
            std::cout << ints[i] << ", ";
        }
    }

    void printBytes(std::vector<Byte> bytes){
        std::vector<bool> bits = bytesToBits(bytes);
        printBits(bits);
    }

    void printBits(std::vector<bool> bits){
        std::cout.flush();
        int byteSize = 8;
        for(int i = 0 ; i < bits.size()/byteSize; i++){
            for (int j = 0; j < byteSize; j++)
            {
                std::cout << bits[byteSize*i + j];
            }
            std::cout << ", ";
        }
        std::cout.flush();
    }

    std::vector<Byte> getRandomBytes( int size ){
        std::vector<Byte> output(size);
        
        std::random_device rand_dev;
        std::mt19937 mt;
        mt.seed(rand_dev());
        std::uniform_int_distribution<> uid(0,255);

        for(int i = 0; i < size; i++){
            output[i] = (Byte) uid(mt);
        }

        return output;
    }
    
    std::vector<int> compress(std::vector<int> input, int d){
        int m = (int) pow(2, d);
        std::vector<int> output(input.size());

        for(int i = 0; i < input.size(); i++){
            //ratio and ratio multiplication
            int temp = m * input[i];
            output[i] = (int) round( (double) temp / q);
            output[i] = mod( output[i], m);
        }
        return output;
    }

    std::vector<int> decompress(std::vector<int> input, int d){
        int m = (int) pow(2, d);
        std::vector<int> output(input.size());
        for(int i = 0; i < input.size(); i++){
            int temp = q * input[i];
            output[i] = (int) round((double) temp / m);
            output[i] = mod( output[i], q);
        }
        return output;
    }

    void polyAdd(std::vector<int>& f, std::vector<int> g){
        for(int i = 0; i < f.size(); i++){
            f[i] = mod(f[i] + g[i], q);
        }
    }

    std::vector<Byte> pseudo_random_eta( int eta, std::vector<Byte> input, Byte byte ){
        int output_size = 64 * eta;
        std::vector<Byte> output_hash(output_size);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
        EVP_DigestUpdate(ctx, input.data(), input.size());
        EVP_DigestUpdate(ctx, &byte, 1);
        EVP_DigestFinalXOF(ctx, output_hash.data(), output_hash.size());
        
        EVP_MD_CTX_free(ctx);
        return output_hash;
    }

    std::vector<Byte> hashJ( std::vector<Byte> seed, int hashSize ){
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::vector<Byte> output_hash(hashSize);

        EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
        EVP_DigestUpdate(ctx, seed.data(), seed.size());
        EVP_DigestFinalXOF(ctx, output_hash.data(), output_hash.size());

        EVP_MD_CTX_free(ctx);
        return output_hash;
    }

    std::vector<Byte> hashH( std::vector<Byte> seed ){
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        unsigned int out_size = 32;
        std::vector<Byte> output(out_size);
        //variable lenght byte input
        EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(ctx, seed.data(), seed.size());
        //two 32 byte arrays
        EVP_DigestFinal_ex(ctx, output.data(), NULL);
        EVP_MD_CTX_free(ctx);
        return output;
    }

    std::vector<Byte> hashG( std::vector<Byte> seed ){
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        unsigned int out_size = 64;
        std::vector<Byte> output(out_size);
        //variable lenght byte input
        EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
        EVP_DigestUpdate(ctx, seed.data(), seed.size());
        //two 32 byte arrays
        EVP_DigestFinal_ex(ctx, output.data(), NULL);
        EVP_MD_CTX_free(ctx);
        return output;
    }

    std::vector<int> polyMult(std::vector<int> f, std::vector<int> g, int n, int modulus){

        std::vector<int> h(f.size() + g.size(),0);

        for(int i = 0; i < f.size(); i++){
            for(int j = 0; j < g.size(); j++){
                h[i + j] += mod(f[i] * g[j], modulus);
            }
        }

        //answer mod x^n + 1
        for(int i = h.size() - 1; i >= n; i = i - 1){
            int t = h[i];
            h[i] = mod(h[i] - t, modulus);
            h[i-n] = mod(h[i-n] - t, modulus);
        }

        return h;
    }

    std::vector<int> samplePolyCBD(std::vector<Byte> seed, int eta){
        std::vector<int> polyRing(256, 0);
        int x; int y; int temp;

        std::vector<bool> bitSeed = bytesToBits(seed);

        for(int i = 0; i < 256; i++){
            x = 0;
            y = 0;
            for(int j = 0; j < eta; j++){
                x += bitSeed[(2 * i * eta) + j];
            }
            for(int j = 0; j < eta; j++){
                y += bitSeed[(2 * i * eta) + eta + j];
            }
            polyRing[i] = (x - y);
            if (polyRing[i] < 0){
                polyRing[i] += q;
            }
        }
        return polyRing;
    }

    std::vector<int> sampleNTT(std::vector<Byte> seed){
        const int MAX_RUNS = 300;
        const int POLY_LENGTH = 256;
        std::vector<int> transform(POLY_LENGTH);
        std::vector<Byte> hash(3);
        int coef1, coef2;

        XOF shake;
        shake.Init( MAX_RUNS * 3 );
        shake.Absorb( seed );

        int j = 0;
        for(int i = 0 ; i < MAX_RUNS; i++){
            if(j >= 256){
                break;
            }
            hash = shake.Squeeze(3);
            coef1 = hash[0] + 256 * (hash[1] % 16);
            coef2 = floor(hash[1] / 16) + 16 * hash[2];
            if(coef1 < q){
                transform[j] = coef1;
                j++;
            }
            if(coef2 < q && j < 256){
                transform[j] = coef2;
                j++;
            }
        }
        shake.Free();
        return transform;
    }

    void calcZeta(){
        for(int i = 0 ; i < 128; i++){

            int product = 1;
            for(int j = 1; j <= 2 * bitrev(i) + 1; j++){
                product *= 17;
                product = product % q;
            }
            std::cout << ", " << (product % q);

            if(i % 8 == 7){
                std::cout << "\n";
            }
        }
        return;
    }

    std::vector<int> NTT(std::vector<int> function){
        std::vector<int> transform(function);
        int i = 1;
        for(int len = 128; len >= 2; len /= 2){
            for(int start = 0; start < 256; start += (2*len) ){
                int zeta = zetaAt[i];
                i = i + 1;
                for(int j = start; j < start + len; j++){
                    int t = (zeta * transform[j + len]) % q;
                    transform[j+len] = mod( (transform[j] - t), q);
                    transform[j] = (transform[j] + t) % q;
                }
            }
        }
        return transform;
    }

    std::vector<int> NTTinverse(std::vector<int> transform){
        std::vector<int> function(transform);
        int i = 127;

        for(int len = 2; len <= 128; len *= 2){
            for(int start = 0 ; start < 256; start += (2 * len)){
                int zeta = zetaAt[i];
                i--;
                for(int j = start; j < start + len; j++){
                    int t = function[j];
                    function[j] = mod( (t + function[j+len]) , q);
                    function[j+len] = mod( zeta * (function[j+len] - t), q );
                }
            }
        }
        for(int i = 0; i < function.size(); i++){
            function[i] = mod ( (function[i] * 3303) , q);
        }
        return function;
    }

    std::vector<int> NTTmultiply( std::vector<int> f, std::vector<int> g){
        std::vector<int> h(256,0);
        for (int i = 0; i < 128; i++)
        {
            std::vector<int> products = baseCaseMultiply( f[2*i], f[2*i+1], g[2*i], g[2*i+1], zetaAt2[i]);
            h[2*i] = products[0];
            h[2*i+1] = products[1];
        }
        return h;
    }

    std::vector<int> baseCaseMultiply(int f0, int f1, int g0, int g1, int gamma){
        std::vector<int> output(2,0);
        int fg11 = f1 * g1 % q;
        output[0] = mod((f0 * g0) + (fg11 * gamma), q);
        output[1] = mod((f0 * g1) + (f1 * g0), q);
        return output;
    }

    std::vector<Byte> byteEncode(std::vector<int> integers, int d){
        std::vector<bool> bits(256 * d);
        for(int i = 0 ; i < 256; i++){
            int currentInt = integers[i];
            for(int j = 0; j < d; j++){
                bits[i*d+j] = currentInt % 2;
                currentInt = (currentInt - bits[i*d+j]) / 2;
            }
        }
        std::vector<Byte> bytes = bitsToBytes(bits);
        return bytes;
    }

    std::vector<int> byteDecode(std::vector<Byte> bytes, int d){
        int m = 0;
        if(d < 12){
            m = (int) pow(2, d);
        }
        else if(d >= 12){
            m = q;
        }

        std::vector<bool> bits = bytesToBits(bytes);

        std::vector<int> integers(256, 0);
        for(int i = 0; i < 256; i++){
            for(int j = 0; j < d; j++ ){
                integers[i] += bits[i*d+j] * (int) pow(2,j);
                integers[i] = mod(integers[i], m);
            }
        }
        return integers;
    }

    std::vector<Byte> bitsToBytes(std::vector<bool> bits){
        
        int lengthBytes = bits.size()/8;
        std::vector<Byte> Bytes(lengthBytes , 0x00);

        for(int i = 0; i < 8 * lengthBytes; i++){
            int index = i/8;
            Bytes[index] = Bytes[index] + ( bits[i] * pow(2 , i % 8 ) );
        }

        return Bytes;
    }

    std::vector<bool> bytesToBits(std::vector<Byte> bytes){

        int lengthBytes = bytes.size();
        std::vector<bool> bits(lengthBytes * 8); 

        std::vector<Byte> C(bytes);

        for(int i = 0; i < lengthBytes; i++){
            for(int j = 0; j < 8; j++){
                bits[8*i + j] = C[i] % 2;
                C[i] = C[i] >> 1;
            }
        }
        
        return bits;
    }

};