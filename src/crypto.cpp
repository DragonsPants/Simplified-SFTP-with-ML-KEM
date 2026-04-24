#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <cstring>
#include <ctime>

#include "../include/shake.hpp"
#include "../include/algorithms.hpp"
#include "../include/crypto.hpp"
#include "../include/logger.hpp"
#include "../include/utils.hpp"

/*
    RYAN
    In this file, I am responsible for producing ML_KEM_KeyGen, ML_KEM_Encaps, and ML_KEM_Decaps
    as well as the _internal versions of these methods
    I also created the KPKE_KeyGen, KPKE_Encrypt and KPKE_Decrypt methods
    All other methods 
*/


/*
    Big block, ik, but just go through it.

    This file performs the main Encryption and Decryption operations using AES-256 in CBC mode
    We're using the library OpenSSL for this purpose.

    While it looks complicated, its far simpler to understand than implementing our own version
    of AES/S-AES from scratch. The library provides a lot of helper functions to make the process
    easier. There are a lot of lines of code here, but most of them are just error handling.

    The whole program is meant to be modular, meaning that you can put anything you want in the
    encryption and decryption functions, while having to make minor changes anywhere else.
    If you want to experiment with using some other cryptographic algorithms, or maybe try
    some other modes of operation, you can do so by changing the encryption and decryption functions.

    Try putting something as simple as a Caesar cipher in there, and see how it works.
    The only thing you need to keep in mind is that the input and output of the functions should
    remain the same. The input is a vector of bytes, and the output is also a vector of bytes.

    If you change the function signature (the parameters and return type), you'll have to make
    changes in the header file and where you call the function accordingly. The rest of the program
    will remain the same.

    The library provides a lot of cryptographic functions and algorithms. We're using the EVP
    (Envelope) interface here.

    The main functions used here are:
    - EVP_CIPHER_CTX_new(): Creates a new cipher context
    - EVP_EncryptInit_ex(): Initializes the encryption operation
    - EVP_EncryptUpdate(): Encrypts the data
    - EVP_EncryptFinal_ex(): Encrypts the final data
    - EVP_CIPHER_CTX_free(): Frees the cipher context
    - EVP_DecryptInit_ex(): Initializes the decryption operation
    - EVP_DecryptUpdate(): Decrypts the data
    - EVP_DecryptFinal_ex(): Decrypts the final data
*/

//random number generator is not secure, only for learning purposes
namespace Crypto {

    //RYAN: My code starts here

    bool ML_KEM_KeyGen(std::vector<Byte>& ek, std::vector<Byte>& dk ){

        std::vector<Byte> d = Algorithms::getRandomBytes(32);
        std::vector<Byte> z = Algorithms::getRandomBytes(32);
        if( d.empty() || d.size() != 32 || z.empty() || z.size() != 32){
            return false;
        }
        ML_KEM_KeyGen_internal(d, z, ek, dk);
        return true;
    }
    
    bool ML_KEM_Encaps(std::vector<Byte> ek, std::vector<Byte>& secret_key, std::vector<Byte>& cyphertext ){
        //ek, &secret_key, &cyphertext
        using namespace Algorithms;
        if(ek.size() != (384*k+32)){
            return false;
        }

        for ( int i = 0; i < k; i++){
            std::vector<Byte> ek_part(ek.begin() + (384*i), ek.begin() + (384*(i+1)) );
            std::vector<Byte> ek_test = byteEncode( byteDecode(ek_part, 12), 12 );
            if( !(ek_test == ek_part) ){
                return false;
            }
        }

        std::vector<Byte> rand_m = getRandomBytes(32);
        if( rand_m.size() != 32 ){
            return false;
        }
        ML_KEM_Encaps_internal(ek, rand_m, secret_key, cyphertext );
        return true;
    }

    bool ML_KEM_Decaps(std::vector<Byte> dk, std::vector<Byte> cyphertext, std::vector<Byte>& secret_key ){
        //dk, cyphertext, &secret_key, 
        using namespace Algorithms;
        
        if(cyphertext.size() != 32*(du*k+dv) || dk.size() != (768*k+96)){
            return false;
        }
        std::vector<Byte> test_input(dk.begin()+(384*k), dk.begin()+(768*k)+32);
        std::vector<Byte> test_hash = hashH(test_input);
        std::vector<Byte> check_val( dk.begin()+(768*k+32), dk.begin()+(768*k)+64 );

        if( !(check_val == test_hash) ){
            return false;
        }

        ML_KEM_Decaps_internal(dk, cyphertext, secret_key );
        return true;
    }

    bool ML_KEM_KeyGen_internal(std::vector<Byte> rand_d, std::vector<Byte> rand_z, std::vector<Byte>& ek, std::vector<Byte>& dk ){
        // rand_d, rand_z, ek, dk
        KPKE_KeyGen( rand_d, ek, dk );

        //Algorithms::printInts( Algorithms::byteDecode( dk ,12) );

        //append ek
        dk.insert( dk.end(), ek.begin(), ek.end() );
        //append H hash of ek
        std::vector<Byte> hash_ek = Algorithms::hashH(ek);
        dk.insert( dk.end(), hash_ek.begin(), hash_ek.end());
        //append z
        dk.insert( dk.end(), rand_z.begin(), rand_z.end());

        return true;
    }

    bool ML_KEM_Encaps_internal(std::vector<Byte> ek, std::vector<Byte> rand_m, std::vector<Byte>& secret_key, std::vector<Byte>& cyphertext ){
        //ek, rand_m, &secret_key, &cyphertext

        std::vector<Byte> hash_ek = Algorithms::hashH(ek);
        std::vector<Byte> hash_input(rand_m);
        hash_input.insert( hash_input.end(), hash_ek.begin(), hash_ek.end() );
        std::vector<Byte> hash_output = Algorithms::hashG( hash_input );
        //secret key and randomness r = G of [ m || H of (ek)]
        std::vector<Byte> hash_key( hash_output.begin(), hash_output.begin() + 32 );
        secret_key = hash_key;
        std::vector<Byte> rand_r( hash_output.begin() + 32, hash_output.end() );
        //cyphertext = k-pke encrypt rand_m using key ek and randomness r) 
        KPKE_Encrypt(cyphertext, ek, rand_m, rand_r);

        return true;
    }

    bool ML_KEM_Decaps_internal(std::vector<Byte> dk, std::vector<Byte> cyphertext, std::vector<Byte>& secret_key ){
        //dk, cyphertext, &secret_key
        using namespace Algorithms;
        using namespace std;

        vector<Byte> decrypt_key( dk.begin()        , dk.begin()+(384*k));
        vector<Byte> encrypt_key( dk.begin()+(384*k), dk.begin()+(768*k)+32);
        vector<Byte> hash_ek( dk.begin()+(768*k)+32, dk.begin()+(768*k)+64);
        vector<Byte> rand_z(  dk.begin()+(768*k)+64, dk.begin()+(768*k)+96);

        vector<Byte> rand_m(0);
        KPKE_Decrypt(rand_m, decrypt_key, cyphertext );

        vector<Byte> hash_input(rand_m); 
        hash_input.insert( hash_input.end(), hash_ek.begin(), hash_ek.end() );

        vector<Byte> output_hash = hashG( hash_input );
        vector<Byte> key_fromHash( output_hash.begin(), output_hash.begin()+32 );
        vector<Byte> r_fromHash(output_hash.begin()+32, output_hash.end());

        vector<Byte> test_cyphertext(0);
        KPKE_Encrypt( test_cyphertext, encrypt_key, rand_m, r_fromHash );

        if( !(test_cyphertext == cyphertext) ){
            cout << "implicit reject";
            rand_z.insert( rand_z.begin(), cyphertext.begin(), cyphertext.end());
            vector<Byte> hash_j = hashJ(rand_z, 32);
            secret_key = hash_j;
        }
        else{
            secret_key = key_fromHash;
        }   
        return true;
    }



    //compression may cause bit flip in rare cases -- FIX
    bool KPKE_Decrypt(std::vector<Byte>& plaintext, std::vector<Byte> dk, std::vector<Byte> c_text){
        using namespace Algorithms;

        std::vector<int> coeffs_u[k];
        std::vector<Byte> c_part1(0);
        c_part1.insert( c_part1.begin(), c_text.begin(), c_text.begin() + (32*du*k) );
        for(int i = 0; i < k; i++){
            std::vector<Byte> c_coeff( c_part1.begin() + (32*du*i), c_part1.begin() + (32*du*(i+1)) );
            coeffs_u[i] = decompress( byteDecode( c_coeff , du), du );
        }

        std::vector<int> v_prime;
        std::vector<Byte> c_part2(0);
        c_part2.insert( c_part2.begin(), c_text.begin() + (32*du*k), c_text.end());
        v_prime = decompress( byteDecode( c_part2 , dv), dv );

        //printInts(coeffs_u[0]);
        //printInts(v_prime);

        std::vector<int> poly_s[k];
        for(int i = 0; i < k; i++){
            std::vector<Byte> s_ring_byte( dk.begin() + (384*i), dk.begin() + (384*(i+1)) );
            poly_s[i] = byteDecode( s_ring_byte, 12);
        }

        std::vector<int> v_constant(256,0);
        for(int i = 0; i < k; i++){
            polyAdd( v_constant, NTTmultiply(poly_s[i], NTT(coeffs_u[i])) );
        }
        v_constant = NTTinverse(v_constant);
        
        for(int i = 0; i < 256; i++){
            v_constant[i] = v_constant[i] * -1;
        }
        std::vector<int> w_constant(256,0);
        polyAdd(w_constant, v_prime);
        polyAdd(w_constant, v_constant);
        std::vector<Byte> decoded_text = byteEncode( compress(w_constant, 1) , 1);

        plaintext = decoded_text;
        return true;
    }

    //rememeber to initialize arrays properly
    bool KPKE_Encrypt( std::vector<Byte>& cyphertext, std::vector<Byte> ek, std::vector<Byte> m, std::vector<Byte> r ){
        //cyphertext, ek, m, r
        using namespace Algorithms;

        Byte N = 0;
        std::vector<int> t[k];
        std::vector<int> A[k][k];
        std::vector<int> y[k];
        std::vector<int> error1[k];
        std::vector<int> error2;
        std::vector<int> u[k];
        std::vector<int> v(256,0);
        std::vector<int> mu;

        for(int i = 0; i < k; i++){
            std::vector<Byte> ek_part(ek.begin() + (384*i), ek.begin() + (384*(i+1)));
            t[i] = byteDecode( ek_part, 12 );
        }
        std::vector<Byte> rho( ek.begin() + (384*k), ek.end() );

        for(int i = 0; i < k; i++){
            for(int j = 0; j < k; j++){
                std::vector<Byte> temp_rho(rho); temp_rho.push_back(j); temp_rho.push_back(i);
                A[i][j] = sampleNTT(temp_rho);
            }
        }
        for(int i = 0; i < k; i++){
            y[i] = samplePolyCBD( pseudo_random_eta(eta1, r, N) , eta1);
            y[i] = NTT(y[i]);
            N++;
        }
        for(int i = 0; i < k; i++){
            error1[i] = samplePolyCBD( pseudo_random_eta(eta2, r, N) , eta2);
            N++;
        }
        error2 = samplePolyCBD( pseudo_random_eta(eta2, r, N) , eta2);
        //generate output function
        for(int i = 0; i < k; i++){
            std::vector<int> u_temp(256,0);
            for(int j = 0; j < k; j++){
                polyAdd( u_temp, NTTmultiply(A[j][i],y[j]) );
            }
            u_temp = NTTinverse(u_temp);
            polyAdd( u_temp, error1[i] );
            u[i] = u_temp;
        }
        //encode message
        mu = decompress(byteDecode(m,1), 1);
        //genarate output result
        for(int j = 0; j < k; j++){
            polyAdd( v, NTTmultiply(t[j],y[j]) );
        }
        v = NTTinverse(v);
        polyAdd( v, error2 );
        polyAdd( v, mu );

        //compress function
        std::vector<Byte> cypher1(0);
        for(int i = 0; i < k; i++){
            std::vector<Byte> cypher_part = byteEncode( compress(u[i], du), du);
            cypher1.insert( cypher1.end(), cypher_part.begin(), cypher_part.end() );
        }
        //compress result
        std::vector<Byte> cypher2 = byteEncode( compress(v, dv), dv);

        //output cyphertext
        std::vector<Byte> encoded_text(0);
        encoded_text.insert( encoded_text.begin(), cypher1.begin(), cypher1.end() );
        encoded_text.insert( encoded_text.end(), cypher2.begin(), cypher2.end() );
        cyphertext = encoded_text;
        //*/

        //printInts(u[0]);
        //printInts(v);

        return true;
    }

    //rememeber to initialize arrays properly
    bool KPKE_KeyGen( std::vector<Byte> d, std::vector<Byte>& ek, std::vector<Byte>& dk ){
        using namespace Algorithms;
        using namespace std;
        //set n and randomness
        std::vector<Byte> randomness(d); randomness.push_back(k);
        Byte N = 0x0;
        //generate rho and sigma from hash of randomness
        vector<Byte> seeds = hashG(randomness);
        vector<Byte> rho(32);
        vector<Byte> sigma(32);
        copy( seeds.begin(), seeds.begin() + 32, rho.begin() );
        copy( seeds.begin() + 32, seeds.end(), sigma.begin() );

        vector<int> A[k][k];
        vector<int> s[k];
        vector<int> e[k];
        vector<int> t[k];
        //generate matrix "A"
        for(int i = 0; i < k; i++){
            for(int j = 0; j < k; j++){
                vector<Byte> temp_rho(rho); temp_rho.push_back(j); temp_rho.push_back(i);
                A[i][j] = sampleNTT(temp_rho);
            }
        }
        //sample secret key "s" and error "e"
        for(int i = 0; i < k; i++){
            s[i] = samplePolyCBD( pseudo_random_eta(eta1, sigma, N) , eta1);
            N++;
        }
        for(int i = 0; i < k; i++){
            e[i] = samplePolyCBD( pseudo_random_eta(eta1, sigma, N) , eta1);
            N++;
        }
        //convert "s" and "e" to NTT form
        for(int i = 0; i < k; i++){
            s[i] = NTT(s[i]);
            e[i] = NTT(e[i]);
        }
        //calculate ring array t
        for(int i = 0; i < k; i++){
            vector<int> temp_t(256,0);
            //sum of product of A and s
            for(int j = 0; j < k; j++){
                polyAdd( temp_t, NTTmultiply(A[i][j],s[j]) );
            }
            //add error
            polyAdd( temp_t, e[i] );
            t[i] = temp_t;
        }

        //printInts(s[0]);
        //printInts(s[1]);

        //return encryption key
        vector<Byte> encryption_key(0);
        for(int i = 0; i < k; i++){
            std::vector<Byte> ek_part = byteEncode(t[i],12);
            encryption_key.insert(encryption_key.end(), ek_part.begin(), ek_part.end());
        }
        encryption_key.insert( encryption_key.end(), rho.begin(), rho.end() );
        ek = encryption_key;
        //return decryption key
        vector<Byte> decryption_key(0);
        for(int i = 0; i < k; i++){
            std::vector<Byte> dk_part = byteEncode(s[i],12);
            decryption_key.insert(decryption_key.end(), dk_part.begin(), dk_part.end());
        }
        dk = decryption_key;
        return true;
    }
    
    //RYAN: My code ends here

    /*
        Encrypts the plaintext using AES-256 in CBC mode
        @param plaintext: the plaintext to be encrypted
        @param ciphertext: the encrypted data
        @return true if encryption is successful, false otherwise
    */
    bool EncryptData(const std::vector<Byte>& plaintext, std::vector<Byte>& ciphertext, std::vector<Byte>& secret_key) {

        const std::array<Byte, 16>& iv = preSharedIV;
        
        // Create a new context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            Log::Error("EncryptData()", "Error creating cipher context\n");
            return false;
        }
        
        /*
            Initialize the encryption operation with a cipher type, key, and IV
            Here, we're using AES-256 in CBC mode
            NULL is passed for the cipher type to use the default
        */
        int initStatus = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret_key.data(), iv.data());
        if (initStatus != 1) {
            Log::Error("EncryptData()", "Error initializing encryption operation\n");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Resize the ciphertext vector to accommodate the encrypted data
        ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        
        /*
            Encrypts the plaintext data
            The ciphertext is written to the ciphertext vector
            The length of the ciphertext is returned in len
        */
        int len;
        int encryptionStatus = EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
        if (encryptionStatus != 1) {
            Log::Error("EncryptData()", "Error encrypting data\n");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Encrypts the "final" data; any data that remains in a partial block. It also writes out the padding.
        int ciphertextLen = len;
        int finalEncryptionStatus = EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        if (finalEncryptionStatus != 1) {
            Log::Error("EncryptData()", "Error encrypting final data\n");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        ciphertextLen += len;
        ciphertext.resize(ciphertextLen);
        
        // Free the context
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    
    /*
        Decrypts the ciphertext using AES-256 in CBC mode
        @param ciphertext: the ciphertext to be decrypted
        @param plaintext: the decrypted data
        @return true if decryption is successful, false otherwise
    */
    bool DecryptData(const std::vector<Byte>& ciphertext, std::vector<Byte>& plaintext, std::vector<Byte>& secret_key) {

        const std::array<Byte, 16>& iv = preSharedIV;

        // Create a new context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr) {
            Log::Error("DecryptData()", "Error creating cipher context\n");
            return false;
        }
        
        // Initialize the decryption operation with a cipher type, key, and IV
        int initStatus = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret_key.data(), iv.data());
        if (initStatus != 1) {
            Log::Error("DecryptData()", "Error initializing decryption operation\n");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Resize the plaintext vector to accommodate the decrypted data
        plaintext.resize(ciphertext.size());

        // Log the sizes of the ciphertext and plaintext
        // Log::Info("DecryptData()", "Ciphertext size: " + std::to_string(ciphertext.size()));
        // Log::Info("DecryptData()", "Plaintext size:  " + std::to_string(plaintext.size()));
        
        /*
            Decrypts the ciphertext data
            The plaintext is written to the plaintext vector
            The length of the plaintext is returned in len
        */
        int len;
        int decryptionStatus = EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
        if (decryptionStatus != 1) {
            Log::Error("DecryptData()", "Error decrypting data\n");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        
        // Decrypts the "final" data; any data that remains in a partial block. It also writes out the padding.
        int plaintextLen = len;
        int finalDecryptionStatus = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        if (finalDecryptionStatus != 1) {
            Log::Error("DecryptData()", "Error decrypting final data\n");
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        plaintextLen += len;
        plaintext.resize(plaintextLen);
        
        // Free the context
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    /*
        Calculates the SHA-256 hash of the given data
        @param data: data to be hashed
        @param hash: hash of the data
        @return If operation was successful or not
    */

    bool CalculateHash(const std::vector<Byte>& data, std::vector<Byte>& hash) {
        // Create a context for the hash operation
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) {
            Log::Error("CalculateHash()", "Error creating hash context");
            return false;
        }

        // Initialize the hash operation with SHA-256
        int initStatus = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        if (initStatus != 1) {
            Log::Error("CalculateHash()", "Error initializing hash operation");
            EVP_MD_CTX_free(ctx);
            return false;
        }

        // Provide the data to be hashed
        int updateStatus = EVP_DigestUpdate(ctx, data.data(), data.size());
        if (updateStatus != 1) {
            Log::Error("CalculateHash()", "Error updating hash operation");
            EVP_MD_CTX_free(ctx);
            return false;
        }

        // Finalize the hash operation and retrieve the hash value
        unsigned int hashLen;
        int finalStatus = EVP_DigestFinal_ex(ctx, hash.data(), &hashLen);
        if (finalStatus != 1) {
            Log::Error("CalculateHash()", "Error finalizing hash operation");
            EVP_MD_CTX_free(ctx);
            return false;
        }

        // Free the context
        EVP_MD_CTX_free(ctx);

        return true;
    }


    /*
        Below are functions implemention one of the most basic encryption algorithms, the Caesar cipher.
        The Caesar cipher is a substitution cipher where each letter in the plaintext is shifted by a
        fixed number of positions in the alphabet. In this case, we're using a shift of 3.
        This is just an example to show how you can implement your own encryption and decryption functions.
        You can replace these functions with any other encryption algorithm you want.
        The EncryptData and DecryptData functions are the same as the ones above, but they use the Caesar cipher
        instead of AES-256.

        Note that this is not a secure encryption method and should not be used for any real-world applications.
    */
    /*
    bool EncryptData(const std::vector<Byte>& plaintext, std::vector<Byte>& ciphertext) {

        const int shift = 3; // Shift value for Caesar cipher
        ciphertext.resize(plaintext.size());
        for (size_t i = 0; i < plaintext.size(); ++i) {
            ciphertext[i] = plaintext[i] + shift;
        }

        return true;
    }
    
    bool DecryptData(const std::vector<Byte>& ciphertext, std::vector<Byte>& plaintext) {

        const int shift = 3; // Shift value for Caesar cipher
        plaintext.resize(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            plaintext[i] = ciphertext[i] - shift;
        }

        return true;
    }
    */

    /*
        Basic hash function that calculates a simple hash of the data
        This is not a secure hash function and should not be used for any real-world applications
        It's just an example to show how you can implement your own hash function

        @param data: the data to be hashed
        @param hashResult: the resulting hash
        @return true (yes, its that simple) :)
    */
    /*
    bool BasicHashFunction(const std::vector<Byte>& data, std::vector<Byte>& hashResult) {

        // Initialize the hash result with 8 bytes, and fill them with 0s
        hashResult.resize(8);
        fill(hashResult.begin(), hashResult.end(), 0);

        // Do a simple hash calculation by adding the bytes together in a cyclic fashion
        // Groups of 8 bytes are added together to form the hash
        int hashIdx = 0;
        for (Byte byte : data) {
            hashResult[hashIdx++] += byte;
            hashIdx %= 8;
        }

        return true;
    }
    */
};