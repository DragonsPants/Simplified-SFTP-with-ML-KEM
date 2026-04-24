#include "../include/shake.hpp"
#include "../include/algorithms.hpp"
#include "../include/crypto.hpp"
#include "../include/logger.hpp"
#include "../include/utils.hpp"

#include <iostream>
#include <bitset>
#include <vector>
#include <cmath>

/*  RYAN
    tester.cpp was created by me
    tester.cpp runs the ML-KEM functions ML_KEM_KeyGen, ML_KEM_Encaps
    and ML_KEM_Decaps and prints their outputs
*/

int main(int argc, char* argv[]) {
    using namespace std;
    using namespace Algorithms;

    vector<Byte> encaps_key;
    vector<Byte> decaps_key;
    vector<Byte> secret_key;
    vector<Byte> decaps_secret_key;
    vector<Byte> cyphertext;

    bool keygenSuccess = Crypto::ML_KEM_KeyGen( encaps_key, decaps_key );
    if ( !keygenSuccess ){
        cout << "keygen failure\n";
    }
    cout << "Encaps key Length = " << encaps_key.size() << "\n";
    cout << "Encaps key:\n";
    Algorithms::printBytes( encaps_key);
    cout << "\n=================================\n";
    cout << "Decaps key Length = " << decaps_key.size() << "\n";
    cout << "Decaps key:\n";
    Algorithms::printBytes( decaps_key);
    cout << "\n=================================\n";

    if ( !Crypto::ML_KEM_Encaps( encaps_key, secret_key, cyphertext ) ){
        cout << "encaps failure\n";
    }
    std::cout << "Cyphertext length = " << cyphertext.size() << "\n";
    cout << "Cyphertext:\n";
    Algorithms::printBytes( cyphertext);
    cout << "\n=================================\n";

    cout << "Secret key K from Encaps method:\n";
    Algorithms::printBytes( secret_key );
    cout << "\nLength of K = " << secret_key.size();
    cout << "\n=================================\n";

    if ( !Crypto::ML_KEM_Decaps( decaps_key, cyphertext, decaps_secret_key ) ){
        cout << "decaps failure\n";
    }
    cout << "Secret key K' from Decaps method:\n";
    Algorithms::printBytes( decaps_secret_key );
    cout << "\nLength of K' = " <<  decaps_secret_key.size();
    cout << "\n=================================\n";

    //*/
}