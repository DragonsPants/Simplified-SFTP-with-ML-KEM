#ifndef ALGORITHMS_SSFTP
#define ALGORITHMS_SSFTP

#include "utils.hpp"
#include <bitset>
#include <vector>
#include <array>

/*  RYAN
    Algorithms.cpp was created entirely by me and performs all of the auxiliary functions required to run ML-KEM
    It also provides functions for printing vectors of integers, bytes, and bits to console
*/

namespace Algorithms{
    
    void printInts(std::vector<int> ints);
    void printBits(std::vector<bool> bits);
    void printBytes(std::vector<Byte> bytes);
    std::vector<int> compress(std::vector<int> input, int d);
    std::vector<int> decompress(std::vector<int> input, int d);
    void polyAdd(std::vector<int>& f, std::vector<int> g);
    //tested
    std::vector<Byte> getRandomBytes( int size );
    std::vector<Byte> hashH( std::vector<Byte> seed );
    std::vector<Byte> hashJ( std::vector<Byte> seed, int hashSize );
    std::vector<int> polyMult(std::vector<int> f, std::vector<int> g,int n, int modulus);
    std::vector<Byte> bitsToBytes(std::vector<bool> bits);
    std::vector<bool> bytesToBits(std::vector<Byte> bytes);
    std::vector<Byte> byteEncode(std::vector<int> integers, int d);
    std::vector<int> byteDecode(std::vector<Byte> integers, int d);
    void calcZeta();
    std::vector<int> sampleNTT(std::vector<Byte> seed);
    std::vector<int> samplePolyCBD(std::vector<Byte> seed, int eta);
    std::vector<int> NTT(std::vector<int> function);
    std::vector<int> NTTinverse(std::vector<int> transform);
    std::vector<int> NTTmultiply( std::vector<int> f, std::vector<int> g);
    std::vector<int> baseCaseMultiply(int f1, int f2, int g1, int g2, int gamma);
    std::vector<Byte> hashG( std::vector<Byte> seed );
    std::vector<Byte> pseudo_random_eta( int eta, std::vector<Byte> input, Byte byte );

    const int q = 3329;
    const int n = 256;
    const int k = 2;
    const int eta1 = 3;
    const int eta2 = 2;
    const int du = 10;
    const int dv = 4;

    const std::array<int, 128> zetaAt = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154 };

    const std::array<int, 128> zetaAt2 = {
        17, -17, 2761, -2761, 583, -583, 2649, -2649,
        1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
        1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
        756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
        1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
        1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
        939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
        733, -733, 2337, -2337, 268, -268, 641, -641,
        1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
        375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
        1063, -1063, 319, -319, 2773, -2773, 757, -757,
        2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
        2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
        1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
        1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
        2110, -2110, 2935, -2935, 885, -885, 2154, -2154
        };

        /*
    const std::array<int, 128> zetaAt2 = {
        17, 3312, 2761, 568, 583, 2746, 2649, 680
    , 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229
    , 1409, 1920, 2662, 667, 3281, 48, 233, 3096
    , 756, 2573, 2156, 1173, 3015, 314, 3050, 279
    , 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540
    , 1847, 1482, 952, 2377, 1461, 1868, 2687, 642
    , 939, 2390, 2308, 1021, 2437, 892, 2388, 941
    , 733, 2596, 2337, 992, 268, 3061, 641, 2688
    , 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109
    , 375, 2954, 2549, 780, 2090, 1239, 1645, 1684
    , 1063, 2266, 319, 3010, 2773, 556, 757, 2572
    , 2099, 1230, 561, 2768, 2466, 863, 2594, 735
    , 2804, 525, 1092, 2237, 403, 2926, 1026, 2303
    , 1143, 2186, 2150, 1179, 2775, 554, 886, 2443
    , 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300
    , 2110, 1219, 2935, 394, 885, 2444, 2154, 1175
    };
    */
};

#endif