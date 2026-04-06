
#include "utils.h"
#include <cmath>

// Compute the bit length (log2) of an integer
uint32_t bitLength(uint32_t x) {
    return static_cast<uint32_t>(std::round(std::log2(x)));
}

// We do not reverse the most significant bit
uint32_t reversebit(uint32_t i, uint32_t k) {
    uint32_t reversed = i & (1 << (k - 1)); // Keep the most significant bit
    for (uint32_t bit = 0; bit < k-1; ++bit) {
        if (i & (1 << bit)) {
            reversed |= (1 << (k - 2 - bit));
        }
    }
    return reversed;
}

void testReversedBits() {
    uint32_t k = 4; // Number of bits to reverse
    for (uint32_t i = 0; i < (1 << k); ++i) {
        uint32_t reversed = reversebit(i, k);
        std::cout << "Original: " << std::bitset<4>(i) << " Reversed: " << std::bitset<4>(reversed) << std::endl;
    }
}