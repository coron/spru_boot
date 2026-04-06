#ifndef SLOTS_TO_COEFFS_UTILS_H
#define SLOTS_TO_COEFFS_UTILS_H

#include <iostream>
#include <vector>
#include <complex>
#include <memory>
#include "openfhe.h"


// Function to convert slots to coefficients
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> SlotsToCoeffs(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cryptoContext, 
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciph);

// Function to set up the SlotsToCoeffs operation
void EvalSlotsToCoeffsSetup(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cryptoContext,
    uint32_t levelBudget,
    uint32_t numSlots,
    uint32_t lDec);

// Test function for SlotsToCoeffs
void testSlots2Coeffs();

#endif // SLOTS_TO_COEFFS_UTILS_H
