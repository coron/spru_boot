#ifndef SLOTS_TO_COEFFS_UTILS_H
#define SLOTS_TO_COEFFS_UTILS_H

#include <iostream>
#include <vector>
#include <complex>
#include <memory>
#include "openfhe.h"

using namespace lbcrypto;

// Function to convert slots to coefficients
Ciphertext<DCRTPoly> SlotsToCoeffs(const CryptoContext<DCRTPoly>& cryptoContext, const Ciphertext<DCRTPoly>& ciph);

// Function to set up the SlotsToCoeffs operation
void EvalSlotsToCoeffsSetup(
    const CryptoContext<DCRTPoly>& cryptoContext,
    uint32_t levelBudget,
    uint32_t numSlots,
    uint32_t lDec);

// Test function for SlotsToCoeffs
void testSlots2Coeffs();

#endif // SLOTS_TO_COEFFS_UTILS_H
