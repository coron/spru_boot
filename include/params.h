

#ifndef PARAMS_H
#define PARAMS_H

#include "openfhe.h"

// Compute multiplicative depth for SPRU bootstrapping: nh + 1 + levelBudget
uint32_t spruMultiplicativeDepth(uint32_t h, uint32_t levelBudget);

lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> genParameters(uint32_t h,uint32_t levelBudget);

#endif // PARAMS_H
