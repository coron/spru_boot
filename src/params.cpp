#include "params.h"
#include "utils.h"

using namespace lbcrypto;

// Compute multiplicative depth for SPRU bootstrapping: nh + 1 + levelBudget
uint32_t spruMultiplicativeDepth(uint32_t h, uint32_t levelBudget)
{
    uint32_t nh = bitLength(h);
    return nh + 1 + levelBudget;
}

// levelBudget is the number of levels consumed by Slots2Coeffs.
CCParams<CryptoContextCKKSRNS> genParameters(uint32_t h,uint32_t levelBudget=0)
{
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 49; 

    // For numSlots=1, with levelBudget=0, we can have 4 levels after bootstrapping
    // For numSlots>1, with levelBudget=1, we can have 3 levels after bootstrapping

    uint32_t levelsAvailableAfterBootstrap = 1; //13-levelBudget; //4 - levelBudget;
    uint32_t multDepth = levelsAvailableAfterBootstrap + spruMultiplicativeDepth(h, levelBudget);

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDAUTO);
    parameters.SetCKKSDataType(COMPLEX);

    return parameters;
}