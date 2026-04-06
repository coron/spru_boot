#ifndef SINGLE_SLOT_H
#define SINGLE_SLOT_H

#include "openfhe.h"


// Generation of the encrypted secret key for bootstrapping, for a single slot
std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> BootstrapSingleSlotKeyGen(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc, 
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
    const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& secretKey,
    int h);

// Bootstrapping function, for a single slot
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BootstrapSingleSlot(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, 
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& bootsk,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,
    int h,uint32_t scaleModSize);

#endif // SINGLE_SLOT_H
