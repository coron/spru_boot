#ifndef MULTIPLE_SLOT_H
#define MULTIPLE_SLOT_H

#include "openfhe.h"

std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> BootstrapMultipleSlotsKeyGen(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc, 
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey,
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> secretKey,
    int h,uint32_t numSlots);

// Bootstrapping function
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BootstrapMultipleSlotsInternal(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, 
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& bootsk,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,
    int h,uint32_t scaleModSize,uint32_t numSlots);

std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> BootstrapMultipleSlotsKeyGenStep(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc, 
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey,
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> secretKey,
    int h,uint32_t numSlots,int step);

// Bootstrapping function
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> BootstrapMultipleSlotsInternalStep(
    const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext, 
    const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& bootsk,
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,
    int h,uint32_t scaleModSize,uint32_t numSlots,int step);


#endif // MULTIPLE_SLOT_H
