#ifndef Ciphertext_UTILS_H
#define Ciphertext_UTILS_H

#include "openfhe.h"
#include "poly-utils.h"


// Function to shift a lbcrypto::Ciphertext to the right by X^i
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ShiftRight(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, uint32_t shift);

// Function to decrypt a lbcrypto::Ciphertext into a Poly
lbcrypto::Poly myDecrypt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly> privateKey);

// Function to extract LWE representation from a lbcrypto::Ciphertext
lbcrypto::BigVector LWEfromCiph(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c);

// Function to decrypt LWE lbcrypto::Ciphertext into a single BigInteger
lbcrypto::BigInteger DecryptLWE(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey);

// Function to decrypt LWE lbcrypto::Ciphertext into a BigVector of size n
lbcrypto::BigVector DecryptLWE(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey, int n);

// Function to compute the conjugate of a lbcrypto::Ciphertext
lbcrypto::Ciphertext<lbcrypto::DCRTPoly> CiphertextConjugate(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, 
                                         const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc);

lbcrypto::Plaintext MakePlaintext(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,double val,uint32_t level);
lbcrypto::Plaintext MakePlaintext(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,std::vector<std::complex<double>> v,uint32_t level);
lbcrypto::Plaintext MakePlaintext(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,std::vector<double> v,uint32_t level);

std::vector<std::complex<double>> DecryptCKKSPackedValue(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey, uint32_t numSlots);
std::vector<double> DecryptCKKSPackedValueReal(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey, uint32_t numSlots);
std::vector<int> DecryptCKKSPackedValueInt(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& c, const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey, uint32_t numSlots);

std::vector<double> genUniformReal(uint32_t n);
std::vector<double> genUniformBinary(uint32_t n);

#endif // Ciphertext_UTILS_H
