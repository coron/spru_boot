#ifndef CIPHERTEXT_UTILS_H
#define CIPHERTEXT_UTILS_H

#include "openfhe.h"
#include "poly-utils.h"

using namespace lbcrypto;

// Function to shift a ciphertext to the right by X^i
Ciphertext<DCRTPoly> ShiftRight(const Ciphertext<DCRTPoly>& ciphertext, uint32_t shift);

// Function to decrypt a ciphertext into a Poly
Poly myDecrypt(const Ciphertext<DCRTPoly>& c, const PrivateKey<DCRTPoly> privateKey);

// Function to extract LWE representation from a ciphertext
BigVector LWEfromCiph(const Ciphertext<DCRTPoly>& ciphertext);

// Function to decrypt LWE ciphertext into a single BigInteger
BigInteger DecryptLWE(const Ciphertext<DCRTPoly>& ciphertext, const PrivateKey<DCRTPoly>& privateKey);

// Function to decrypt LWE ciphertext into a BigVector of size n
BigVector DecryptLWE(const Ciphertext<DCRTPoly>& ciphertext, const PrivateKey<DCRTPoly>& privateKey, int n);

// Function to compute the conjugate of a ciphertext
Ciphertext<DCRTPoly> CiphertextConjugate(const Ciphertext<DCRTPoly>& ciphertext, 
                                         const CryptoContext<DCRTPoly>& cc);

Plaintext MakePlaintext(const CryptoContext<DCRTPoly> &cc,double val,uint32_t level);
Plaintext MakePlaintext(const CryptoContext<DCRTPoly> &cc,std::vector<std::complex<double>> v,uint32_t level);
Plaintext MakePlaintext(const CryptoContext<DCRTPoly> &cc,std::vector<double> v,uint32_t level);

std::vector<std::complex<double>> DecryptCKKSPackedValue(const Ciphertext<DCRTPoly>& ciphertext, const PrivateKey<DCRTPoly>& privateKey, uint32_t numSlots);

std::vector<double> genUniformReal(uint32_t n);
double estimatePrecision(std::vector<std::complex<double>> &v1, std::vector<std::complex<double>> &v2);

#endif // CIPHERTEXT_UTILS_H
