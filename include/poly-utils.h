#ifndef POLY_UTILS_H
#define POLY_UTILS_H

#include "openfhe.h"

// Converts a DCRTPoly to a Poly with a big modulus
lbcrypto::Poly PolyFromDCRTPoly(const lbcrypto::DCRTPoly& poly);

// Multiplies a NativePoly by X^i
lbcrypto::NativePoly ShiftRight(const lbcrypto::NativePoly& poly, uint32_t shift);

// Multiplies a DCRTPoly by X^i
lbcrypto::DCRTPoly ShiftRight(const lbcrypto::DCRTPoly& poly, uint32_t shift);

void printIntegerMod(const lbcrypto::BigInteger &x, const lbcrypto::BigInteger &q);
void printBigVectorMod(const lbcrypto::BigVector &x);
void printPoly(const lbcrypto::Poly &p);

#endif // POLY_UTILS_H

