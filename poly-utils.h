#ifndef POLY_UTILS_H
#define POLY_UTILS_H

#include "openfhe.h"

using namespace lbcrypto;

// Converts a DCRTPoly to a Poly with a big modulus
Poly PolyFromDCRTPoly(const DCRTPoly& poly);

// Multiplies a NativePoly by X^i
NativePoly ShiftRight(const NativePoly& poly, uint32_t shift);

// Multiplies a DCRTPoly by X^i
DCRTPoly ShiftRight(const DCRTPoly& poly, uint32_t shift);

void printIntegerMod(const BigInteger &x,const BigInteger &q);
void printBigVectorMod(const BigVector &x);
void printPoly(const Poly &p);

#endif // POLY_UTILS_H

