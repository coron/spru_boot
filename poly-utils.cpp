#include "poly-utils.h"

using namespace lbcrypto;

// Converts a DCRTPoly to a Poly with a big modulus
Poly PolyFromDCRTPoly(const DCRTPoly& poly) {
    DCRTPoly polyCopy(poly);
    polyCopy.SetFormat(Format::COEFFICIENT);
    Poly result=polyCopy.CRTInterpolate();
    return result;
}

// Multiplies a NativePoly by X^i
NativePoly ShiftRight(const NativePoly& poly, uint32_t shift) {
    size_t N = poly.GetRingDimension();
    NativePoly shiftedPoly(poly);
    shiftedPoly.SetFormat(Format::COEFFICIENT);

    for (size_t j = 0; j < N; j++) {
        if (j >= shift ) {
            shiftedPoly[j] = poly[j - shift];
        } else {
            shiftedPoly[j] = poly.GetModulus() - poly[j - shift + N];       
        }
    }
    return shiftedPoly;
}

// Multiplies a DCRTPoly by X^i
DCRTPoly ShiftRight(const DCRTPoly& poly, uint32_t shift) {
    DCRTPoly shiftedPoly(poly);
    shiftedPoly.SetFormat(Format::COEFFICIENT);

    for (size_t i = 0; i < shiftedPoly.GetNumOfElements(); i++) {
        NativePoly element = shiftedPoly.GetElementAtIndex(i);
        element = ShiftRight(element, shift);
        shiftedPoly.SetElementAtIndex(i, element);
    }

    shiftedPoly.SetFormat(poly.GetFormat());
    return shiftedPoly;
}

void printIntegerMod(const BigInteger &x,const BigInteger &q)
{
    if(x>q/2)
        std::cout << "-" << (q-x);
    else
        std::cout << x;
}

void printBigVectorMod(const BigVector &x)
{
    std::cout << "[";
    for (size_t i = 0; i < x.GetLength(); i++) {
        printIntegerMod(x[i],x.GetModulus());
        if (i<x.GetLength()-1) std::cout << " ";
    }
    std::cout << "]";
}

void printPoly(const Poly &p)
{
    std::cout << "[";
    for (size_t i = 0; i < p.GetLength(); i++) {
        printIntegerMod(p[i],p.GetModulus());
        if (i<p.GetLength()-1) std::cout << " ";
    }
    std::cout << "]";
}