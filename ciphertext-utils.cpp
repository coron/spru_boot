#include "ciphertext-utils.h"

using namespace lbcrypto;

// Multiplies a ciphertext by X^i
Ciphertext<DCRTPoly> ShiftRight(const Ciphertext<DCRTPoly>& ciphertext,uint32_t shift) {
    Ciphertext<DCRTPoly> shiftedCiphertext = ciphertext->Clone();
    std::vector<DCRTPoly> elements = shiftedCiphertext->GetElements();
    for (size_t i = 0; i < elements.size(); i++) {
        elements[i] = ShiftRight(elements[i],shift);
    }
    shiftedCiphertext->SetElements(elements);
    return shiftedCiphertext;
}

Poly myDecrypt(const Ciphertext<DCRTPoly>& c, const PrivateKey<DCRTPoly> privateKey) {
    const std::vector<DCRTPoly>& cv = c->GetElements();
    DCRTPoly s(privateKey->GetPrivateElement());
    s.DropLastElements(s.GetNumOfElements() - cv[0].GetNumOfElements());
    DCRTPoly b(cv[0]);
    b.SetFormat(Format::EVALUATION);
    DCRTPoly c11(cv[1]);
    c11.SetFormat(Format::EVALUATION);
    b += s * c11;
    return PolyFromDCRTPoly(b);
}

BigVector LWEfromCiph(const Ciphertext<DCRTPoly>& ciphertext) {
    BigVector c1vtemp = PolyFromDCRTPoly(ciphertext->GetElements()[1]).GetValues();
    BigVector c1v(c1vtemp);
    BigInteger q = c1v.GetModulus();

    for (size_t i = 1; i < c1vtemp.GetLength(); i++) {
        c1v[i] = q - c1vtemp[c1vtemp.GetLength() - i]; // OpenFHE doesn't know negative integers !
    }

    c1v[0] = (c1vtemp[0] + PolyFromDCRTPoly(ciphertext->GetElements()[0])[0]) % q;

    return c1v;
}

BigInteger DecryptLWE(const Ciphertext<DCRTPoly>& ciphertext, const PrivateKey<DCRTPoly>& privateKey) {
    BigVector c1v = LWEfromCiph(ciphertext);
    BigVector skv = PolyFromDCRTPoly(privateKey->GetPrivateElement()).GetValues();

    BigInteger val = 0;
    for (size_t i = 0; i < c1v.GetLength(); i++) {
        val += c1v[i] * skv[i];
    }

    return val % c1v.GetModulus();
}

BigVector DecryptLWE(const Ciphertext<DCRTPoly>& ciphertext, const PrivateKey<DCRTPoly>& privateKey, int n) {
    BigVector skv = PolyFromDCRTPoly(privateKey->GetPrivateElement()).GetValues();
    
    size_t N=ciphertext->GetCryptoContext()->GetRingDimension();
    BigVector v(n);

    BigInteger q=ciphertext->GetElements()[0].GetModulus();
    v.SetModulus(q);

    for (size_t j = 0; j < n; j++) {
        BigVector cv=LWEfromCiph(ShiftRight(ciphertext,N-j*N/n));
        BigInteger val=0;
        for (size_t i = 0; i < N; i++) {
            val +=(q-cv[i]) * skv[i];
        }
        v[j] = val % q;
    }

    return v;
}

Ciphertext<DCRTPoly> CiphertextConjugate(const Ciphertext<DCRTPoly>& ciphertext, 
                                         const CryptoContext<DCRTPoly>& cc) {
    uint32_t indexConj = 2 * cc->GetRingDimension() - 1;
    auto evalConjKeyMap = cc->GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
    return cc->EvalAutomorphism(ciphertext, indexConj, evalConjKeyMap);
}

Plaintext MakePlaintext(const CryptoContext<DCRTPoly> &cc,double val,uint32_t level)
{
    std::vector<std::complex<double>> x1;
    for (size_t i = 0; i < cc->GetRingDimension()/2 ;i++) {
        x1.push_back(std::complex<double>(val, 0.0));
    }
    return cc->MakeCKKSPackedPlaintext(x1, 1,level);
}

Plaintext MakePlaintext(const CryptoContext<DCRTPoly> &cc,std::vector<std::complex<double>> v,uint32_t level)
{
    std::vector<std::complex<double>> x1;
    uint32_t numSlots=v.size();
    for (size_t i = 0; i < cc->GetRingDimension()/2/numSlots ;i++) {
        for(size_t j = 0; j < numSlots; j++) {
            x1.push_back(v[j]);
        }
    }
    return cc->MakeCKKSPackedPlaintext(x1, 1,level);
}

Plaintext MakePlaintext(const CryptoContext<DCRTPoly> &cc,std::vector<double> v,uint32_t level)
{
    std::vector<std::complex<double>> x1;
    uint32_t numSlots=v.size();
    for (size_t i = 0; i < cc->GetRingDimension()/2/numSlots ;i++) {
        for(size_t j = 0; j < numSlots; j++) {
            x1.push_back(std::complex<double>(v[j],0));
        }
    }
    return cc->MakeCKKSPackedPlaintext(x1, 1,level);
}

std::vector<std::complex<double>> DecryptCKKSPackedValue(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const PrivateKey<DCRTPoly>& privateKey, 
    uint32_t numSlots) {

    Plaintext result;
    ciphertext->GetCryptoContext()->Decrypt(privateKey, ciphertext, &result);
    result->SetLength(numSlots);
    return result->GetCKKSPackedValue();
}

std::vector<double> genUniformReal(uint32_t n) {
    std::vector<double> vec(n);
    std::random_device rd;  
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.5, 1.0);
    for (size_t i = 0; i < n; i++) {
        vec[i] = dis(gen);
    }
    return vec;
}

double estimatePrecision(std::vector<std::complex<double>> &v1, std::vector<std::complex<double>> &v2) {
    double precVal=0.;
    uint32_t n=v1.size();
    for(size_t i=0; i<n; i++) {
        double prec=-std::log2(abs(v1[i].real()-v2[i].real())/abs(v2[i].real()));
        precVal+=prec;
    }
    return precVal/n;
}