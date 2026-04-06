// Generation of the encrypted secret key for bootstrapping, for a single slot

#include "single_slot.h"
#include "ciphertext-utils.h"

using namespace lbcrypto;

std::vector<Ciphertext<DCRTPoly>> BootstrapSingleSlotKeyGen(
    const CryptoContext<DCRTPoly>& cc, 
    const PublicKey<DCRTPoly>& publicKey,
    const PrivateKey<DCRTPoly>& secretKey,
    int h) {

    size_t N = cc->GetRingDimension();
    std::vector<std::complex<double>> sv1(N/2),sv2(N/2);

    BigVector skv = PolyFromDCRTPoly(secretKey->GetPrivateElement()).GetValues();

    size_t B=N/h;

    for (size_t k = 0; k < h; k++) {
        for (size_t i = 0; i < B/2; i++) {
            sv1[i*h+k] = std::complex<double>(skv[ k * B + i].ConvertToDouble(), 0.);
            sv2[i*h+k] = std::complex<double>(skv[ k * B + i + B/2].ConvertToDouble(), 0.);
        }
    }

    Plaintext ptsk1 = cc->MakeCKKSPackedPlaintext(sv1);
    Plaintext ptsk2 = cc->MakeCKKSPackedPlaintext(sv2);

    auto esk1 = cc->Encrypt(publicKey, ptsk1);
    auto esk2 = cc->Encrypt(publicKey, ptsk2);

    std::vector<Ciphertext<DCRTPoly>> result(2);
    result[0]=esk1;
    result[1]=esk2;
    return result;
}

// Bootstrapping function, for a single slot
Ciphertext<DCRTPoly> BootstrapSingleSlot(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const std::vector<Ciphertext<DCRTPoly>>& bootsk,
    const CryptoContext<DCRTPoly> &cc,
    int h,uint32_t scaleModSize) {
    
    BigVector c1v = LWEfromCiph(ciphertext);
    
    size_t N=c1v.GetLength();
    
    BigInteger q = c1v.GetModulus();
    double pi = M_PI;

    size_t B=N/h;
    
    double scaleCiph=1.;
    double scale=pow(q.ConvertToDouble() / (4. * pi) / pow(2.,scaleModSize) /scaleCiph,1./h);

    std::vector<std::complex<double>> v1(N/2),v2(N/2);

    for (size_t k = 0; k < h; k++) {
        for (size_t i = 0; i < B/2; i++) {
            double angle = 2. * pi * c1v[k * B + i].ConvertToDouble() *scaleCiph  / q.ConvertToDouble();
            v1[i * h+k] = std::complex<double>(scale*cos(angle), scale*sin(angle));
            
            angle= 2. * pi * c1v[k * B + i + B/2].ConvertToDouble() * scaleCiph/ q.ConvertToDouble();
            v2[i * h + k] = std::complex<double>(scale*cos(angle),scale*sin(angle));
        }
    }

    auto esk1 = bootsk[0]; 
    auto esk2 = bootsk[1];  

    auto cmult1=cc->EvalMult(esk1, cc->MakeCKKSPackedPlaintext(v1));
    auto cmult2=cc->EvalMult(esk2, cc->MakeCKKSPackedPlaintext(v2));
    
    auto cadd=cc->EvalAdd(cmult1, cmult2);
    
    size_t irot=N/4;
    size_t nB = static_cast<size_t>(std::round(std::log2(B)));

    for (size_t k = 0; k < (nB-1); k++) {
        cadd=cadd+cc->EvalRotate(cadd, irot);
        irot=irot/2;
    }

    size_t nh=static_cast<size_t>(std::round(std::log2(h)));

    for (size_t k = 0; k < nh; k++) {
        cadd=cc->EvalMult(cadd, cc->EvalRotate(cadd, irot));
        irot=irot/2;
    }

    cadd = cc->EvalSub(CiphertextConjugate(cadd,cc),cadd);
    cadd=ShiftRight(cadd,N/2); // We multiply by I

    return cadd; 
}