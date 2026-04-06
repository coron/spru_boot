#include "multiple_slot.h"
#include "ciphertext-utils.h"
#include "utils.h"
#include "slotstocoeffs-utils.h"

using namespace lbcrypto;

std::vector<Ciphertext<DCRTPoly>> BootstrapMultipleSlotsKeyGen(
    const CryptoContext<DCRTPoly>& cc, 
    PublicKey<DCRTPoly> publicKey,
    PrivateKey<DCRTPoly> secretKey,
    int h,uint32_t numSlots) {

    uint32_t n=numSlots*2;
    size_t N = cc->GetRingDimension();
    size_t B=N/h;
    
    if (B < 2 * n) {
        std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << std::endl;
        throw std::invalid_argument("B must be >= 2 * n");
    }

    std::vector<std::vector<std::complex<double>>> sv(2*n);

    for(size_t u=0; u < 2*n; u++) {
        sv[u].resize(N/2);
    }   

    BigVector skv = PolyFromDCRTPoly(secretKey->GetPrivateElement()).GetValues();

    for (size_t a = 0; a < n; a++) {  // index of the LWE ciphertext, low order index in the encoded ciphertext
        for (size_t u=0; u < 2*n; u++) { // high-order index in the block, index of the encoded ciphertext, handled by the sum of ciphertexts
            for (size_t k = 0; k < B/(2*n); k++) { // low-order index in the block, high-order index in the encoded ciphertext, handled by the trace
                for (size_t b = 0; b < h; b++) {  // index of the block, middle index in the encoded ciphertext, handled by the product operator
                  sv[u][k*h*n+b*n+a] = std::complex<double>(skv[ b*B+u*B/(2*n)+k].ConvertToDouble(), 0.);
                }
            }
        }
    }

    std::vector< Ciphertext<DCRTPoly> > esv(2*n);

    for(size_t u=0; u < 2*n; u++) {
        esv[u] = cc->Encrypt(publicKey, cc->MakeCKKSPackedPlaintext(sv[u])); 
    }

    return esv;
}


// Bootstrapping function
Ciphertext<DCRTPoly> BootstrapMultipleSlotsInternal(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const std::vector<Ciphertext<DCRTPoly>>& bootsk,
    const CryptoContext<DCRTPoly> &cc,
    int h,uint32_t scaleModSize,uint32_t numSlots) {

    size_t N=ciphertext->GetCryptoContext()->GetRingDimension();

    std::vector<std::complex<double>> vres;
    size_t B=N/h;
    size_t n=numSlots*2;

    std::vector<std::vector<std::complex<double>>> v(2*n);

    for(size_t u=0; u < 2*n; u++) {
        v[u].resize(N/2);
    }   

    BigInteger q = ciphertext->GetElements()[0].GetModulus();
    double pi = M_PI;

    if (B < 2 * n) {
        throw std::invalid_argument("B must be >= 2 * n");
    }

    if (numSlots < 2) {
        throw std::invalid_argument("numSlots must be >= 2");
    }

    double scaleCiph=4.;
    double scale=pow(q.ConvertToDouble() / (4. * pi) / pow(2.,scaleModSize) /scaleCiph,1./h);
 
    size_t nsize = static_cast<size_t>(std::round(std::log2(n)));

    // a: index of the LWE ciphertext => low order index in the encoded ciphertext, in bitreversed order.
    // b: index of the block => middle index in the encoded ciphertext, handled by the product operator
    // u: high-order index in the block => index of the encoded ciphertext, handled by the sum of ciphertexts
    // k: low-order index in the block => high-order index in the encoded ciphertext, handled by the trace

    #pragma omp parallel for
    for (size_t a = 0; a < n; a++) {  // index of the LWE ciphertext, low order index in the encoded ciphertext
        uint32_t rev = reversebit(a, nsize);
        BigVector c1v = LWEfromCiph(ShiftRight(ciphertext,N-rev*N/n));
        for (size_t b = 0; b < h; b++) {  // index of the block
            for (size_t u=0; u < 2*n; u++) { // high-order index in the block, index of the encoded ciphertext, 
                for (size_t k = 0; k < B/(2*n); k++) { // low-order index in the block        
                     double angle = -2. * pi * c1v[b * B + u*B/(2*n) + k].ConvertToDouble() *scaleCiph / q.ConvertToDouble();
                     v[u][k*h*n+b*n+a] = std::complex<double>(scale*cos(angle), scale*sin(angle));
                }
            }
        }
    }

    std::vector< Ciphertext<DCRTPoly> > eprod(2*n);

    #pragma omp parallel for
    for(size_t u=0; u < 2*n; u++) {
        eprod[u] = cc->EvalMult(bootsk[u], cc->MakeCKKSPackedPlaintext(v[u]));
    }

    Ciphertext<DCRTPoly> evs=eprod[0]; 

    for (size_t u = 1; u < 2*n; u++) {
        evs=cc->EvalAdd(evs,eprod[u]);
    }

    size_t irot=N/4;
    size_t nB2n = static_cast<size_t>(std::round(std::log2(B/(2*n))));

    //std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << std::endl;

    for (int k = 0; k < nB2n; k++) {
        evs=evs+cc->EvalRotate(evs, irot);
        irot=irot/2;
    }

    size_t nh=static_cast<size_t>(std::round(std::log2(h)));

    for (size_t k = 0; k < nh; k++) {
        evs=cc->EvalMult(evs, cc->EvalRotate(evs, irot));
        irot=irot/2;
    }

    evs = cc->EvalSub(CiphertextConjugate(evs,cc),evs);
    evs=ShiftRight(evs,N/2); // We multiply by I

    evs->SetSlots(n/2);

    cc->GetScheme()->ModReduceInternalInPlace(evs,1);

    //std::cout << "Before S2C: level: " << evs->GetLevel() << " Encoding scale:" << log2(evs->GetScalingFactor()) << std::endl;

    Ciphertext<DCRTPoly> evsf = SlotsToCoeffs(cc, evs);
    
    return evsf;
}


std::vector<Ciphertext<DCRTPoly>> BootstrapMultipleSlotsKeyGenStep(
    const CryptoContext<DCRTPoly>& cc, 
    PublicKey<DCRTPoly> publicKey,
    PrivateKey<DCRTPoly> secretKey,
    int h,uint32_t numSlots,int step) {

    if (step==1)
        return BootstrapMultipleSlotsKeyGen(cc,publicKey,secretKey,h,numSlots);

    uint32_t n=numSlots*2;
    size_t N = cc->GetRingDimension();
    size_t B=N/h;
    
    // we must have step <= 2*n <= B*step

    if (B*step < 2 * n) {
        std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << " step=" << step << std::endl;
        throw std::invalid_argument("B*step must be >= 2 * n");
    }

    if (step > 2*n) {
        std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << " step=" << step << std::endl;
        throw std::invalid_argument("step must be <= 2 * n");
    }

    std::vector<std::vector<std::complex<double>>> sv(2*n);

    for(size_t k=0; k < 2*n/step; k++) {
        sv[k].resize(N/2);
    }   

    BigVector skv = PolyFromDCRTPoly(secretKey->GetPrivateElement()).GetValues();

    for (size_t j = 0; j < n; j++) {  // index of the LWE ciphertext, low order index in the encoded ciphertext
        for (size_t k=0; k < 2*n/step; k++) { // high-order index in the block, index of the encoded ciphertext, 
            for (size_t i2 = 0; i2 < B*step/(2*n); i2+=step) { // low-order index in the block
                for (size_t i1 = 0; i1 < h; i1++) {  // index of the block
                  sv[k][i2/step*h*n+i1*n+j] = std::complex<double>(skv[ i1*B+k*B*step/(2*n)+i2].ConvertToDouble(), 0.);
                }
            }
        }
    }

    std::vector< Ciphertext<DCRTPoly> > esv(2*n);

    for(size_t u=0; u < 2*n/step; u++) {
        esv[u] = cc->Encrypt(publicKey, cc->MakeCKKSPackedPlaintext(sv[u])); 
    }

    return esv;
}

// Bootstrapping function
Ciphertext<DCRTPoly> BootstrapMultipleSlotsInternalStep(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const std::vector<Ciphertext<DCRTPoly>>& bootsk,
    const CryptoContext<DCRTPoly> &cc,
    int h,uint32_t scaleModSize,uint32_t numSlots,int step) {

    if (step==1)
        return BootstrapMultipleSlotsInternal(ciphertext, bootsk, cc, h, scaleModSize, numSlots);   

    size_t N=ciphertext->GetCryptoContext()->GetRingDimension();

    std::vector<std::complex<double>> vres;
    size_t B=N/h;
    size_t n=numSlots*2;

    std::vector<std::vector<std::complex<double>>> v(2*n);

    for(size_t u=0; u < 2*n/step; u++) {
        v[u].resize(N/2);
    }   

    BigInteger q = ciphertext->GetElements()[0].GetModulus();
    double pi = M_PI;

    if (B*step < 2 * n) {
        std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << " step=" << step << std::endl;
        throw std::invalid_argument("B*step must be >= 2 * n");
    }

    if (step > 2*n) {
        std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << " step=" << step << std::endl;
        throw std::invalid_argument("step must be <= 2 * n");
    }

    if (numSlots < 2) {
        throw std::invalid_argument("numSlots must be >= 2");
    }

    double scaleCiph=4.;
    double scale=pow(q.ConvertToDouble() / (4. * pi) / pow(2.,scaleModSize) /scaleCiph,1./h);
 
    size_t nsize = static_cast<size_t>(std::round(std::log2(n)));

    #pragma omp parallel for
    for (size_t j = 0; j < n; j++) {  // index of the LWE ciphertext, low order index in the encoded ciphertext
        uint32_t rev = reversebit(j, nsize);
        BigVector c1v = LWEfromCiph(ShiftRight(ciphertext,N-rev*N/n));
        for (size_t k=0; k < 2*n/step; k++) { // high-order index in the block, index of the encoded ciphertext, 
            for (size_t i2 = 0; i2 < B*step/(2*n); i2+=step) { // low-order index in the block
                for (size_t i1 = 0; i1 < h; i1++) {  // index of the block
                double angle = -2. * pi * c1v[i1 * B + k*B*step/(2*n) + i2].ConvertToDouble() *scaleCiph / q.ConvertToDouble();
                v[k][i2/step*h*n+i1*n+j] = std::complex<double>(scale*cos(angle), scale*sin(angle));
                }
            }
        }
    }

    std::vector< Ciphertext<DCRTPoly> > eprod(2*n);

    #pragma omp parallel for
    for(size_t u=0; u < 2*n/step; u++) {
        eprod[u] = cc->EvalMult(bootsk[u], cc->MakeCKKSPackedPlaintext(v[u]));
    }

    Ciphertext<DCRTPoly> evs=eprod[0]; 

    for (size_t u = 1; u < 2*n/step; u++) {
        evs=cc->EvalAdd(evs,eprod[u]);
    }

    size_t irot=N/4;
    size_t nB2n = static_cast<size_t>(std::round(std::log2(B/(2*n))));

    //std::cout << "N=" << N << " h=" << h << " B=" << B << " n=" << n << std::endl;

    for (int k = 0; k < nB2n; k++) {
        evs=evs+cc->EvalRotate(evs, irot);
        irot=irot/2;
    }

    size_t nh=static_cast<size_t>(std::round(std::log2(h)));

    for (size_t k = 0; k < nh; k++) {
        evs=cc->EvalMult(evs, cc->EvalRotate(evs, irot));
        irot=irot/2;
    }

    evs = cc->EvalSub(CiphertextConjugate(evs,cc),evs);
    evs=ShiftRight(evs,N/2); // We multiply by I

    evs->SetSlots(n/2);

    cc->GetScheme()->ModReduceInternalInPlace(evs,1);

    //std::cout << "Before S2C: level: " << evs->GetLevel() << " Encoding scale:" << log2(evs->GetScalingFactor()) << std::endl;

    Ciphertext<DCRTPoly> evsf = SlotsToCoeffs(cc, evs);
    
    return evsf;
}
