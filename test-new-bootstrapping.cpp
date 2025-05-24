#define PROFILE

#include "openfhe.h"
#include "poly-utils.h"
#include "ciphertext-utils.h"
#include "slotstocoeffs-utils.h"

#include <cmath>
#include <random>
#include <chrono>

using namespace lbcrypto;

CCParams<CryptoContextCKKSRNS> genParameters(uint32_t h,uint32_t levelBudget=0)
{
    uint32_t firstModSize = 60;
    uint32_t scaleModSize = 49; 

    // For numSlots=1, with levelBudget=0, we can have 4 levels after bootstrapping
    // For numSlots>1, with levelBudget=1, we can have 3 levels after bootstrapping

    uint32_t levelsAvailableAfterBootstrap = 1; //13-levelBudget; //4 - levelBudget;
    size_t nh=static_cast<size_t>(std::round(std::log2(h)));
    uint32_t multDepth = levelsAvailableAfterBootstrap + nh + 1 + levelBudget;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CKKSDataType ckksDataType = COMPLEX;
    parameters.SetCKKSDataType(ckksDataType);

    return parameters;
}

// We generate a block binary secret key, where the first bit is always 1
DCRTPoly genBlockSparseKey(CryptoContext<DCRTPoly> &cc, int h) {
    
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(cc->GetCryptoParameters());
    const std::shared_ptr<DCRTPoly::Params> paramsPK = cryptoParams->GetParamsPK();
    DCRTPoly::TugType tug;

    DCRTPoly s(tug, paramsPK, Format::COEFFICIENT);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);

    int B=s.GetRingDimension()/h;

    std::uniform_int_distribution<> disBlock(0, B - 1);
    
    for (int j = 0; j < h; j++) {
        int ind=disBlock(gen);
        if(j==0) ind=0;
        for (int i = 0; i < s.GetNumOfElements(); i++) {
            NativePoly skt = s.GetElementAtIndex(i);
            for(int k=0;k<B;k++) skt[j*B+k]=0;
            skt[j*B+ind] = 1;            
            s.SetElementAtIndex(i, skt);
        }
    }
    s.SetFormat(Format::EVALUATION);

    return s;
}

KeyPair<DCRTPoly> myKeyGen(CryptoContext<DCRTPoly> &cc,int h) {

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(cc->GetCryptoParameters());
    const std::shared_ptr<DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();
    const std::shared_ptr<DCRTPoly::Params> paramsPK = cryptoParams->GetParamsPK();
    const auto ns = cryptoParams->GetNoiseScale();
    const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DCRTPoly::DugType dug;
    
    DCRTPoly s = genBlockSparseKey(cc,h);

    DCRTPoly a(dug, paramsPK, Format::EVALUATION);
    DCRTPoly e(dgg, paramsPK, Format::EVALUATION);
    DCRTPoly b(ns * e - a * s);

    usint sizeQ = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();

    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }
    keys.secretKey->SetPrivateElement(std::move(s));

    keys.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});
    keys.publicKey->SetKeyTag(keys.secretKey->GetKeyTag());

    cc->EvalMultKeyGen(keys.secretKey);

    std::vector<int32_t>  indexList;
    for (uint32_t i = 1; i <= cc->GetRingDimension() / 4; i *= 2) {
        indexList.push_back(i);
    }
    cc->EvalRotateKeyGen(keys.secretKey, indexList);

    uint32_t indexConj = 2 * cc->GetRingDimension() - 1;
    cc->EvalAutomorphismKeyGen(keys.secretKey, {indexConj});

    return keys;
}

// We do not reverse the most significant bit
uint32_t reversebit(uint32_t i, uint32_t k) {
    uint32_t reversed = i & (1 << (k - 1)); // Keep the most significant bit
    for (uint32_t bit = 0; bit < k-1; ++bit) {
        if (i & (1 << bit)) {
            reversed |= (1 << (k - 2 - bit));
        }
    }
    return reversed;
}

void testReversedBits() {
    uint32_t k = 4; // Number of bits to reverse
    for (uint32_t i = 0; i < (1 << k); ++i) {
        uint32_t reversed = reversebit(i, k);
        std::cout << "Original: " << std::bitset<4>(i) << " Reversed: " << std::bitset<4>(reversed) << std::endl;
    }
}

// Generation of the encryted secret key for bootstrapping, for a single slot
std::vector<Ciphertext<DCRTPoly>> BootstrapSingleSlotKeyGen(
    const CryptoContext<DCRTPoly>& cc, 
    const KeyPair<DCRTPoly>& keys,
    int h) {

    size_t N = cc->GetRingDimension();
    std::vector<std::complex<double>> sv1(N/2),sv2(N/2);

    BigVector skv = PolyFromDCRTPoly(keys.secretKey->GetPrivateElement()).GetValues();

    size_t B=N/h;

    for (size_t k = 0; k < h; k++) {
        for (size_t i = 0; i < B/2; i++) {
            sv1[i*h+k] = std::complex<double>(skv[ k * B + i].ConvertToDouble(), 0.);
            sv2[i*h+k] = std::complex<double>(skv[ k * B + i + B/2].ConvertToDouble(), 0.);
        }
    }

    Plaintext ptsk1 = cc->MakeCKKSPackedPlaintext(sv1);
    Plaintext ptsk2 = cc->MakeCKKSPackedPlaintext(sv2);

    auto esk1 = cc->Encrypt(keys.publicKey, ptsk1);
    auto esk2 = cc->Encrypt(keys.publicKey, ptsk2);

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
    double pi = 3.14159265358979323846;

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


std::vector<Ciphertext<DCRTPoly>> BootstrapMultipleSlotsKeyGen(
    const CryptoContext<DCRTPoly>& cc, 
    const KeyPair<DCRTPoly>& keys,
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

    BigVector skv = PolyFromDCRTPoly(keys.secretKey->GetPrivateElement()).GetValues();

    for (size_t a = 0; a < n; a++) {  // index of the LWE ciphertext, low order index in the encoded ciphertext
        for (size_t u=0; u < 2*n; u++) { // high-order index in the block, index of the encoded ciphertext, 
            for (size_t k = 0; k < B/(2*n); k++) { // low-order index in the block
                for (size_t b = 0; b < h; b++) {  // index of the block
                  sv[u][k*h*n+b*n+a] = std::complex<double>(skv[ b*B+u*B/(2*n)+k].ConvertToDouble(), 0.);
                }
            }
        }
    }

    std::vector< Ciphertext<DCRTPoly> > esv(2*n);

    for(size_t u=0; u < 2*n; u++) {
        esv[u] = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(sv[u])); 
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
    double pi = 3.14159265358979323846;

    if (B < 2 * n) {
        throw std::invalid_argument("B must be >= 2 * n");
    }

    if (numSlots < 2) {
        throw std::invalid_argument("numSlots must be >= 2");
    }

    double scaleCiph=4.;
    double scale=pow(q.ConvertToDouble() / (4. * pi) / pow(2.,scaleModSize) /scaleCiph,1./h);
 
    size_t nsize = static_cast<size_t>(std::round(std::log2(n)));

    #pragma omp parallel for
    for (size_t a = 0; a < n; a++) {  // index of the LWE ciphertext, low order index in the encoded ciphertext
        uint32_t rev = reversebit(a, nsize);
        BigVector c1v = LWEfromCiph(ShiftRight(ciphertext,N-rev*N/n));
        for (size_t u=0; u < 2*n; u++) { // high-order index in the block, index of the encoded ciphertext, 
            for (size_t k = 0; k < B/(2*n); k++) { // low-order index in the block
                for (size_t b = 0; b < h; b++) {  // index of the block
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

Ciphertext<DCRTPoly> ModReduce(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const CryptoContext<DCRTPoly> &cc) {
    Ciphertext<DCRTPoly> c1 = ciphertext->Clone();
    cc->GetScheme()->ModReduceInternalInPlace(c1,1);
    return c1;
}

Ciphertext<DCRTPoly> BootstrapMultipleSlots(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const std::vector<Ciphertext<DCRTPoly>>& bootsk,
    const CryptoContext<DCRTPoly> &cc,
    int h,uint32_t scaleModSize,uint32_t internalNumSlots,uint32_t numSlots) {

    if (numSlots <= internalNumSlots) {
        return BootstrapMultipleSlotsInternal(ciphertext, bootsk, cc, h, scaleModSize, numSlots);
    } 
    else 
    {
        size_t N=cc->GetRingDimension();
        size_t n2=numSlots/internalNumSlots;
        Ciphertext<DCRTPoly> c1 = BootstrapMultipleSlotsInternal(ciphertext, bootsk, cc, h, scaleModSize, internalNumSlots);

        for(size_t i=1; i < n2; i++) {
            Ciphertext<DCRTPoly> temp = ShiftRight(ciphertext,i*N/(2*numSlots));
            temp = BootstrapMultipleSlotsInternal(temp, bootsk, cc, h, scaleModSize, internalNumSlots);
            temp = ShiftRight(temp,N-i*N/(2*numSlots));            
            c1 = cc->EvalSub(c1,temp);
        }
        c1->SetSlots(numSlots);
        return c1;
    }
}

uint32_t min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

double runBootstrap(uint32_t numSlots,bool verbose=false)
{
    if (verbose) std::cout << "New bootstrapping" << std::endl;
    uint32_t internalNumSlots=32; // 
    
    uint32_t h=64; // Hamming weight of the secret key
    uint32_t nh=static_cast<uint32_t>(std::round(std::log2(h)));

    
    // Level budget for SlotstoCoeffs
    uint32_t levelBudget= (numSlots > 1) ? 1 : 0;
    CCParams<CryptoContextCKKSRNS> parameters=genParameters(h,levelBudget);

    //uint32_t ringDim = 1 << 4;
    //parameters.SetSecurityLevel(HEStd_NotSet);  // We can fix the ring dimension ourselves
    //parameters.SetRingDim(ringDim);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    auto keys = myKeyGen(cc,h); // Generate a block binary key with Hamming weight h

    std::vector< Ciphertext<DCRTPoly> > bootsk;

    if(numSlots>1) {
        uint32_t lDec=parameters.GetMultiplicativeDepth()-nh-1-levelBudget+1; // number of remaining levels after SlotsToCoeffs
        EvalSlotsToCoeffsSetup(cc, levelBudget, min(numSlots,internalNumSlots),lDec);  
        cc->EvalBootstrapKeyGen(keys.secretKey,min(numSlots,internalNumSlots));
        bootsk=BootstrapMultipleSlotsKeyGen(cc,keys,h,min(numSlots,internalNumSlots));
    }
    else {
        bootsk=BootstrapSingleSlotKeyGen(cc, keys,h);
    }

    if (verbose) std::cout << "Number of slots: " << numSlots << std::endl;
    if (verbose) std::cout << "Multiplicative depth: " << parameters.GetMultiplicativeDepth() << std::endl;
    if (verbose) std::cout << "Ring dimension: " << cc->GetRingDimension() << std::endl;
    if (verbose) std::cout << "Modulus size in bits: " << cc->GetModulus().GetMSB() << std::endl;
    if (verbose) std::cout << "Full modulus size in bits: " << keys.publicKey->GetPublicElements()[0].GetModulus().GetMSB() << std::endl;


    std::vector<double> vec=genUniformReal(numSlots);

    //if (verbose) std::cout << "Input value: " << vec << std::endl;

    uint32_t level = parameters.GetMultiplicativeDepth(); // We encode at the last level
    Plaintext ptxt1=MakePlaintext(cc,vec,level);

    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);
   
    std::vector<std::complex<double>> dc1=DecryptCKKSPackedValue(c1,keys.secretKey,numSlots);
    //if (verbose) std::cout << "Decrypted c1:" << dc1 << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> newciph;
    if (numSlots > 1) {
        newciph = BootstrapMultipleSlots(c1, bootsk, cc, h, parameters.GetScalingModSize(),internalNumSlots,numSlots);
    }
    else
        newciph=BootstrapSingleSlot(c1, bootsk, cc, h, parameters.GetScalingModSize());
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    double dt=elapsed.count();

    std::vector<std::complex<double>> newVal=DecryptCKKSPackedValue(newciph,keys.secretKey,numSlots);
    //if (verbose) std::cout << "Decrypted c1:" << newVal << std::endl;
    //std::cout << "After boot: level" << newciph->GetLevel()  << " Scaling degree" << newciph->GetNoiseScaleDeg() << std::endl;
    if (verbose) std::cout << "Number of levels remaining after bootstrapping: "
              << parameters.GetMultiplicativeDepth() - newciph->GetLevel() - (newciph->GetNoiseScaleDeg() - 1) << std::endl;
              if (verbose) std::cout << "Bootstrap execution time: " << dt << " seconds" << std::endl;


    if (verbose) std::cout << "Estimated precision: " << estimatePrecision(newVal,dc1) << " bits" << std::endl;
    /*
    if(verbose) {
        std::cout << "Error: ";
        for(size_t i=0; i<numSlots; i++) {
            std::cout << newVal[i]-dc1[i] << " ";
        }
        std::cout << std::endl;
    }
    */

    // Erase the cryptoContext to free memory
    cc->ClearEvalAutomorphismKeys();
    cc->ClearEvalMultKeys();
    cc->ClearEvalSumKeys();

   return dt;
}

void testNewCKKSBootstrap()
{
    uint32_t ntries=5;
    std::vector<double> vec;
    for(size_t i= 0; i<11; i++) {
        double total=0;
        uint32_t numSlots=1<<i;
        for(size_t j=0; j<ntries; j++) {
            double elapsed=runBootstrap(numSlots,j==0);
            total+=elapsed;
        }
        std::cout << "Average time: " << total/ntries << std::endl << std::endl;
        vec.push_back(total/ntries);
    }

    std::cout << "[ "; 
    for(size_t i=0; i<vec.size(); i++) {
        std::cout << vec[i];
        if(i<vec.size()-1) std::cout << ", ";
    }
    std::cout << " ]" << std::endl;

}

int main() {
    testNewCKKSBootstrap();
    return 0;
}
    
