#define PROFILE

#include <cmath>
#include <random>
#include <chrono>
#include <omp.h>
#include <thread>

#include "openfhe.h"

#include "poly-utils.h"
#include "ciphertext-utils.h"
#include "slotstocoeffs-utils.h"
#include "analysis.h"
#include "params.h"
#include "keygen.h"
#include "utils.h"
#include "single_slot.h"
#include "multiple_slot.h"

using namespace lbcrypto;


Ciphertext<DCRTPoly> ModReduce(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const CryptoContext<DCRTPoly> &cc) {
    Ciphertext<DCRTPoly> c1 = ciphertext->Clone();
    cc->GetScheme()->ModReduceInternalInPlace(c1,1);
    return c1;
}

uint32_t min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

Ciphertext<DCRTPoly> BootstrapMultipleSlots(
    const Ciphertext<DCRTPoly>& ciphertext, 
    const std::vector<Ciphertext<DCRTPoly>>& bootsk,
    const CryptoContext<DCRTPoly> &cc,
    int h,uint32_t scaleModSize,uint32_t internalNumSlots,uint32_t numSlots,int step) {

    if (numSlots == internalNumSlots) {
        return BootstrapMultipleSlotsInternalStep(ciphertext, bootsk, cc, h, scaleModSize, numSlots, step);
    } 
    else 
    {
        size_t N=cc->GetRingDimension();
        size_t n2=numSlots/internalNumSlots;
        Ciphertext<DCRTPoly> c1 = BootstrapMultipleSlotsInternalStep(ciphertext, bootsk, cc, h, scaleModSize, internalNumSlots, step);

        for(size_t i=1; i < n2; i++) {
            Ciphertext<DCRTPoly> temp = ShiftRight(ciphertext,i*N/(2*numSlots));
            temp = BootstrapMultipleSlotsInternalStep(temp, bootsk, cc, h, scaleModSize, internalNumSlots, step);
            temp = ShiftRight(temp,N-i*N/(2*numSlots));            
            c1 = cc->EvalSub(c1,temp);
        }
        c1->SetSlots(numSlots);
        return c1;
    }
}

double runBootstrap(uint32_t numSlots,int step=1,bool verbose=false)
{
    if (verbose) std::cout << "New bootstrapping with step " << step << std::endl;
    uint32_t maxInternalNumSlots=32; // 
    uint32_t internalNumSlots = min(numSlots, maxInternalNumSlots);
    
    uint32_t h=64; // Hamming weight of the secret key
    //uint32_t nh=bitLength(h);

    // Level budget for SlotstoCoeffs
    uint32_t levelBudget= (numSlots > 1) ? 1 : 0;
    CCParams<CryptoContextCKKSRNS> parameters=genParameters(h,levelBudget);

    //uint32_t ringDim = 1 << 4;
    //parameters.SetSecurityLevel(HEStd_NotSet);  // We can fix the ring dimension ourselves
    //parameters.SetRingDim(ringDim);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    PublicKey<DCRTPoly> publicKey;
    PrivateKey<DCRTPoly> firstSecretKey; 
    PrivateKey<DCRTPoly> sparseSecretKey;
    
    EvalKey<DCRTPoly> ksKey;

    // Here, sparseSecretKey is sparse, it is not the private key
    // corresponding to publicKey. It is the private key after
    // key switching using ksKey.
    myKeyGenStep(cc, h, step, publicKey, firstSecretKey, sparseSecretKey, ksKey);

    if (verbose && ksKey) {
        const auto& aVec = ksKey->GetAVector();
        if (!aVec.empty()) {
            std::cout << "ksKey modulus size in bits (A[0]): "
                      << aVec[0].GetModulus().GetMSB() << std::endl;
            //std::cout << "ksKey number of modulus levels (A[0]): "
            //          << aVec[0].GetNumOfElements() << std::endl;
        }
    }

    std::vector< Ciphertext<DCRTPoly> > bootsk;

    if(numSlots>1) {
        uint32_t lDec=parameters.GetMultiplicativeDepth()-spruMultiplicativeDepth(h, levelBudget)+1; // number of remaining levels after SlotsToCoeffs
        EvalSlotsToCoeffsSetup(cc, levelBudget, internalNumSlots,lDec);  
        cc->EvalBootstrapKeyGen(firstSecretKey,internalNumSlots);
        bootsk=BootstrapMultipleSlotsKeyGenStep(cc,publicKey,sparseSecretKey,h,internalNumSlots,step);
    }
    else {
        bootsk=BootstrapSingleSlotKeyGen(cc, publicKey, sparseSecretKey, h);
    }

    if (verbose) std::cout << "Number of slots: " << numSlots << std::endl;
    if (verbose) std::cout << "Multiplicative depth: " << parameters.GetMultiplicativeDepth() << std::endl;
    if (verbose) std::cout << "Ring dimension: " << cc->GetRingDimension() << std::endl;
    if (verbose) std::cout << "Modulus size in bits: " << cc->GetModulus().GetMSB() << std::endl;
    if (verbose) std::cout << "Full modulus size in bits: " << publicKey->GetPublicElements()[0].GetModulus().GetMSB() << std::endl;

    std::vector<double> vec=genUniformReal(numSlots);

    //if (verbose) std::cout << "Input value: " << vec << std::endl;

    uint32_t level = parameters.GetMultiplicativeDepth(); // We encode at the last level
    Plaintext ptxt1=MakePlaintext(cc,vec,level);

    auto c1 = cc->Encrypt(publicKey, ptxt1);
    //if (verbose) {
    //    std::cout << "c1 number of modulus levels (after Encrypt): "
    //              << c1->GetElements()[0].GetNumOfElements() << std::endl;
    //}

    c1 = FHECKKSRNS::KeySwitchSparse(c1, ksKey);
    
    std::vector<std::complex<double>> dc1=DecryptCKKSPackedValue(c1,sparseSecretKey,numSlots);
    //if (verbose) std::cout << "Decrypted c1:" << dc1 << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> newciph;
    if (numSlots > 1) {
        newciph = BootstrapMultipleSlots(c1, bootsk, cc, h, parameters.GetScalingModSize(),internalNumSlots,numSlots,step);
    }
    else
        newciph=BootstrapSingleSlot(c1, bootsk, cc, h, parameters.GetScalingModSize());
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    double dt=elapsed.count();

    std::vector<std::complex<double>> newVal=DecryptCKKSPackedValue(newciph,firstSecretKey,numSlots);
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
    #pragma omp parallel
    {
        #pragma omp master
        std::cout << "OpenMP is using " << omp_get_num_threads() << " threads." << std::endl;
    }
    int step=1;
    uint32_t ntries=5;
    std::vector<double> vec;
    for(size_t i= 0; i<9; i++) {
        double total=0;
        uint32_t numSlots=1<<i;
        for(size_t j=0; j<ntries; j++) {
            double elapsed=runBootstrap(numSlots,step,j==0);
            total+=elapsed;
        }
        std::cout << "Average time: " << total/ntries << std::endl << std::endl;
        vec.push_back(total/ntries);

        std::this_thread::sleep_for(std::chrono::seconds(1));
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
