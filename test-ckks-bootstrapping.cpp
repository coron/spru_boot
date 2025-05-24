//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*

Example for CKKS bootstrapping with full packing

*/

#define PROFILE

#include "openfhe.h"
#include "ciphertext-utils.h"
#include <chrono>

using namespace lbcrypto;


double SimpleBootstrapExample(uint32_t numSlots,bool verbose=false) {

    if (verbose) std::cout << "Original CKKS bootstrapping" << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = SPARSE_TERNARY; // UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);
    uint32_t batchSize = numSlots; // This is the number of slots in the plaintext

    parameters.SetBatchSize(batchSize);
    //parameters.SetSecurityLevel(HEStd_NotSet);
    //parameters.SetRingDim(1 << 15);

    /*  A3) Scaling parameters.
    * By default, we set the modulus sizes and rescaling technique to the following values
    * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
    * below unless you are an FHE expert.
    */
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 78;
    usint firstMod               = 89;
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);
   
    /*  A4) Bootstrapping parameters.
    * We set a budget for the number of levels we can consume in bootstrapping for encoding and decoding, respectively.
    * Using larger numbers of levels reduces the complexity and number of rotation keys,
    * but increases the depth required for bootstrapping.
	* We must choose values smaller than ceil(log2(slots)). A level budget of {4, 4} is good for higher ring
    * dimensions (65536 and higher).
    */

    // for numSlots <= 32, we can use {1,1}
    // for numSlots > 32, we can use {2,2}

    std::vector<uint32_t> levelBudget;
    if (numSlots <= 16) {
        levelBudget = {1, 1};
    } else {
        levelBudget = {2, 2};
    }

    // With {1,1}, we can have 8 levels after bootstrapping
    // With {2,2}, we can have 6 levels after bootstrapping
    uint32_t levelsAvailableAfterBootstrap = 1; //10 - levelBudget[0] - levelBudget[1];
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    
    std::vector<uint32_t> dim1 = {0, 0};
    cryptoContext->EvalBootstrapSetup(levelBudget,dim1,numSlots);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    if (verbose) std::cout << "Number of slots: " << numSlots << std::endl;
    if (verbose) std::cout << "Multiplicative depth: " << depth << std::endl;
    if (verbose) std::cout << "Ring dimension " << ringDim << std::endl;
    if (verbose) std::cout << "Modulus size in bits: " << cryptoContext->GetModulus().GetMSB() << std::endl;
    if (verbose) std::cout << "Full modulus size in bits: " << keyPair.publicKey->GetPublicElements()[0].GetModulus().GetMSB() << std::endl;
    if (verbose) std::cout << "Level budget: " << levelBudget[0] << " " << levelBudget[1] << std::endl;

    std::vector<double> x=genUniformReal(numSlots);

    size_t encodedLength  = x.size();

    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth-1);

    ptxt->SetLength(encodedLength);
    //if (verbose) std::cout << "Input: " << ptxt << std::endl;

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    std::vector<std::complex<double>> dc1=DecryptCKKSPackedValue(ciph,keyPair.secretKey,numSlots);

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto start = std::chrono::high_resolution_clock::now();

    auto scheme = cryptoContext->GetScheme();

    auto ciphertextAfter = scheme->EvalBootstrap(ciph,1,0);
    //auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    if (verbose) std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertextAfter->GetLevel() - (ciphertextAfter->GetNoiseScaleDeg() - 1) << std::endl;

    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(encodedLength);
    //if (verbose) std::cout << "Output after bootstrapping \n\t" << result << std::endl;
    double dt=elapsed.count();
    if (verbose) std::cout << "Bootstrap execution time: " << dt << " seconds" << std::endl;

    std::vector<std::complex<double>> newVal=DecryptCKKSPackedValue(ciphertextAfter,keyPair.secretKey,numSlots);

    if (verbose) std::cout << "Estimated precision: " << estimatePrecision(newVal,dc1) << " bits" << std::endl;

    // Erase the cryptoContext to free memory
    cryptoContext->ClearEvalAutomorphismKeys();
    cryptoContext->ClearEvalMultKeys();
    cryptoContext->ClearEvalSumKeys();
    return dt;
}

void testCKKSBootstrap()
{
    uint32_t ntries=5;
    std::vector<double> vec;
    for(size_t i= 0; i<11; i++) {
        double total=0;
        uint32_t numSlots=1<<i;
        for(size_t j=0; j<ntries; j++) {
            double elapsed=SimpleBootstrapExample(numSlots,j==0);
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

int main(int argc, char* argv[]) {
    testCKKSBootstrap();
}
