#include "slotstocoeffs-utils.h"
#include "ciphertext-utils.h"

#include <typeinfo>

using namespace lbcrypto;

// In this file, we use two workarounds:
// 1. We use a shadow class of SchemeBase<DCRTPoly> to access a protected member. 
//    This is necessary because the FHEBase<DCRTPoly> member m_FHE is protected in SchemeBase<DCRTPoly
// 2. We use a shadow class for FHECKKSRNS to access private members.
//    This is necessary because m_correctionFactor and m_bootPrecomMap are private in FHECKKSRNS
//    This only works if the layout of FHECKKSRNS does not change.


std::shared_ptr<FHECKKSRNS> getFHEAlgorithm(const CryptoContext<DCRTPoly>& cryptoContext)
{
    std::shared_ptr<SchemeBase<DCRTPoly>> scheme=cryptoContext->GetScheme();
    
    // This is because m_FHE is protected in SchemeBase<DCRTPoly>
    struct Shadow : public SchemeBase<DCRTPoly> {
        using SchemeBase<DCRTPoly>::m_FHE;
    };

    auto baseAlgo = static_cast<const Shadow&>(*scheme).m_FHE;

    if(!baseAlgo) {
        throw std::runtime_error("Failed to get FHEBase<DCRTPoly>");
    }

    std::shared_ptr<FHECKKSRNS> algo = std::dynamic_pointer_cast<FHECKKSRNS>(baseAlgo);
    if (!algo) {
        throw std::runtime_error("Failed to cast FHEBase<DCRTPoly> to FHECKKSRNS");
    }
    return algo;
}

class FHECKKSRNSShadow : public FHERNS {
public:
    const uint32_t K_SPARSE  = 28;  
    const uint32_t K_UNIFORM = 512;  
    static const uint32_t R_UNIFORM = 6; 
    static const uint32_t R_SPARSE = 3;  
    uint32_t m_correctionFactor = 0; 
    std::map<uint32_t, std::shared_ptr<CKKSBootstrapPrecom>> m_bootPrecomMap;
};

class FHECKKSRNSDerived : public FHECKKSRNS {
public:
    void EvalSlotsToCoeffsSetup(const CryptoContextImpl<DCRTPoly>& cc, std::vector<uint32_t> levelBudget,
                                        std::vector<uint32_t> dim1, uint32_t numSlots,uint32_t lDec) {
        
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc.GetCryptoParameters());

        uint32_t M     = cc.GetCyclotomicOrder();
        uint32_t slots = (numSlots == 0) ? M / 4 : numSlots;

        bool precompute = true;

        // This is a workaround because m_correctionFactor and m_bootPrecomMap are private in FHECKKSRNS
        auto shadow=reinterpret_cast<FHECKKSRNSShadow*>(this);    
    
        uint32_t &m_correctionFactor=shadow->m_correctionFactor;                                    
        std::map<uint32_t, std::shared_ptr<CKKSBootstrapPrecom>> &m_bootPrecomMap=shadow->m_bootPrecomMap;
    
        m_correctionFactor = 9;

        m_bootPrecomMap[slots]                      = std::make_shared<CKKSBootstrapPrecom>();
        std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap[slots];

        precom->m_slots = slots;
        precom->m_dim1  = dim1[0];

        uint32_t logSlots = std::log2(slots);
        // even for the case of a single slot we need one level for rescaling
        if (logSlots == 0) {
            logSlots = 1;
        }

        // Perform some checks on the level budget and compute parameters
        std::vector<uint32_t> newBudget = levelBudget;

        if (newBudget[1] > logSlots) {
            std::cerr << "\nWarning, the level budget for decoding is too large. Setting it to " << logSlots << std::endl;
         newBudget[1] = logSlots;
        }
        if (newBudget[1] < 1) {
           std::cerr << "\nWarning, the level budget for decoding can not be zero. Setting it to 1" << std::endl;
           newBudget[1] = 1;
        }

        // precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget[0], dim1[0]);
        precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget[1], dim1[1]);

        if (precompute) {
            uint32_t m    = 4 * slots;
            //bool isSparse = (M != m) ? true : false;

            // computes indices for all primitive roots of unity
            std::vector<uint32_t> rotGroup(slots);
            uint32_t fivePows = 1;
            for (uint32_t i = 0; i < slots; ++i) {
                rotGroup[i] = fivePows;
                fivePows *= 5;
                fivePows %= m;
            }

            // computes all powers of a primitive root of unity exp(2 * M_PI/m)
            std::vector<std::complex<double>> ksiPows(m + 1);
            for (uint32_t j = 0; j < m; ++j) {
                double angle = 2.0 * M_PI * j / m;
               ksiPows[j].real(cos(angle));
                ksiPows[j].imag(sin(angle));
            }
             ksiPows[m] = ksiPows[0];

             // Extract the modulus prior to bootstrapping
             NativeInteger q = cryptoParams->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt();
            double qDouble  = q.ConvertToDouble();

            uint128_t factor = ((uint128_t)1 << ((uint32_t)std::round(std::log2(qDouble))));
            double pre       = qDouble / factor;
            double scaleDec  = 1 / pre;

            precom->m_U0PreFFT     = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);

        }
    }


    Ciphertext<DCRTPoly> EvalSlotsToCoeffs(ConstCiphertext<DCRTPoly> ctxt)  {
        uint32_t slots = ctxt->GetSlots();

        // This is a workaround because m_bootPrecomMap is private in FHECKKSRNS
        auto shadow=reinterpret_cast<FHECKKSRNSShadow*>(this);    
        std::map<uint32_t, std::shared_ptr<CKKSBootstrapPrecom>> &m_bootPrecomMap=shadow->m_bootPrecomMap;
    
        auto pair = m_bootPrecomMap.find(slots);
        if (pair == m_bootPrecomMap.end()) {
            std::string errorMsg(std::string("Precomputations for ") + std::to_string(slots) +
                             std::string(" slots were not generated") +
                             std::string(" Need to call EvalBootstrapSetup and then EvalBootstrapKeyGen to proceed"));
            OPENFHE_THROW(errorMsg);
        }
        const std::shared_ptr<CKKSBootstrapPrecom> precom = pair->second;

        return FHECKKSRNS::EvalSlotsToCoeffs(precom->m_U0PreFFT, ctxt);
    }
};

void EvalSlotsToCoeffsSetup(
    const CryptoContext<DCRTPoly> &cryptoContext,
    uint32_t levelBudget,
    uint32_t numSlots,
    uint32_t lDec) // This is the number of remaining levels after SlotsToCoeffs, 
                   // this means that the input ciphertext of SlotsToCoeffs must be encoded at level depth-lDec-1
{
   
    std::vector<uint32_t> dim1 = {0, 0};
    std::vector<uint32_t> levelBudget2 = {0,levelBudget};
    
    //algo->EvalSlotsToCoeffsSetup(*cryptoContext, levelBudget2, dim1, numSlots,lDec);

    std::shared_ptr<FHECKKSRNS> algo= getFHEAlgorithm(cryptoContext);
    FHECKKSRNSDerived &algo2=static_cast<FHECKKSRNSDerived&>(*algo);

    algo2.EvalSlotsToCoeffsSetup(*cryptoContext, levelBudget2, dim1, numSlots,lDec);
}


Ciphertext<DCRTPoly> SlotsToCoeffs(const CryptoContext<DCRTPoly>& cryptoContext, const Ciphertext<DCRTPoly> &ciph) {
    std::shared_ptr<FHECKKSRNS> algo = getFHEAlgorithm(cryptoContext);

    FHECKKSRNSDerived &algo2=static_cast<FHECKKSRNSDerived&>(*algo);

    //Ciphertext<DCRTPoly> ciphout = algo->EvalSlotsToCoeffs(ciph);
    Ciphertext<DCRTPoly> ciphout = algo2.EvalSlotsToCoeffs(ciph);

    cryptoContext->EvalAddInPlace(ciphout, cryptoContext->EvalRotate(ciphout, ciphout->GetSlots()));    
    return ciphout;
}


void testSlots2Coeffs() {
    std::cout << "Test SlotsToCoeffs" << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    uint32_t batchSize = 4; // This is the number of slots in the plaintext
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 5);

    parameters.SetExecutionMode(EXEC_NOISE_ESTIMATION); // This is to allow computation with complex numbers
    parameters.SetScalingTechnique(FIXEDAUTO);

    uint32_t levelBudget = 2;
    
    usint depth = 3;
    parameters.SetMultiplicativeDepth(depth);

    std::cout << "Depth: " << depth << std::endl;

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    // This is the maximum number of slots that can be used for full packing.

    usint numSlots = batchSize;
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl;

    std::vector<uint32_t> dim1 = {0, 0};
    uint32_t lDec=2; // number of remaining levels after SlotsToCoeffs
    EvalSlotsToCoeffsSetup(cryptoContext, levelBudget, numSlots,lDec);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    
    std::vector<std::complex<double>> vec={
        std::complex<double>(0., 0.), std::complex<double>(0.0, 0.),
        std::complex<double>(1., 0.), std::complex<double>(0.0, 0.),
        std::complex<double>(0., 0.), std::complex<double>(0.0, 0.),
        std::complex<double>(0., 0.), std::complex<double>(0.0, 0.)
    };
    std::cout << "Input value: " << vec << std::endl;

    // To test SlotsToCoeffs, we must encode with twice the number of slots.
    Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(vec, 1,depth-lDec-1,nullptr,numSlots*2);
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt1);

    std::cout << "After encrypt: level:" << ciph->GetLevel() << " Encoding scale:" << log2(ciph->GetScalingFactor()) << std::endl;

    ciph->SetSlots(numSlots);

    ciph=cryptoContext->EvalMult(ciph, ciph);

    std::cout << "After mult: level:" << ciph->GetLevel() << " Encoding scale:" << log2(ciph->GetScalingFactor()) << std::endl;
   
    ciph = SlotsToCoeffs(cryptoContext, ciph);

    std::cout << "After S2C: level:" << ciph->GetLevel() << " Encoding scale:" << log2(ciph->GetScalingFactor()) << std::endl;

    //cryptoContext->GetScheme()->ModReduceInternalInPlace(ciph,1);
    
    //ciph=cryptoContext->EvalMult(ciph, ciph);

    std::cout << "After scaling: Level:" << ciph->GetLevel() << " Encoding scale:" << log2(ciph->GetScalingFactor()) << std::endl;

    Poly xx1=myDecrypt(ciph, keyPair.secretKey);
    std::cout << "slots:" << ciph->GetSlots() << std::endl;
    std::cout << "modulus size: " << ciph->GetElements()[0].GetModulus().GetMSB() << std::endl;
    for(size_t i=0; i<xx1.GetLength(); i++) {
        std::cout << i << " ";
        printIntegerMod(xx1[i],xx1.GetModulus());
        std::cout << std::endl;
    }
    std::cout << std::endl;
}
