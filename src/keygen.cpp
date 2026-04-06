#include "keygen.h"

using namespace lbcrypto;

// We generate a block binary secret key, where the first bit is always 1
DCRTPoly genBlockSparseKey(const std::shared_ptr<DCRTPoly::Params> &paramsPK , int h,int step=1) {

    DCRTPoly::TugType tug;
    DCRTPoly s(tug, paramsPK, Format::COEFFICIENT);

    std::random_device rd;
    std::mt19937 gen(rd());

    int B=s.GetRingDimension()/h;

    std::uniform_int_distribution<> disBlock(0, B/step - 1);
    
    for (int j = 0; j < h; j++) {
        int ind=disBlock(gen);
        if(j==0) ind=0;
        for (int i = 0; i < s.GetNumOfElements(); i++) {
            NativePoly skt = s.GetElementAtIndex(i);
            for(int k=0;k<B;k++) skt[j*B+k]=0;
            skt[j*B+step*ind] = 1;            
            s.SetElementAtIndex(i, skt);
        }
    }
    s.SetFormat(Format::EVALUATION);

    return s;
}

void EvalMultRotateAutoKeyGen(const CryptoContext<DCRTPoly>& cc, const KeyPair<DCRTPoly>& keys) {
    cc->EvalMultKeyGen(keys.secretKey);
    std::vector<int32_t> indexList;

    usint ringDim = cc->GetRingDimension();

    for (uint32_t i = 1; i <= ringDim / 4; i *= 2) {
        indexList.push_back(i);
    }
    cc->EvalRotateKeyGen(keys.secretKey, indexList);

    uint32_t indexConj = 2 * ringDim - 1;
    cc->EvalAutomorphismKeyGen(keys.secretKey, {indexConj});
}

void EnableAllFeatures(CryptoContext<DCRTPoly>& cc) {
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
}

void DCRTPolyReduceSize(DCRTPoly& s, const CryptoParametersRLWE<DCRTPoly>* cryptoParams) {
    const std::shared_ptr<DCRTPoly::Params> elementParams = cryptoParams->GetElementParams();
    const std::shared_ptr<DCRTPoly::Params> paramsPK = cryptoParams->GetParamsPK();

    usint sizeQ = elementParams->GetParams().size();
    usint sizePK = paramsPK->GetParams().size();

    if (sizePK > sizeQ) {
        s.DropLastElements(sizePK - sizeQ);
    }
}

KeyPair<DCRTPoly> myKeyGen(CryptoContext<DCRTPoly> &cc,int h) {

    EnableAllFeatures(cc);

    KeyPair<DCRTPoly> keys = cc->KeyGen();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(cc->GetCryptoParameters());
    const std::shared_ptr<DCRTPoly::Params> paramsPK = cryptoParams->GetParamsPK();
    const auto ns = cryptoParams->GetNoiseScale();
    const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DCRTPoly::DugType dug;
    
    DCRTPoly s = genBlockSparseKey(paramsPK,h);

    DCRTPoly a(dug, paramsPK, Format::EVALUATION);
    DCRTPoly e(dgg, paramsPK, Format::EVALUATION);
    DCRTPoly b(ns * e - a * s);

    DCRTPolyReduceSize(s, cryptoParams.get());

    keys.secretKey->SetPrivateElement(std::move(s));
    keys.publicKey->SetPublicElements(std::vector<DCRTPoly>{std::move(b), std::move(a)});
    keys.publicKey->SetKeyTag(keys.secretKey->GetKeyTag());

    EvalMultRotateAutoKeyGen(cc, keys);

    return keys;
}

void myKeyGenStep(CryptoContext<DCRTPoly> &cc,int h,int step,
    PublicKey<DCRTPoly> &publicKey,
    PrivateKey<DCRTPoly> &firstSecretKey,
    PrivateKey<DCRTPoly> &secretKey,
    EvalKey<DCRTPoly> &ksKey) {

    EnableAllFeatures(cc);

    // We generate the main key pair, used for homomorphic operations in bootstrapping
    KeyPair<DCRTPoly> keys = cc->KeyGen();
    EvalMultRotateAutoKeyGen(cc, keys);

    publicKey = keys.publicKey;
    firstSecretKey = keys.secretKey;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(cc->GetCryptoParameters());
    const std::shared_ptr<DCRTPoly::Params> paramsPK = cryptoParams->GetParamsPK();
        
    DCRTPoly s = genBlockSparseKey(paramsPK,h,step);
    DCRTPolyReduceSize(s, cryptoParams.get());
    secretKey = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
    secretKey->SetPrivateElement(s);

    ksKey = FHECKKSRNS::KeySwitchGenSparse(keys.secretKey, secretKey);
}

