#include "openfhe.h"

// We generate a block binary secret key, where the first bit is always 1
lbcrypto::DCRTPoly genBlockSparseKey(const std::shared_ptr<lbcrypto::DCRTPoly::Params> &paramsPK , int h,int step);

void EvalMultRotateAutoKeyGen(const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc, const lbcrypto::KeyPair<lbcrypto::DCRTPoly>& keys);

lbcrypto::KeyPair<lbcrypto::DCRTPoly> myKeyGen(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,int h);

void myKeyGenStep(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,int h,int step,
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> &publicKey,
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> &firstSecretKey,
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> &secretKey,
    lbcrypto::EvalKey<lbcrypto::DCRTPoly> &ksKey);
