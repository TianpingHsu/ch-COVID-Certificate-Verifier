#include "ch.h"
#include <cstdlib>
#include "zlib.h"
#include "base45.h"
#include "base64.h"
#include "t_cose/t_cose_sign1_verify.h"
#include <vector>
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <memory>
#include "openssl/ecdsa.h"

class DecoderVerifier::DecoderVerifierImp {
    public:
        bool decode(const char* qrcode, size_t len);
        bool getPayload(jsoncons::ojson & payload);
        bool setPublicKey(const std::string &k);

        bool verify();
        bool getDecodeState();
        std::string getKID();
        DecoderVerifier::CertType getCertType();
        ~DecoderVerifierImp();
    private:
        void cborEncode(q_useful_buf_c plain, std::vector<uint8_t> &encoded);
        bool createTBS();

    private:
        bool m_decodeState = false;
        EVP_PKEY *pKey;
        int alg = -7;
        std::string kid="";
        UsefulBufC phdr = {NULL, 0}, payload = {NULL, 0}, sig = {NULL, 0}, tbs = {NULL, 0}, cose = {NULL, 0};
        DecoderVerifier::CertType certType = DecoderVerifier::CertType::UNKNOWN;
};

inline bool DecoderVerifier::DecoderVerifierImp::getDecodeState() {
    return m_decodeState;
}

void DecoderVerifier::DecoderVerifierImp::cborEncode(q_useful_buf_c plain, std::vector<uint8_t> &encoded) {
    encoded.clear();
    std::vector<uint8_t> v((uint8_t*)plain.ptr, (uint8_t*)plain.ptr + plain.len);
    jsoncons::json j(jsoncons::byte_string_arg, v);
    jsoncons::cbor::encode_cbor(j, encoded);
}

bool DecoderVerifier::DecoderVerifierImp::createTBS() {
    /**
     * Sig_structure = [
     *    context : "Signature" / "Signature1" / "CounterSignature",
     *    body_protected : empty_or_serialized_map,
     *    ? sign_protected : empty_or_serialized_map,
     *    external_aad : bstr
     *    payload : bstr
     * ]
     **/
    // to be signed
    const int MAX_BUF_LEN = 1 * 1024 * 1024;
    tbs.ptr = malloc(MAX_BUF_LEN * sizeof(uint8_t));
    uint8_t *p = (uint8_t*)tbs.ptr;
    *p++ = 0x84;  // array with four items
    *p++ = 0x6a; memcpy(p, "Signature1", 10);  // context: "Signature1" with length 10

    std::vector<uint8_t> buf;
    cborEncode(phdr, buf);
    memcpy((p += 10), (uint8_t*)(&buf[0]), buf.size());  // protected_header/body_protected
    p += buf.size();  // update pointer

    *p++ = 0x40;  // empty string for external_aad

    cborEncode(payload, buf);
    memcpy(p, (uint8_t*)(&buf[0]), buf.size());  // payload

    p += buf.size();  // update pointer
    tbs.len = p - (uint8_t*)tbs.ptr;  //calculate length

#ifdef DEBUG
    std::vector<uint8_t> v((uint8_t*)tbs.ptr, (uint8_t*)tbs.ptr + tbs.len);
    jsoncons::ojson j = jsoncons::cbor::decode_cbor<jsoncons::ojson>(v);
    std::cout << jsoncons::pretty_print(j) << std::endl;
#endif

    return true;
}

bool DecoderVerifier::DecoderVerifierImp::setPublicKey(const std::string &k) {
    const static std::string header = "-----BEGIN CERTIFICATE-----\n";
    const static std::string footer = "\n-----END CERTIFICATE-----\n";
    std::string key = header + k + footer;
    BIO *keybio = BIO_new_mem_buf(key.c_str(), key.size());
    if (!keybio) {
        BIO_free_all(keybio);
        printf("keybio is null\n"); return false;
    }
    X509* pX509 = PEM_read_bio_X509(keybio, NULL, NULL, NULL);
    if (!pX509) {
        BIO_free_all(keybio);
        X509_free(pX509);
        printf("PEM_read_bio_X509 failed!\n");
        return false;
    }
    pKey = X509_get_pubkey(pX509);
    BIO_free_all(keybio);
    X509_free(pX509);
    if ((alg != -37 && alg != -7) || !pKey) {
        printf("setPublicKey failed, with alg: %d\n", alg);
        return false;
    }
    return true;
}

bool DecoderVerifier::DecoderVerifierImp::verify() {
    if (alg == -37) {  // PS256
        createTBS();
        int ret = 0;
        // set rsa key
        const EVP_MD *pMd = EVP_sha256();
        EVP_MD_CTX *pMDCtx = NULL;
        pMDCtx = EVP_MD_CTX_create();
        EVP_PKEY_CTX *pKeyCtx = NULL;
        ret = EVP_DigestVerifyInit(pMDCtx, &pKeyCtx, pMd, NULL, pKey);
        if (ret != 1) {
            printf("EVP_DigestVerifyInit: %d\n", ret);
            return false;
        }
        EVP_PKEY_free(pKey); pKey = NULL;

        // set padding
        ret = EVP_PKEY_CTX_set_rsa_padding(pKeyCtx, RSA_PKCS1_PSS_PADDING);
        if (ret != 1) {
            printf("EVP_PKEY_CTX_set_rsa_padding: %d\n", ret);
            return false;
        }

        // set saltlen
        ret = EVP_PKEY_CTX_set_rsa_pss_saltlen(pKeyCtx, 32);
        if (ret != 1) {
            printf("EVP_PKEY_CTX_set_rsa_pss_saltlen: %d\n", ret);
            return false;
        }

        // set 'to be signed'
        ret = EVP_DigestVerifyUpdate(pMDCtx, (uint8_t*)tbs.ptr, tbs.len);
        if (ret != 1) {
            printf("EVP_DigestVerifyUpdate: %d\n", ret);
            return false;
        }

        // verify signature
        ret = EVP_DigestVerifyFinal(pMDCtx, (uint8_t*)sig.ptr, sig.len);
        if (ret != 1) {
            printf("EVP_DigestVerifyFinal: %d\n", ret);
            return false;
        }

        EVP_MD_CTX_destroy(pMDCtx); pMDCtx = NULL;
        return true;
    } else if (alg == -7){  // ES256
        struct t_cose_key key;
        key.k.key_ptr = EVP_PKEY_get1_EC_KEY(pKey);
        key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
        struct t_cose_sign1_verify_ctx ctx;
        t_cose_sign1_verify_init(&ctx, 0);
        t_cose_sign1_set_verification_key(&ctx, key);
        EC_KEY_free((EC_KEY*)key.k.key_ptr);

        struct t_cose_parameters params;
        UsefulBufC tmppayload;
        int result = t_cose_sign1_verify(&ctx, cose, &tmppayload, &params, NULL, NULL);
        EVP_PKEY_free(pKey); pKey = NULL;
        if (result != T_COSE_SUCCESS) {
            printf("t_cose_sign1_verify failed, with errcode: %d\n", result);
            return false;
        }
        return true;
    } else {
        return false;
    }
}

bool DecoderVerifier::DecoderVerifierImp::decode(const char* qrcode, size_t len) {
    // skip 'CH1:' or 'LT1:'
    const int CONTEXT_PREFIX = 4;
    if (len >= CONTEXT_PREFIX) {
        if (strncmp(qrcode, "HC1:", CONTEXT_PREFIX) == 0) {
            certType = DecoderVerifier::CertType::EU_DCC;
        } else if (strncmp(qrcode, "LT1:", CONTEXT_PREFIX) == 0) {
            certType = DecoderVerifier::CertType::CH_LIGHT;
        } else {
            printf("bad prefix!\n");
            return m_decodeState = false;
        }
    }
    qrcode += CONTEXT_PREFIX;
    len -= CONTEXT_PREFIX;  // skip certificate prefix

    // base45 decode
    const int MAX_BUF_LEN = 5 * 1024 * 1024;
    std::unique_ptr<uint8_t[]> pb45decoded(new uint8_t[MAX_BUF_LEN]);
    size_t decoded_len = MAX_BUF_LEN;
    int result = 0;
    if ((result = base45_decode(pb45decoded.get(), &decoded_len, qrcode, len))) {
        printf("base45_decode failed with error code: %d!\n", result); 
        return m_decodeState = false;
    }

    // zlib uncompress
    cose.ptr = malloc(MAX_BUF_LEN * sizeof(uint8_t));
    cose.len = MAX_BUF_LEN;
    if ((result = uncompress((uint8_t*)cose.ptr, &cose.len, (const Bytef*)pb45decoded.get(), (uLong)decoded_len)) != Z_OK) {
        printf("uncompress failed with error code: %d\n", result);
        return m_decodeState = false;
    }

    // extract payload, params, phdr, sig
    UsefulBufC tmppayload;
    struct t_cose_sign1_verify_ctx ctx;
    struct t_cose_parameters params;
    t_cose_sign1_verify_init(&ctx, 0);
    ctx.option_flags |= T_COSE_OPT_REQUIRE_KID | T_COSE_OPT_DECODE_ONLY;
    result = t_cose_sign1_verify(&ctx, cose, &tmppayload, &params, &phdr, &sig);
    if (result != 0){
        printf("t_cose_sign1_verify failed with error code: %d\n", result);
        return m_decodeState = false;
    }

    payload.ptr = malloc(tmppayload.len * sizeof(uint8_t));
    memcpy((uint8_t*)payload.ptr, (uint8_t*)tmppayload.ptr, tmppayload.len);  // stack to heap
    payload.len = tmppayload.len;
    alg = params.cose_algorithm_id;  // set algorithm id here
    kid.clear();
    kid.insert(0, (const char*)params.kid.ptr, params.kid.len);
    kid = base64_encode(kid);
    return m_decodeState = true;
}

bool DecoderVerifier::DecoderVerifierImp::getPayload(jsoncons::ojson &pl) {
    if (!getDecodeState()) return false;
    pl.clear();
    std::vector<uint8_t> v((uint8_t*)payload.ptr, (uint8_t*)payload.ptr + payload.len);
    pl = jsoncons::cbor::decode_cbor<jsoncons::ojson>(v);
    return true;
}

DecoderVerifier::CertType DecoderVerifier::DecoderVerifierImp::getCertType() {
    return certType;
}

std::string DecoderVerifier::DecoderVerifierImp::getKID() {
    return kid;
}

DecoderVerifier::DecoderVerifierImp::~DecoderVerifierImp() {
#define DESTROY_BUF(q_buf) do { \
    if (q_buf.ptr) { \
        free((uint8_t*)q_buf.ptr); \
        q_buf.ptr = NULL; \
        q_buf.len = 0; \
    } \
} while (0)
    DESTROY_BUF(payload);
    DESTROY_BUF(phdr);
    DESTROY_BUF(sig);
    DESTROY_BUF(tbs);
    DESTROY_BUF(cose);
}

/***********************************************/

DecoderVerifier::DecoderVerifier():m_imp(NULL) {
    m_imp = new DecoderVerifierImp();
}

DecoderVerifier::~DecoderVerifier() {
    if (m_imp) delete m_imp;
    m_imp = NULL;
}

bool DecoderVerifier::getPayload(jsoncons::ojson &payload) {
    return m_imp->getPayload(payload);
}

bool DecoderVerifier::decode(const char* qrcode, size_t len) {
    return m_imp->decode(qrcode, len);
}

bool DecoderVerifier::setPublicKey(const std::string &k) {
    return m_imp->setPublicKey(k);
}

bool DecoderVerifier::verify() {
    return m_imp->verify();
}

DecoderVerifier::CertType DecoderVerifier::getCertType() {
    return m_imp->getCertType();
}

std::string DecoderVerifier::getKID() {
    return m_imp->getKID();
}

