#ifndef __CH_H__
#define __CH_H__

#include <cstdio>
#include <string>
#include <jsoncons/json.hpp>
#include <jsoncons_ext/cbor/cbor.hpp>

class DecoderVerifier {
    public:
        DecoderVerifier();
        ~DecoderVerifier();

        bool decode(const char* qrcode, size_t len);

        bool getPayload(jsoncons::ojson & payload);

        // return 'kid' filed of COSE, which is base64 encoded
        // Example:
        //      DecoderVerifier dv;
        //      bool ret = dv.decode();
        //      if (ret) {
        //          std::string kid = dv.getKID();
        //      }
        std::string getKID();

        // set public key, which is X509 Certificate format without header and footer
        bool setPublicKey(const std::string &k);

        // true : verify successfully
        // false : verify failed
        bool verify();

        enum class CertType {
            UNKNOWN,
            EU_DCC,
            CH_LIGHT,
        };

        CertType getCertType();

    private:
        class DecoderVerifierImp;
        DecoderVerifierImp* m_imp;
};

#endif
