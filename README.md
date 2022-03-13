# 瑞士码报告

[QuickView](#QuickView)
[API注解和用例](#API注解和用例)
[三方库的使用和修改](#三方库的使用和修改)
[瑞士码基本信息](#瑞士码基本信息)
[解码](#解码)
[校验](#校验)
[TrustList下载](#TrustList下载)
[需求相关信息](#需求相关信息)
[参考](#参考)

## Quick View

快速运行:

> $ mkdir build && cd build && cmake .. && make -j8
>
> $ ./ch

你会看到类似如下输出（分别包含字段解析和验签结果）：

```
{
    "1": "CH", 
    "4": 1688056891, 
    "6": 1624984891, 
    "-260": {
        "1": {
            "v": [
                {
                    "ci": "urn:uvci:01:CH:D3EEC3BECA5E15781671A5C0", 
                    "co": "CH", 
                    "dn": 2, 
                    "dt": "2021-06-04", 
                    "is": "Bundesamt für Gesundheit (BAG)", 
                    "ma": "ORG-100031184", 
                    "mp": "EU/1/20/1507", 
                    "sd": 2, 
                    "tg": "840539006", 
                    "vp": "1119349007"
                }
            ], 
            "dob": "1984-03-29", 
            "nam": {
                "fn": "Bosshard", 
                "gn": "Andreas", 
                "fnt": "BOSSHARD", 
                "gnt": "ANDREAS"
            }, 
            "ver": "1.3.0"
        }
    }
}
verify ok!
```



## API注解和用例

* [include/ch.h](./include/ch.h)包含了所有的接口和注解，实现在[src/ch.cpp](./src/ch.cpp)

* [test_ch.cpp](./src/test_ch.cpp)包含了测试用例

由于接口已经封装，你可以如下使用：

```C++
for (const auto code : QRCODES) {
        DecoderVerifier dv;
        dv.decode (code , strlen(code));

        jsoncons::ojson j;
        dv.getPayload(j);
        std::cout << jsoncons::pretty_print(j) << std::endl;

        std::string kid = dv.getKID();
        if (pubkeys.find(kid) != pubkeys.end()) {
            if (dv.setPublicKey(pubkeys[kid])) {
                bool ret = dv.verify();
                if (ret) {
                    printf("verify ok!\n");
                } else {
                    printf("verify failed!\n");
                }
            }
        } else {
            printf("kid is not in pubkeys!\n");
        }
    }

```

获取的payload是一个jsoncons::ojson对象，你可以非常方便的使用这个json对象。
需要注意的是，对于每一个qrcode，你都应该使用一个新的DecoderVerifier对象；而不要构造一个DV对象后，对多个qrcode进行操作，当然，你可以修改里面的资源申请和释放操作，从而满足该方式。



## 三方库的使用和修改

* [base45](https://github.com/ehn-dcc-development/base45-ansi-C.git)
* [base64](https://github.com/ReneNyffenegger/cpp-base64)
* [zlib](https://github.com/madler/zlib.git)
* [qcbor](https://github.com/laurencelundblade/QCBOR)
* [openssl](https://github.com/openssl/openssl)
* [t_cose](https://github.com/laurencelundblade/t_cose)
* [jsoncons](https://github.com/danielaparker/jsoncons)

openssl使用的版本是openssl-1.1.1k
为了支持PS256签名算法，对原来的t_cose开源库做了修改，请使用res目录下的t_cose库;
你可以使用git diff，查看t_cose库的修改
以上个别库的编译需要C++11的支持


## 瑞士码基本信息

1. 瑞士码包含4种二维码：

   * 疫苗码
   * 康复码
   * 检测码
   * 抗体码

   其中前三种就是[欧盟码](https://github.com/ehn-dcc-development/ehn-dcc-schema)（Dcc: Digital Covid-Certificate），第四种仅在瑞士有效；但是为了他们的手机app兼容性考虑，抗体码在检测码的基础上对三个字段做了硬编码:

   * Type of Test-**tt** : (from typeCode in Test Certificate request.) : [94504-8](https://loinc.org/94504-8)

   - Test Result-**tr** : [260373001](https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/main/valuesets/test-result.json)
   - as an EVP_PKEY pointer with its reference count incremented:Date/Time of Sample Collection-**sc** : **sampleDate** at start of day (midnight: 00:00:00)

   具体请看[这里](https://github.com/admin-ch/CovidCertificate-Apidoc#bulb-for-your-information-bulb)；这样抗体码也可以归为检测码。

2. 另外瑞士那边处于数据保护，基于上述4种二维码，删除健康信息后，生成了一种轻量级的二维码，叫做[`Certificate light`](https://www.bag.admin.ch/bag/en/home/krankheiten/ausbrueche-epidemien-pandemien/aktuelle-ausbrueche-epidemien/novel-cov/covid-zertifikat/covid-zertifikat-grundlagen.html#-1673323790)，该二维码也仅在瑞士有效，解码和验签流程和Dcc无区别，是否需要支持和需求相关;看[Kotlin-SDK](https://github.com/admin-ch/CovidCertificate-SDK-Kotlin)的实现，只需要验证签名，没有过期，uvci不在废弃列表中即可。



## 解码

在官方提供的[Android-SDK](https://github.com/admin-ch/CovidCertificate-SDK-Android)中解释了解码流程：

Decoding a QR code into a COVID certificate uses the following steps. For more information, refer to the [EHN specification](https://ec.europa.eu/health/sites/default/files/ehealth/docs/digital-green-certificates_v1_en.pdf).

1. Check the prefix of the data. Only `HC1:` (EU Dcc Certificate) and `LT1:` (CH Certificate Light) are valid prefixes你可以使用git diff，查看t_cose库的修改
2. Base45 decode the data [[1\]](https://datatracker.ietf.org/doc/draft-faltstrom-base45/)
3. ZLIB decompress the data
4. COSE decode the data [[2\]](https://github.com/cose-wg/COSE-JAVA)
5. CBOR decode the data and parse it into a `CertificateHolder` containing either a `DccCert` or a `ChLightCert`

注意：

1. 抗体码也是检测码，以`HC1:`开头，属于EU Dcc Certificate
2. Light版二维码以`LT1:`开头

二维码解析出来后，各个字段的相关信息，请看[示例](https://github.com/admin-ch/CovidCertificate-Examples#recovery)和[api-doc中的介绍](https://github.com/admin-ch/CovidCertificate-Apidoc#request---certificate-data)



以下两个示例

* 瑞士疫苗码
```
HC1:NCFR606G0/3WUWGSLKH47GO0Y%5S.PK%96L79CK3600XK0JCV496F37.JZK72F3QWR-L7Y50.FK6ZK7:EDOLOPCO8F6%E3.DA%EOPC1G72A6YM8LG7UL61Y8RL61Y8/A8SX8XW6U47J%69A60X6B56UPC0JCZ69FVCPD0LVC6JD846Y96C463W50S6+EDG8F3I80/D6$CBECSUER:C2$NS346$C2%E9VC- CSUE145GB8JA5B$D% D3IA4W5646946%96X47.JCP9EJY8L/5M/5546.96D463KC.SC4KCD3DX47B46IL6646H*6Z/E5JD%96IA74R6646407GVC*JC1A6X473W56L6WF6TPCBEC7ZKW.C58D14EOQEGEC3VCI3DI2D0/DZKEHECLPCG/D58DC1AZNARB82T8I3D9WENB8US8:X8HOAO/EZKEZ967L6256V50/K9PI4551S/PR+8XU3OUUR8QBMVIXROO0. 65WU/C1P9EGQ3YILMN9SAU%*IW%0Q-GNVFQUN*/6Q6KGRL9%Q6OV03QT+S9DKI6W.BL-.9-9PL:BN-Q75ER/FFI4E7N*PIY2IFO6T236%7C3W20ECAD44BC5R5:KPL7BN5+QL/TP/SN:BHYXARBUOAS2AM%FHV-R1NU%:6S2NCOHH7IALHN PM 56OOI61H+EM:D-:C8V3/ZUI7HVDVE+PE:J8SKU*UM3O5*PUBENOS1O4M+O- SZKE72WA%T:ZGCRI+20PXLCCFB82T%ORB03NFD5ON6Q4V552DOT0-E1343Z$CNJOP54E-KZQ7*4HNY7FTE 3A:BDJ09YW2LI9 0C6EQAD5*LVZ8S
  {
      "1": "CH", 
      "4": 1688056891, 
      "6": 1624984891, 
      "-260": {
          "1": {
              "v": [
                  {
                      "ci": "urn:uvci:01:CH:D3EEC3BECA5E15781671A5C0", 
                      "co": "CH", 
                      "dn": 2, 
                      "dt": "2021-06-04", 
                      "is": "Bundesamt für Gesundheit (BAG)", 
                      "ma": "ORG-100031184", 
                      "mp": "EU/1/20/1507", 
                      "sd": 2, 
                      "tg": "840539006", 
                      "vp": "1119349007"
                  }
              ], 
              "dob": "1984-03-29", 
              "nam": {
                  "fn": "Bosshard", 
                  "gn": "Andreas", 
                  "fnt": "BOSSHARD", 
                  "gnt": "ANDREAS"
              }, 
              "ver": "1.3.0"
          }
      }
  }
```
* 瑞士Light码
```
  LT1:NCFP80M80T9WUWGSLKH47GO0W*TE:D.W8P/18CKULD*70YM8FN0EGCQBWWY0DGC..L597.FKMTKGVC*JC1A6X473W5$Q6PF6TPCBEC7ZKW.C 2D7WEZED5$C JC7/DAC8HWEM-D:1A*PDXKEW.C9WE2OA7Y8C+9VIAI3DDWENB8STA3+9C1A5N9VIAO/EZKEZ96446256V50PIHMFS09S+-5DVMWGT.TOFD6QCO*RLO58WYBY%RD2V050/.BCX4TEH-+FXYRM-UAPVEXBJOT4Y92T74SE2/G$TQC75Q/1FOFV8U/BI1Z5.ID:AWN:P56D+XAVR427DZ-R38EV7VERG$PRARFJ1N.$J +UZBJ+3A183MG78PTRVKWVEC-E$QNGUHY87HP80VD$NNCROM39X REHC33JF3PEQ6R$ECTTXW6/NK1*B6DH$6C7TFUWNVDQ%1U4A771BZKBIJKVXE35676799FVY0NF0Q$NRSBP0P/C9X1C.PMIAB7$SX/H:X64:8W 3WHO3HL96M8YS78ERIAHM4/I5*Z4 AS.:8:-0U.4+WMI7UJ8WGK5QQ4LDB--U -TNAK+C2B13TYL
  {
      "1": "CH", 
      "4": 1640693545, 
      "6": 1640607145, 
      "-250": {
          "1": {
              "dob": "1984-04-22", 
              "nam": {
                  "fn": "Steiner", 
                  "gn": "Anton Oskar", 
                  "fnt": "STEINER", 
                  "gnt": "ANTON<OSKAR"
              }, 
              "ver": "1.0.0"
          }
      }
  }
```

注意Light码中只包含了最基本的信息，不包含健康信息



## 校验

The verification process consists of three parts that need to be successful in order for a certificate to be considered valid.

1. The certificate signature is verified against a list of trusted public keys from issueing countries
2. The UVCI (unique vaccination certificate identifier) is compared to a list of revoked certificates to ensure the certificate has not been revoked
3. The certificate details are checked based on the Swiss national rules for certificate validity. (Is the number of vaccination doses sufficient, is the test recent enough, how long ago was the recovery?)

备注：

1. 第一步是使用公钥验签
2. 第二步是将二维码id和废弃列表比对
3. 第三步是使用national rules验证将二维码内的信息[

其中公钥，废弃列表和national rules都可以通过api-token访问官方服务下载（见下一节）
注意national rules使用的是[CertLogic](https://github.com/ehn-dcc-development/dgc-business-rules/blob/main/certlogic/specification/README.md)方式表示的，CertLogic是[jsonLogic](https://jsonlogic.com/)的一个子集，目前有Java，Kotlin，js等语言的解析引擎，没有找到C/C++的实现。
[这个](https://github.com/panzi/jsonlogic-c)是jsonlogic的一个C实现(也实现了CertLogic)，但是作者表示，只是一个toy，不保证正确性和速度。



## TrustList下载

相关信息需要从给定网站上下载，而访问该网站需要API-TOKEN;

### API-TOKEN获取

[api-doc](https://github.com/admin-ch/CovidCertificate-Apidoc#specific-recovery-data)给出了[获取方式](https://github.com/admin-ch/CovidCertificate-Apidoc#verification-api):与 [Covid-Zertifikat@bag.admin.ch](mailto:Covid-Zertifikat@bag.admin.ch)联系



### 下载地址

* DCSs

```
https://www.cc.bit.admin.ch/trust/v2/keys/list
```

```
https://www.cc.bit.admin.ch/trust/v2/keys/updates
```

* Revocation List

```
https://www.cc.bit.admin.ch/trust/v2/revocationList
```

* National Rules

```
https://www.cc.bit.admin.ch/trust/v2/verificationRules
```

可以使用Postman工具，向以上链接发送请求（需要api-token)，鉴权方式是Bearer
或者使用[get_trustlist.py](./res/get_trustlist.py)脚本获取，注意你需要一个正式的api-token



## 需求相关信息

针对不同的场景，有不同的[检测模式](https://www.bag.admin.ch/bag/en/home/krankheiten/ausbrueche-epidemien-pandemien/aktuelle-ausbrueche-epidemien/novel-cov/covid-zertifikat/covid-zertifikat-einsatz.html#-296420520)

更多信息请看[这里](https://www.bag.admin.ch/bag/en/home/krankheiten/ausbrueche-epidemien-pandemien/aktuelle-ausbrueche-epidemien/novel-cov/massnahmen-des-bundes.html)

你可以使用git diff，查看t_cose库的修改你可以使用git diff，查看t_cose库的修改


## 参考
* [rfc7049 CBOR](https://datatracker.ietf.org/doc/html/rfc7049)
* [rfc8949 CBOR](https://cbor.io/)
* [base45](https://github.com/ehn-dcc-development/base45-ansi-C.git)
* [zlib](https://github.com/madler/zlib.git)
* [t_cose](https://github.com/laurencelundblade/t_cose)
* [qcbor](https://github.com/laurencelundblade/QCBOR)
* [openssl](https://github.com/openssl/openssl)
* [eu-dcc-specification](https://ec.europa.eu/health/sites/health/files/ehealth/docs/digital-green-certificates_dt-specifications_en.pdf)
* [jsoncons](https://github.com/danielaparker/jsoncons)
* [hcert-spec](https://github.com/ehn-dcc-development/hcert-spec)
* [hcer-kotlin](https://github.com/ehn-dcc-development/hcert-kotlin)
* [ehn-dev](https://github.com/ehn-dcc-development)
* [dgc-testdata](https://github.com/eu-digital-green-certificates/dgc-testdata/tree/d142b8d23afa742e00659f0e99f636211f153218)
* [Kotlin-SDK](https://github.com/admin-ch/CovidCertificate-SDK-Kotlin)
* [Android-SDK](https://github.com/admin-ch/CovidCertificate-SDK-Android)
* [Switzerland covid certificate doc](https://www.bag.admin.ch/covid-certificate)
* [fileds of certificates](https://github.com/admin-ch/CovidCertificate-Examples)
* [cose-algorithm](https://python-cwt.readthedocs.io/en/stable/algorithms.html)
* [COSE_Sign1 Structure](https://pycose.readthedocs.io/en/latest/cose/messages/sign1message.html)
* [Decode your EU Digital COVID Certificate using Linux tools](https://www.corentindupont.info/blog/posts/Programming/2021-08-13-GreenPass.html#summary)
* [COSE PS256](https://datatracker.ietf.org/doc/rfc8230/)
