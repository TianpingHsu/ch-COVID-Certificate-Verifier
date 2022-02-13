#include "ch.h"
#include <cstring>
#include "testdata.h"
#include "base64.h"
#include <fstream>
#include "pubkeys.h"
using namespace std;

void test_light() {
    char TEST_LT1[] =
        "LT1:NCFP80M80T9WUWGSLKH47GO0W*TE:D.W8P/18CKULD*70YM8FN0EGCQBWWY0DGC..L597.FKMTKGVC*JC1A6X473W5$Q6PF6TPCBEC7ZKW.C 2D7WEZED5$C JC7/DAC8HWEM-D:1A*PDXKEW.C9WE2OA7Y8C+9VIAI3DDWENB8STA3+9C1A5N9VIAO/EZKEZ96446256V50PIHMFS09S+-5DVMWGT.TOFD6QCO*RLO58WYBY%RD2V050/.BCX4TEH-+FXYRM-UAPVEXBJOT4Y92T74SE2/G$TQC75Q/1FOFV8U/BI1Z5.ID:AWN:P56D+XAVR427DZ-R38EV7VERG$PRARFJ1N.$J +UZBJ+3A183MG78PTRVKWVEC-E$QNGUHY87HP80VD$NNCROM39X REHC33JF3PEQ6R$ECTTXW6/NK1*B6DH$6C7TFUWNVDQ%1U4A771BZKBIJKVXE35676799FVY0NF0Q$NRSBP0P/C9X1C.PMIAB7$SX/H:X64:8W 3WHO3HL96M8YS78ERIAHM4/I5*Z4 AS.:8:-0U.4+WMI7UJ8WGK5QQ4LDB--U -TNAK+C2B13TYL";
    DecoderVerifier dv;
    dv.decode(TEST_LT1, strlen(TEST_LT1));

}

int main() {
    //while (true) {
        for (const auto code : QRCODES) {
            DecoderVerifier dv;
            dv.decode (code , strlen(code));

            jsoncons::ojson j;
            dv.getPayload(j);
            //std::cout << jsoncons::pretty_print(j) << std::endl;

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
    //}
}
