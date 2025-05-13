#include "ciphersuite/KuznyechikTest.h"
#include "ciphermodes/ECBTest.h"
#include "ciphermodes/CTRTest.h"
#include "ciphermodes/OFBTest.h"
#include "ciphermodes/CBCTest.h"
#include "ciphermodes/CFBTest.h"
#include "ciphermodes/CMACTest.h"
#include "hashfunc/StreebogTest.h"
#include "hmac/HMACTest.h"
#include "kdf/KDFHMACTest.h"
#include "kdf/KDFCMACTest.h"
#include "kexp15kimp15/KExp15Test.h"
#include "crisp/CrispTest.h"
#include "ciphersuite/MagmaTest.h"


int main() {
    KuznyechikTest kuznyechikTest;
    kuznyechikTest.assert_all_functions();

    MagmaTest magmaTest;
    magmaTest.assert_all_functions();

    ECBTest ecbTest;
    ecbTest.assert_all_functions();

    CTRTest ctrTest;
    ctrTest.assert_all_functions();

    OFBTest ofbTest;
    ofbTest.assert_all_functions();

    CBCTest cbcTest;
    cbcTest.assert_all_functions();

    CFBTest cfbTest;
    cfbTest.assert_all_functions();

    CMACTest cmacTest;
    cmacTest.assert_all_functions();

    StreebogTest streebogTest;
    streebogTest.assert_all_functions();

    HMACTest hmacTest;
    hmacTest.assert_all_functions();

    KDFHMACTest kdfHmacTest;
    kdfHmacTest.assert_all_functions();

    KDFCMACTest kdfCmacTest;
    kdfCmacTest.assert_all_functions();

    KExp15Test kexp15Test;
    kexp15Test.assert_all_functions();

    CrispTest crispTest;
    crispTest.assert_all_functions();
}