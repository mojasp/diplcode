#include "lcmsec_common.h"
#include <string.h>

lcm_t *lcmsec_setup(int id) {
    lcm_security_parameters secparams={0};

    char key[100];
    char cert[100];

    snprintf(cert, sizeof(cert), "%s%d%s", "test_chain/", id, ".crt");
    printf("cert: %s\n", cert);
    secparams.certificate = cert;

    snprintf(key, sizeof(key), "%s%d%s", "test_chain/", id, ".key");
    printf("key: %s\n", key);
    secparams.keyfile = key;

    secparams.algorithm = strdup("AES-128/GCM");

    secparams.root_ca = strdup("test_chain/root_ca.crt");

    return lcm_create_with_security("udpm://239.255.76.67:7667", &secparams);
}
