/**
 * sdith_keygen_bridge.c
 *
 * Bridge exposing SDitH key generation to Python.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sdith_signature.h"
#include "sdith_keygen_bridge.h"

static const signature_parameters* pick_params(int security_level, int fast) {
    if (fast) {
        if (security_level == 1) return &CAT1_FAST_PARAMETERS;
        if (security_level == 3) return &CAT3_FAST_PARAMETERS;
        if (security_level == 5) return &CAT5_FAST_PARAMETERS;
    } else {
        if (security_level == 1) return &CAT1_SHORT_PARAMETERS;
        if (security_level == 3) return &CAT3_SHORT_PARAMETERS;
        if (security_level == 5) return &CAT5_SHORT_PARAMETERS;
    }
    return NULL;
}

int sdith_bridge_keygen(int security_level, int fast,
                        const uint8_t* skseed, const uint8_t* pkseed,
                        uint8_t* out_public_key, uint8_t* out_secret_key) {
    const signature_parameters* params = pick_params(security_level, fast);
    uint8_t* entropy = NULL;
    uint8_t* tmp_space = NULL;
    uint64_t lambda_bytes;
    uint64_t tmp_bytes;

    if (!params || !skseed || !pkseed || !out_public_key || !out_secret_key) {
        return -1;
    }

    lambda_bytes = params->lambda >> 3;

    /* entropy = pkseed || skseed (required by sdith_keygen) */
    entropy = (uint8_t*)malloc(2 * lambda_bytes);
    if (!entropy) {
        return -1;
    }
    memcpy(entropy, pkseed, lambda_bytes);
    memcpy(entropy + lambda_bytes, skseed, lambda_bytes);

    tmp_bytes = sdith_keygen_tmp_bytes(params);
    tmp_space = (uint8_t*)malloc(tmp_bytes);
    if (!tmp_space) {
        free(entropy);
        return -1;
    }

    sdith_keygen(params, out_secret_key, out_public_key, entropy, tmp_space);

    free(tmp_space);
    free(entropy);
    return 0;
}

uint64_t sdith_bridge_public_key_bytes(int security_level, int fast) {
    const signature_parameters* params = pick_params(security_level, fast);
    if (!params) return 0;
    return sdith_public_key_bytes(params);
}

uint64_t sdith_bridge_secret_key_bytes(int security_level, int fast) {
    const signature_parameters* params = pick_params(security_level, fast);
    if (!params) return 0;
    return sdith_secret_key_bytes(params);
}
