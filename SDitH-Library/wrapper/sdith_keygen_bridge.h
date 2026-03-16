#ifndef SDITH_KEYGEN_BRIDGE_H
#define SDITH_KEYGEN_BRIDGE_H

#include <stdint.h>

int sdith_bridge_keygen(int security_level, int fast,
                        const uint8_t* skseed, const uint8_t* pkseed,
                        uint8_t* out_public_key, uint8_t* out_secret_key);

uint64_t sdith_bridge_public_key_bytes(int security_level, int fast);
uint64_t sdith_bridge_secret_key_bytes(int security_level, int fast);

#endif
