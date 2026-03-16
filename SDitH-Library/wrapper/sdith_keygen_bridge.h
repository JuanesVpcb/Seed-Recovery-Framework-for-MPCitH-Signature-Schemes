#ifndef SDITH_KEYGEN_BRIDGE_H
#define SDITH_KEYGEN_BRIDGE_H

#include <stdint.h>

/**
 * sdith_bridge_keygen
 * Generates an SDitH key pair from externally provided seeds.
 *
 * @param security_level  1, 3, or 5
 * @param fast            1 = FAST parameters, 0 = SHORT parameters
 * @param skseed          pointer to secret key seed (lambda/8 bytes)
 * @param pkseed          pointer to public key seed (lambda/8 bytes)
 * @param out_public_key  output buffer for public key
 * @param out_secret_key  output buffer for secret key
 * @return 0 on success, -1 on error
 */
int sdith_bridge_keygen(int security_level, int fast,
                        const uint8_t* skseed, const uint8_t* pkseed,
                        uint8_t* out_public_key, uint8_t* out_secret_key);

uint64_t sdith_bridge_public_key_bytes(int security_level, int fast);
uint64_t sdith_bridge_secret_key_bytes(int security_level, int fast);

#endif
