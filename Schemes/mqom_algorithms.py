"""
MQOM Oracle Implementation for Seed Recovery Framework

Wraps the existing MQOM Python reference implementation.
Uses gf2_fast_r3 variant for all security levels (1, 3, 5).
"""

import sys
import os
import secrets
from abstract_oracle import MPCitHOracle

# Add MQOM reference to path
MQOM_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "MQOM-v2",
    "Reference_Implementation_Python"
)
if MQOM_PATH not in sys.path:
    sys.path.insert(0, MQOM_PATH)

try:
    from mqom import MQOM2, MQOM2Parameters, Category, TradeOff, Variant
except ImportError as e:
    raise ImportError(f"Failed to import MQOM reference implementation from {MQOM_PATH}: {e}")


class MQOMOracle(MPCitHOracle):
    """MQOM scheme oracle supporting gf2_fast_r3 variant for all security levels."""

    PARAMS_BY_LEVEL = {
        1: {
            "variant": "MQOM2-L1-gf2-fast-R3",
            "lambda_bits": 128,
            "category": Category.I,
            "tradeoff": TradeOff.FAST,
            "scheme_variant": Variant.R3,
        },
        3: {
            "variant": "MQOM2-L3-gf2-fast-R3",
            "lambda_bits": 192,
            "category": Category.III,
            "tradeoff": TradeOff.FAST,
            "scheme_variant": Variant.R3,
        },
        5: {
            "variant": "MQOM2-L5-gf2-fast-R3",
            "lambda_bits": 256,
            "category": Category.V,
            "tradeoff": TradeOff.FAST,
            "scheme_variant": Variant.R3,
        },
    }

    def __init__(self, security_level: int = 1) -> None:
        if security_level not in self.PARAMS_BY_LEVEL:
            raise ValueError(f"security_level must be one of {list(self.PARAMS_BY_LEVEL.keys())}")

        self.security_level = security_level
        self.params = dict(self.PARAMS_BY_LEVEL[security_level])
        self.params["lambda_bytes"] = self.params["lambda_bits"] // 8
        
        # Get MQOM parameters from reference implementation
        self.mqom_params = MQOM2Parameters.get(
            self.params["category"],
            2,  # GF(2)
            self.params["tradeoff"],
            self.params["scheme_variant"]
        )

    # ============= MPCitHOracle Abstract Methods =============
    def seeds(self) -> tuple[bytes, bytes]:
        """
        For MQOM, generate a single master seed (no pkseed).
        Return (master_seed, b"") to maintain uniform interface.
        """
        # MQOM uses a single 2*lda-byte master seed, but for framework compatibility,
        # we return it as the first component and empty bytes as second
        master_seed = secrets.token_bytes(2 * self.mqom_params.lda)
        return master_seed, b""

    def expand(self, seeds: tuple[bytes, bytes]) -> dict:
        """Expand master seed to full MQOM instance (x, mseed_eq, y)."""
        master_seed, _ = seeds
        
        # Create MQOM instance with custom random bytes function
        def random_bytes_fn(n):
            return master_seed[:n] if n <= len(master_seed) else master_seed + secrets.token_bytes(n - len(master_seed))
        
        mqom = MQOM2(self.mqom_params, random_bytes_fn)
        
        # Generate keys using the reference implementation
        pk, sk = mqom.generate_keys(seed_key=master_seed)
        
        # Parse pk and sk to extract components
        # pk format: mseed_eq || y
        # Parse into expanded material
        lda = self.mqom_params.lda
        pk_size = mqom.pk_format.get_bytesize()
        sk_size = mqom.sk_format.get_bytesize()
        
        return {
            "master_seed": master_seed,
            "pk": pk,
            "sk": sk,
            "pk_size": pk_size,
            "sk_size": sk_size,
            "mqom": mqom,
        }

    def proof(self, expanded_material: dict) -> bytes:
        """Return the public key as the proof."""
        return expanded_material["pk"]

    def verify(self, seeds: tuple[bytes, bytes], y: bytes, expanded_material: dict) -> bytes:
        """
        Verify that the expanded material produces the expected public key.
        In MQOM, the public key IS the proof, so just verify it matches.
        """
        master_seed, _ = seeds
        
        # Check if the PK from expanded material matches the provided y
        if expanded_material["pk"] != y:
            return b""
        
        return y

    def keygen_from_seeds(self, skseed: bytes, pkseed: bytes) -> tuple[bytes, bytes]:
        """
        Generate (pk, sk) from seed(s).
        For MQOM: ignore pkseed (unused), use skseed as master seed.
        """
        expanded = self.expand((skseed, pkseed))
        pk = expanded["pk"]
        sk = expanded["sk"]
        
        return pk, sk

    def get_seedpk(self, public_key: bytes) -> bytes:
        """
        For MQOM, extract mseed_eq from public key.
        Public key structure: mseed_eq (2*lda bytes) || y
        """
        lda = self.mqom_params.lda
        mseed_eq_bytes = 2 * lda
        return public_key[:mseed_eq_bytes]

    def get_y(self, public_key: bytes) -> bytes:
        """
        For MQOM, extract y from public key.
        Public key structure: mseed_eq (2*lda bytes) || y
        """
        lda = self.mqom_params.lda
        mseed_eq_bytes = 2 * lda
        return public_key[mseed_eq_bytes:]
