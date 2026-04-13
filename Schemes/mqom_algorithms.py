"""
MQOM Oracle Implementation for Seed Recovery Framework

Default behavior uses a lightweight deterministic proof-of-concept expansion
that preserves the same seed-recovery interface used by the framework.
Reference MQOM keygen remains available as an opt-in mode.
"""

import sys
import os
import secrets
import hashlib
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
    """MQOM scheme oracle supporting gf2_fast_r3 levels with a fast PoC mode."""

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

    def __init__(self, security_level: int = 1, use_reference: bool = False) -> None:
        if security_level not in self.PARAMS_BY_LEVEL:
            raise ValueError(f"security_level must be one of {list(self.PARAMS_BY_LEVEL.keys())}")

        self.security_level = security_level
        self.use_reference = bool(use_reference)
        self.params = dict(self.PARAMS_BY_LEVEL[security_level])
        self.params["lambda_bytes"] = self.params["lambda_bits"] // 8

        # Get MQOM parameters from reference implementation
        self.mqom_params = MQOM2Parameters.get(
            self.params["category"],
            2,  # GF(2)
            self.params["tradeoff"],
            self.params["scheme_variant"]
        )
        self.params["master_seed_bytes"] = 2 * self.mqom_params.lda
        self.params["mseed_eq_bytes"] = 2 * self.mqom_params.lda
        # Lightweight y size keeps public key compact but non-trivial.
        self.params["y_bytes"] = max(self.params["lambda_bytes"], self.mqom_params.lda)

    # ============= MPCitHOracle Abstract Methods =============
    def seeds(self) -> tuple[bytes, bytes]:
        """
        For MQOM, generate a single master seed (no pkseed).
        Return (master_seed, b"") to maintain uniform interface.
        """
        # MQOM uses a single 2*lda-byte master seed, but for framework compatibility,
        # we return it as the first component and empty bytes as second
        master_seed = secrets.token_bytes(self.params["master_seed_bytes"])
        return master_seed, b""

    def expand(self, seeds: tuple[bytes, bytes]) -> dict:
        """Expand master seed to (mseed_eq, y) in reference or lightweight mode."""
        master_seed, _ = seeds
        if len(master_seed) != self.params["master_seed_bytes"]:
            raise ValueError(f"master_seed must be {self.params['master_seed_bytes']} bytes")

        if self.use_reference:
            return self._expand_reference(master_seed)
        return self._expand_lightweight(master_seed)

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

    def _expand_reference(self, master_seed: bytes) -> dict:
        """Reference path: call upstream MQOM Python implementation."""
        def random_bytes_fn(n):
            if n <= len(master_seed):
                return master_seed[:n]
            return master_seed + secrets.token_bytes(n - len(master_seed))

        mqom = MQOM2(self.mqom_params, random_bytes_fn)
        pk, sk = mqom.generate_keys(seed_key=master_seed)
        return {
            "master_seed": master_seed,
            "pk": pk,
            "sk": sk,
            "mode": "reference",
        }

    def _expand_lightweight(self, master_seed: bytes) -> dict:
        """Fast deterministic PoC path for seed-recovery experiments."""
        mseed_eq_bytes = self.params["mseed_eq_bytes"]
        y_bytes = self.params["y_bytes"]

        # Deterministic expansion from the master seed with domain-separated SHAKE.
        shake = hashlib.shake_256()
        shake.update(b"MQOM-LIGHT-EQ")
        shake.update(master_seed)
        mseed_eq = shake.digest(mseed_eq_bytes)

        shake = hashlib.shake_256()
        shake.update(b"MQOM-LIGHT-Y")
        shake.update(master_seed)
        shake.update(mseed_eq)
        y = shake.digest(y_bytes)

        pk = mseed_eq + y
        # Lightweight secret key keeps the same conceptual shape: seed plus public data.
        sk = master_seed + pk
        return {
            "master_seed": master_seed,
            "pk": pk,
            "sk": sk,
            "mode": "lightweight",
        }

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
