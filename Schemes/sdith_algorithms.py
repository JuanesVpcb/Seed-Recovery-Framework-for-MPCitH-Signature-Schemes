import hashlib
import secrets

from abstract_oracle import MPCitHOracle


class SDitHOracle(MPCitHOracle):
    """Simplified SDitH-like oracle with deterministic seed expansion and serialization."""

    PARAMS = {
        1: {"lambda": 16, "n": 256, "k": 128, "t": 16},
        3: {"lambda": 24, "n": 384, "k": 192, "t": 24},
        5: {"lambda": 32, "n": 512, "k": 256, "t": 32},
    }

    def __init__(self, security_level: int = 1) -> None:
        if security_level not in self.PARAMS:
            raise ValueError("security_level must be one of: 1, 3, 5")
        self.security_level = security_level
        self.params = self.PARAMS[security_level]

    def seeds(self) -> tuple[bytes, bytes]:
        """Generate (skseed, pkseed), both lambda-byte values."""
        lam = self.params["lambda"]
        return secrets.token_bytes(lam), secrets.token_bytes(lam)

    def expand(self, seeds: tuple[bytes, bytes]) -> dict:
        """
        Expand seeds deterministically using PRG.Init-style initialization.

        - ExpandH uses pkseed and integer sampling from a PRG stream.
        - Witness uses skseed and integer sampling for support positions.
        """
        if not isinstance(seeds, tuple) or len(seeds) != 2:
            raise ValueError("seeds must be a tuple: (skseed, pkseed)")

        skseed, pkseed = seeds
        expected = self.params["lambda"]
        if len(skseed) != expected or len(pkseed) != expected:
            raise ValueError("seed sizes do not match security level")

        h_prg = self._prg_init(pkseed, b"ExpandH")
        h_matrix = self._expand_h(h_prg)

        w_prg = self._prg_init(skseed, b"Witness")
        witness = self._sample_weight_t_vector(w_prg)

        return {
            "H": h_matrix,
            "witness": witness,
            "skseed": skseed,
            "pkseed": pkseed,
        }

    def proof(self, expanded_material: dict) -> bytes:
        """Compute syndrome y = H * witness over GF(2), serialized as bytes."""
        h_matrix = expanded_material["H"]
        witness = expanded_material["witness"]
        syndrome_bits = []

        for row in h_matrix:
            dot = 0
            for i, bit in enumerate(row):
                dot ^= bit & witness[i]
            syndrome_bits.append(dot)

        return self._bits_to_bytes(syndrome_bits)

    def verify(self, seeds: tuple[bytes, bytes], y: bytes, expanded_material: dict) -> bytes:
        """Return serialized public key if y is consistent; otherwise empty bytes."""
        if not isinstance(y, (bytes, bytearray)):
            raise ValueError("y must be bytes")

        recomputed = self.proof(expanded_material)
        if recomputed != bytes(y):
            return b""

        _, pkseed = seeds
        return self.serialize_public_key(pkseed, recomputed)

    # Helper methods for key generation and serialization
    def keygen_from_seeds(self, skseed: bytes, pkseed: bytes) -> tuple[bytes, bytes]:
        """Deterministic key generation from explicit seeds."""
        expanded = self.expand((skseed, pkseed))
        y = self.proof(expanded)
        pk = self.serialize_public_key(pkseed, y)
        sk = self.serialize_secret_key(pkseed, y, expanded['witness'], skseed)
        return pk, sk

    def serialize_public_key(self, h_a_seed: bytes, y: bytes) -> bytes:
        """Serialize public key as H_a_seed || y."""
        return h_a_seed + y

    def deserialize_public_key(self, pk: bytes) -> tuple[bytes, bytes]:
        """Deserialize public key encoded as H_a_seed || y."""
        lam = self.params["lambda"]
        if len(pk) < lam:
            raise ValueError("public key is too short")
        return pk[:lam], pk[lam:]

    def serialize_secret_key(self, pkseed: bytes, y: bytes, witness: list[int], skseed: bytes) -> bytes:
        """Serialize secret key as raw master seed m_seed."""
        return skseed + y + self._bits_to_bytes(witness) + pkseed

    def deserialize_secret_key(self, sk: bytes) -> bytes:
        """Deserialize secret key (raw m_seed)."""
        return sk

    # Routines for deterministic PRG expansion and sampling
    def _prg_init(self, seed: bytes, domain: bytes):
        """Initialize XOF-based PRG state with domain separation."""
        # TODO: In a real implementation, we would want to use a proper XOF construction with a counter for multiple calls.
        xof = hashlib.shake_256()
        xof.update(b"SDitH-v2")
        xof.update(domain)
        xof.update(len(seed).to_bytes(2, "big"))
        xof.update(seed)
        return xof

    def _sample_uint(self, prg_state, modulus: int) -> int:
        """Sample an unbiased integer in [0, modulus)."""
        if modulus <= 0:
            raise ValueError("modulus must be > 0")

        threshold = (1 << 16) - ((1 << 16) % modulus)
        while True:
            candidate = int.from_bytes(prg_state.digest(2), "big")
            if candidate < threshold:
                return candidate % modulus

    def _expand_h(self, prg_state) -> list[list[int]]:
        """ExpandH: build a binary (n-k) x n matrix from PRG integer sampling."""
        n = self.params["n"]
        r = n - self.params["k"]
        h_matrix = []

        for _ in range(r):
            row = [0] * n
            for j in range(n):
                row[j] = self._sample_uint(prg_state, 2)
            h_matrix.append(row)

        return h_matrix

    def _sample_weight_t_vector(self, prg_state) -> list[int]:
        """Sample witness of length n and Hamming weight t."""
        n = self.params["n"]
        t = self.params["t"]
        witness = [0] * n
        used = set()

        while len(used) < t:
            idx = self._sample_uint(prg_state, n)
            if idx in used:
                continue
            used.add(idx)
            witness[idx] = 1

        return witness

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        """Pack a list of 0/1 bits into bytes (MSB first in each byte)."""
        if not bits:
            return b""

        out = bytearray((len(bits) + 7) // 8)
        for i, bit in enumerate(bits):
            if bit:
                out[i // 8] |= 1 << (7 - (i % 8))
        return bytes(out)