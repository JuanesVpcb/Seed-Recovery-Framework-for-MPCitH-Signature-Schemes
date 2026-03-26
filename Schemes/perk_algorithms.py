"""
PERK Oracle Implementation for Seed Recovery Framework

Minimal faithful implementation of PERK key generation.
Supports security levels 1 (128-bit), 3 (192-bit), and 5 (256-bit).
"""

import hashlib
import secrets
from abstract_oracle import MPCitHOracle


class _ShakePRG:
    """SHAKE-based PRG for PERK seed expansion (CAT1, CAT3, CAT5)."""

    def __init__(self, seed: bytes, shake_size: int) -> None:
        self._seed = seed
        self._shake_size = shake_size
        self._counter = 0
        self._buffer = b""

    def read(self, out_len: int) -> bytes:
        while len(self._buffer) < out_len:
            if self._shake_size == 128:
                xof = hashlib.shake_128()
            else:
                xof = hashlib.shake_256()

            xof.update(self._seed)
            xof.update(self._counter.to_bytes(8, "little"))
            self._buffer += xof.digest(64)
            self._counter += 1

        out = self._buffer[:out_len]
        self._buffer = self._buffer[out_len:]
        return out


class PERKOracle(MPCitHOracle):
    """PERK scheme oracle supporting fast variants for CAT1, CAT3, CAT5."""

    PARAMS_BY_LEVEL = {
        1: {
            "variant": "perk-128-fast",
            "lambda_bits": 128,
            "security_bytes": 16,
            "param_n1": 79,
            "param_m": 35,
            "param_t": 3,
            "param_tau": 30,
            "param_q": 1021,
            "param_q_bits": 10,
            "shake_bits": 128,
            "pk_bytes": 96,  # SEED_BYTES + ((M * Q_BITS * T + 7) / 8)
            "sk_bytes": 128,  # SEED_BYTES + PK_BYTES
        },
        3: {
            "variant": "perk-192-fast",
            "lambda_bits": 192,
            "security_bytes": 24,
            "param_n1": 112,
            "param_m": 54,
            "param_t": 3,
            "param_tau": 46,
            "param_q": 1021,
            "param_q_bits": 10,
            "shake_bits": 256,
            "pk_bytes": 165,  # Adjusted
            "sk_bytes": 195,  # Adjusted
        },
        5: {
            "variant": "perk-256-fast",
            "lambda_bits": 256,
            "security_bytes": 32,
            "param_n1": 150,
            "param_m": 76,
            "param_t": 5,
            "param_tau": 57,
            "param_q": 1021,
            "param_q_bits": 10,
            "shake_bits": 256,
            "pk_bytes": 237,  # Adjusted
            "sk_bytes": 281,  # Adjusted
        },
    }

    def __init__(self, security_level: int = 1, fast: bool = True) -> None:
        if security_level not in self.PARAMS_BY_LEVEL:
            raise ValueError(f"security_level must be one of {list(self.PARAMS_BY_LEVEL.keys())}")
        if not fast:
            raise ValueError("This framework currently supports only fast PERK variants")

        self.security_level = security_level
        self.fast = fast
        self.params = dict(self.PARAMS_BY_LEVEL[security_level])
        self.params["lambda_bytes"] = self.params["lambda_bits"] // 8

    # ============= MPCitHOracle Abstract Methods =============
    def seeds(self) -> tuple[bytes, bytes]:
        """Generate two λ-byte seeds: (skseed, pkseed)."""
        lam = self.params["lambda_bytes"]
        return secrets.token_bytes(lam), secrets.token_bytes(lam)

    def expand(self, seeds: tuple[bytes, bytes]) -> dict:
        """Expand seeds to instance: H matrix, x vectors, and y = H*π(x)."""
        skseed, pkseed = self._validate_seeds(seeds)
        
        # Generate PRG from pkseed
        shake_bits = self.params["shake_bits"]
        prg = _ShakePRG(pkseed, shake_bits)
        
        # Sample permutation from skseed
        perm_prg = _ShakePRG(skseed, shake_bits)
        pi = self._sample_permutation(perm_prg)
        
        # Generate H matrix (m x n1) and x vectors (n1-dim, t copies)
        n1 = self.params["param_n1"]
        m = self.params["param_m"]
        t = self.params["param_t"]
        q = self.params["param_q"]
        
        H = self._random_matrix(prg, m, n1, q)
        x = [self._random_vector(prg, n1, q) for _ in range(t)]
        
        # Compute y = H * π(x)
        y = []
        for xi in x:
            pi_xi = self._permute_vector(pi, xi)
            yi = self._matrix_vector_mul(H, pi_xi, q)
            y.append(yi)
        
        return {
            "skseed": skseed,
            "pkseed": pkseed,
            "H": H,
            "x": x,
            "y": y,
            "pi": pi,
        }

    def proof(self, expanded_material: dict) -> bytes:
        """Return y (the public output of the scheme)."""
        y_vectors = expanded_material["y"]
        m = self.params["param_m"]
        q_bits = self.params["param_q_bits"]
        t = self.params["param_t"]
        
        # Serialize y vectors
        y_bytes = self._serialize_y(y_vectors, m, q_bits, t)
        return y_bytes

    def verify(self, seeds: tuple[bytes, bytes], y: bytes, expanded_material: dict) -> bytes:
        """Verify seeds produce correct y, then return public key."""
        skseed, pkseed = self._validate_seeds(seeds)
        
        # Check if expanded y matches provided y
        proof_y = self.proof(expanded_material)
        if proof_y != y:
            return b""
        
        # Return serialized public key (pkseed || y)
        return self._serialize_public_key(pkseed, y)

    def keygen_from_seeds(self, skseed: bytes, pkseed: bytes) -> tuple[bytes, bytes]:
        """Generate (pk, sk) from seeds."""
        expanded = self.expand((skseed, pkseed))
        public_key = self.verify((skseed, pkseed), self.proof(expanded), expanded)
        
        if public_key == b"":
            raise RuntimeError("Key verification failed")
        
        # For minimal implementation, secret key = skseed || public_key
        secret_key = skseed + public_key
        
        return public_key, secret_key

    def get_seedpk(self, public_key: bytes) -> bytes:
        """Extract pkseed from public key."""
        lam_bytes = self.params["lambda_bytes"]
        return public_key[:lam_bytes]

    def get_y(self, public_key: bytes) -> bytes:
        """Extract y from public key."""
        lam_bytes = self.params["lambda_bytes"]
        return public_key[lam_bytes:]

    # ============= Helper Methods =============
    def _validate_seeds(self, seeds: tuple[bytes, bytes]) -> tuple[bytes, bytes]:
        """Validate seed sizes."""
        lam_bytes = self.params["lambda_bytes"]
        skseed, pkseed = seeds
        if len(skseed) != lam_bytes or len(pkseed) != lam_bytes:
            raise ValueError(f"Seeds must be {lam_bytes} bytes each")
        return skseed, pkseed

    def _sample_permutation(self, prg: _ShakePRG) -> list[int]:
        """Sample a random permutation of n1 elements using Fisher-Yates."""
        n1 = self.params["param_n1"]
        perm = list(range(n1))
        
        # Fisher-Yates shuffle using PRG bytes
        for i in range(n1 - 1, 0, -1):
            # Get random byte and map to [0, i]
            rand_bytes = prg.read(2)
            rand_val = int.from_bytes(rand_bytes, 'little')
            j = rand_val % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        
        return perm

    def _random_vector(self, prg: _ShakePRG, size: int, q: int) -> list[int]:
        """Sample a random vector of size elements in Z_q."""
        q_bits = self.params["param_q_bits"]
        bytes_needed = (size * q_bits + 7) // 8
        
        rand_bytes = prg.read(bytes_needed)
        vector = []
        bit_pos = 0
        
        for _ in range(size):
            val = 0
            for b in range(q_bits):
                byte_idx = bit_pos // 8
                bit_idx = bit_pos % 8
                if byte_idx < len(rand_bytes):
                    bit = (rand_bytes[byte_idx] >> bit_idx) & 1
                    val |= (bit << b)
                bit_pos += 1
            vector.append(val % q)
        
        return vector

    def _random_matrix(self, prg: _ShakePRG, rows: int, cols: int, q: int) -> list[list[int]]:
        """Sample a random matrix of rows x cols elements in Z_q."""
        matrix = []
        for _ in range(rows):
            row = self._random_vector(prg, cols, q)
            matrix.append(row)
        return matrix

    def _permute_vector(self, perm: list[int], vector: list[int]) -> list[int]:
        """Apply permutation π to vector."""
        return [vector[perm[i]] for i in range(len(perm))]

    def _matrix_vector_mul(self, matrix: list[list[int]], vector: list[int], q: int) -> list[int]:
        """Compute matrix-vector product over Z_q."""
        result = []
        for row in matrix:
            dot = sum(row[i] * vector[i] for i in range(len(vector))) % q
            result.append(dot)
        return result

    def _serialize_y(self, y_vectors: list[list[int]], m: int, q_bits: int, t: int) -> bytes:
        """Serialize y vectors to bytes."""
        y_bits = m * q_bits * t
        y_bytes = bytearray((y_bits + 7) // 8)
        
        bit_pos = 0
        for vec in y_vectors:
            for val in vec:
                for b in range(q_bits):
                    if val & (1 << b):
                        byte_idx = bit_pos // 8
                        bit_idx = bit_pos % 8
                        y_bytes[byte_idx] |= (1 << bit_idx)
                    bit_pos += 1
        
        return bytes(y_bytes)

    def _serialize_public_key(self, pkseed: bytes, y: bytes) -> bytes:
        """Serialize public key as pkseed || y."""
        return pkseed + y
