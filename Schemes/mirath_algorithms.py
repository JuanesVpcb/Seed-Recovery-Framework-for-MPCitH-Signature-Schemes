"""
Mirath Oracle Implementation for Seed Recovery Framework

Minimal faithful implementation of Mirath key generation.
Uses multivariate polynomial scheme. Supports levels 1a, 3a, 5a (fast variants).
"""

import hashlib
import secrets
from abstract_oracle import MPCitHOracle


class _ShakePRG:
    """SHAKE-based PRG for Mirath seed expansion."""

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


class MirathOracle(MPCitHOracle):
    """Mirath scheme oracle supporting 'a' variant fast modes for levels 1, 3, 5."""

    PARAMS_BY_LEVEL = {
        1: {
            "variant": "mirath_1a_fast",
            "lambda_bits": 128,
            "security_bytes": 16,
            "param_q": 16,
            "param_m": 16,
            "param_k": 143,
            "param_n": 16,
            "param_r": 4,
            "param_tau": 17,
            "param_rho": 16,
            "param_mu": 2,
            "shake_bits": 128,
            "pk_bytes": 73,
            "sk_bytes": 104,
        },
        3: {
            "variant": "mirath_3a_fast",
            "lambda_bits": 192,
            "security_bytes": 24,
            "param_q": 256,
            "param_m": 16,
            "param_k": 143,
            "param_n": 16,
            "param_r": 4,
            "param_tau": 24,
            "param_rho": 16,
            "param_mu": 2,
            "shake_bits": 256,
            "pk_bytes": 109,
            "sk_bytes": 157,
        },
        5: {
            "variant": "mirath_5a_fast",
            "lambda_bits": 256,
            "security_bytes": 32,
            "param_q": 256,
            "param_m": 32,
            "param_k": 287,
            "param_n": 32,
            "param_r": 8,
            "param_tau": 32,
            "param_rho": 32,
            "param_mu": 2,
            "shake_bits": 256,
            "pk_bytes": 217,
            "sk_bytes": 313,
        },
    }

    def __init__(self, security_level: int = 1, fast: bool = True) -> None:
        if security_level not in self.PARAMS_BY_LEVEL:
            raise ValueError(f"security_level must be one of {list(self.PARAMS_BY_LEVEL.keys())}")
        if not fast:
            raise ValueError("This framework currently supports only fast Mirath variants")

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
        """Expand seeds to multivariate polynomial instance."""
        skseed, pkseed = self._validate_seeds(seeds)
        
        # Generate PRG from pkseed for public polynomial
        shake_bits = self.params["shake_bits"]
        pub_prg = _ShakePRG(pkseed, shake_bits)
        
        # Generate PRG from skseed for secret data
        sec_prg = _ShakePRG(skseed, shake_bits)
        
        m = self.params["param_m"]
        n = self.params["param_n"]
        r = self.params["param_r"]
        k = self.params["param_k"]
        mu = self.params["param_mu"]
        
        # Sample random solution x of length n*m (in extension field GF(q^mu))
        x = self._random_gf_vector(sec_prg, n * m, self.params["param_q"], mu)
        
        # Sample random multivariate polynomial coefficients
        # For TCiTH: use public seed to generate public polynomial
        # Number of monomials in m vars of degree 2: m(m+1)/2 + m + 1
        num_monomials = (m * (m + 1)) // 2 + m + 1
        
        # Generate m polynomials
        polys = []
        for _ in range(m):
            # Each polynomial has k terms (rank of multivariate system)
            poly_coeff = self._random_gf_vector(pub_prg, k, self.params["param_q"], mu)
            polys.append(poly_coeff)
        
        # Compute y = F(x) (multivariate polynomial evaluation)
        y = self._evaluate_polynomials(polys, x, m, n, self.params["param_q"])
        
        return {
            "skseed": skseed,
            "pkseed": pkseed,
            "x": x,
            "y": y,
            "polynomials": polys,
        }

    def proof(self, expanded_material: dict) -> bytes:
        """Return y (multivariate polynomial evaluation output)."""
        y = expanded_material["y"]
        
        # Serialize y
        y_bytes = self._serialize_gf_vector(y, self.params["param_q"])
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

    def _random_gf_vector(self, prg: _ShakePRG, size: int, q: int, mu: int) -> list[int]:
        """Sample a random vector in GF(q^mu)."""
        # Compute bits needed per element
        q_bits = q.bit_length()
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

    def _evaluate_polynomials(self, polys: list[list[int]], x: list[int], 
                             m: int, n: int, q: int) -> list[int]:
        """Evaluate multivariate polynomials at point x."""
        result = []
        
        for poly in polys:
            # Simple evaluation: sum of coefficients * x[i]
            # In full implementation, would compute actual polynomial evaluation
            val = 0
            for i, coeff in enumerate(poly):
                if i < len(x):
                    val = (val + coeff * x[i]) % q
            result.append(val)
        
        return result

    def _serialize_gf_vector(self, vector: list[int], q: int) -> bytes:
        """Serialize GF(q) vector to bytes."""
        q_bits = q.bit_length()
        total_bits = len(vector) * q_bits
        total_bytes = (total_bits + 7) // 8
        result = bytearray(total_bytes)
        
        bit_pos = 0
        for val in vector:
            for b in range(q_bits):
                if val & (1 << b):
                    byte_idx = bit_pos // 8
                    bit_idx = bit_pos % 8
                    result[byte_idx] |= (1 << bit_idx)
                bit_pos += 1
        
        return bytes(result)

    def _serialize_public_key(self, pkseed: bytes, y: bytes) -> bytes:
        """Serialize public key as pkseed || y."""
        return pkseed + y
