import hashlib
import math
import secrets

from abstract_oracle import MPCitHOracle


class _ShakePRG:
    """SHAKE-based PRG for CAT1 (SHAKE128) and CAT3/CAT5 (SHAKE256)."""

    def __init__(self, seed: bytes, iv: bytes, shake_size: int) -> None:
        self._seed = seed
        self._iv = iv
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
            xof.update(self._iv)
            xof.update(self._counter.to_bytes(8, "little"))
            self._buffer += xof.digest(64)
            self._counter += 1

        out = self._buffer[:out_len]
        self._buffer = self._buffer[out_len:]
        return out


class SDitHOracle(MPCitHOracle):
    """SDitH key expansion supporting CAT1_FAST, CAT3_FAST, and CAT5_FAST."""

    PARAMS_BY_LEVEL = {
        1: {
            "variant": "cat1_fast",
            "lambda_bits": 128,
            "kappa": 8,
            "tau": 16,
            "target_topen": 101,
            "proofow_w": 2,
            "rsd_w": 56,
            "rsd_n": 10360,
            "mux_depth": 4,
            "mux_arities": (4, 4, 4, 3),
            "shake_bits": 128,
        },
        3: {
            "variant": "cat3_fast",
            "lambda_bits": 192,
            "kappa": 8,
            "tau": 24,
            "target_topen": 153,
            "proofow_w": 2,
            "rsd_w": 73,
            "rsd_n": 18396,
            "mux_depth": 4,
            "mux_arities": (4, 4, 4, 4),
            "shake_bits": 256,
        },
        5: {
            "variant": "cat5_fast",
            "lambda_bits": 256,
            "kappa": 8,
            "tau": 32,
            "target_topen": 207,
            "proofow_w": 2,
            "rsd_w": 104,
            "rsd_n": 19864,
            "mux_depth": 4,
            "mux_arities": (4, 4, 4, 3),
            "shake_bits": 256,
        },
    }

    def __init__(self, security_level: int = 1, fast: bool = True) -> None:
        if security_level not in self.PARAMS_BY_LEVEL:
            raise ValueError(f"security_level must be one of {list(self.PARAMS_BY_LEVEL.keys())}")
        if not fast:
            raise ValueError("This framework currently supports only fast SDitH variants")

        self.security_level = security_level
        self.fast = fast
        self.params = dict(self.PARAMS_BY_LEVEL[security_level])
        self.params["lambda_bytes"] = self.params["lambda_bits"] // 8
        self.params["rsd_codim"] = self._compute_rsd_codim(self.params["rsd_n"], self.params["rsd_w"])
        self.params["rsd_codim_bytes"] = (self.params["rsd_codim"] + 7) >> 3
        self.params["npw"] = self.params["rsd_n"] // self.params["rsd_w"]
        self.params["n_minus_k"] = self.params["rsd_n"] - self.params["rsd_codim"]
        self.params["h_col_bytes"] = self.params["rsd_codim_bytes"]
        self.params["h_last_mask"] = 0xFF >> ((-self.params["rsd_codim"]) & 7)
        self.params["mux_inputs"] = self._compute_mux_inputs(
            self.params["mux_depth"], self.params["mux_arities"]
        )
        self.params["encoded_solution_bytes"] = (
            (self.params["rsd_w"] * self.params["mux_inputs"] + 7) >> 3
        )

    def seeds(self) -> tuple[bytes, bytes]:
        lam = self.params["lambda_bytes"]
        return secrets.token_bytes(lam), secrets.token_bytes(lam)

    def expand(self, seeds: tuple[bytes, bytes]) -> dict:
        skseed, pkseed = self._validate_seeds(seeds)
        return self._expand_instance_with_solution(skseed, pkseed)

    def proof(self, expanded_material: dict) -> bytes:
        return expanded_material["pkey_y"]

    def verify(self, seeds: tuple[bytes, bytes], y: bytes, expanded_material: dict) -> bytes:
        _, pkseed = self._validate_seeds(seeds)
        if bytes(y) != expanded_material["pkey_y"]:
            return b""
        return self.serialize_public_key(pkseed, expanded_material["pkey_y"])

    def keygen_from_seeds(self, skseed: bytes, pkseed: bytes) -> tuple[bytes, bytes]:
        expanded = self._expand_instance_with_solution(skseed, pkseed)
        public_key = self.serialize_public_key(pkseed, expanded["pkey_y"])
        secret_key = self.serialize_secret_key(
            skseed,
            pkseed,
            expanded["encoded_solution"],
            expanded["pkey_y"],
        )
        return public_key, secret_key

    def serialize_public_key(self, pkey_seed: bytes, pkey_y: bytes) -> bytes:
        return pkey_seed + pkey_y

    def deserialize_public_key(self, public_key: bytes) -> tuple[bytes, bytes]:
        lam = self.params["lambda_bytes"]
        codim_bytes = self.params["rsd_codim_bytes"]
        expected = lam + codim_bytes
        if len(public_key) != expected:
            raise ValueError("invalid public key size for variant")
        return public_key[:lam], public_key[lam:]

    def serialize_secret_key(
        self,
        skey_seed: bytes,
        pkey_seed: bytes,
        skey_encoded_solution: bytes,
        pkey_y: bytes,
    ) -> bytes:
        return skey_seed + pkey_seed + skey_encoded_solution + pkey_y
    
    def get_seedpk(self, public_key: bytes) -> bytes:
        return self.deserialize_public_key(public_key)[0]
    
    def get_seedsk(self, private_key: bytes) -> bytes:
        lam = self.params["lambda_bytes"]
        return private_key[:lam]
    
    def get_y(self, public_key: bytes) -> bytes:
        return self.deserialize_public_key(public_key)[1]

    def _expand_instance_with_solution(self, skseed: bytes, pkseed: bytes) -> dict:
        h_rows = self._expand_h_from_pkseed(pkseed)
        solution = self._sample_solution_from_skseed(skseed)
        pkey_y = self._compute_pkey_y_from_h_and_solution(h_rows, solution)
        encoded_solution = self._encode_solution(solution)
        return {
            "H_rows": h_rows,
            "solution": solution,
            "encoded_solution": encoded_solution,
            "pkey_y": pkey_y,
            "skey_seed": skseed,
            "pkey_seed": pkseed,
        }

    def _expand_h_from_pkseed(self, pkseed: bytes) -> list[bytes]:
        prg = self._prg_init(pkseed)
        n_minus_k = self.params["n_minus_k"]
        col_bytes = self.params["h_col_bytes"]
        mask = self.params["h_last_mask"]

        h_rows = []
        for _ in range(n_minus_k):
            row = bytearray(prg.read(col_bytes))
            row[-1] &= mask
            h_rows.append(bytes(row))
        return h_rows

    def _sample_solution_from_skseed(self, skseed: bytes) -> list[int]:
        prg = self._prg_init(skseed)
        npw = self.params["npw"]
        npw_max = (1 << 32) - ((1 << 32) % npw)
        solution = []
        for _ in range(self.params["rsd_w"]):
            while True:
                pos = int.from_bytes(prg.read(4), "little")
                if pos < npw_max:
                    solution.append(pos % npw)
                    break
        return solution

    def _compute_pkey_y_from_h_and_solution(self, h_rows: list[bytes], solution: list[int]) -> bytes:
        rsd_w = self.params["rsd_w"]
        npw = self.params["npw"]
        rsd_codim = self.params["rsd_codim"]
        col_bytes = self.params["h_col_bytes"]
        yy = bytearray(self.params["rsd_codim_bytes"])

        for i in range(rsd_w):
            real_index = i * npw + solution[i]
            if real_index < rsd_codim:
                yy[real_index >> 3] ^= 1 << (real_index & 7)
            else:
                row = h_rows[real_index - rsd_codim]
                for j in range(col_bytes):
                    yy[j] ^= row[j]
        yy[-1] &= self.params["h_last_mask"]
        return bytes(yy)

    def _encode_solution(self, solution: list[int]) -> bytes:
        rsd_w = self.params["rsd_w"]
        mux_depth = self.params["mux_depth"]
        mux_arities = self.params["mux_arities"]
        out = bytearray(self.params["encoded_solution_bytes"])

        bitpos = 0
        for i in range(rsd_w):
            si = solution[i]
            for j in range(mux_depth):
                arj = mux_arities[j]
                sij = si % arj
                si //= arj
                if sij != 0:
                    pos = bitpos + sij - 1
                    out[pos // 8] |= 1 << (pos % 8)
                bitpos += arj - 1
        return bytes(out)

    def _validate_seeds(self, seeds: tuple) -> tuple[bytes, bytes]:
        if not isinstance(seeds, tuple) or len(seeds) != 2:
            raise ValueError("seeds must be a tuple: (skseed, pkseed)")
        skseed, pkseed = seeds
        lam = self.params["lambda_bytes"]
        if len(skseed) != lam or len(pkseed) != lam:
            raise ValueError(f"seed size must be {lam} bytes for the variant")
        return skseed, pkseed

    def _prg_init(self, seed: bytes) -> _ShakePRG:
        iv = bytes(self.params["lambda_bytes"])
        shake_bits = self.params["shake_bits"]
        return _ShakePRG(seed=seed, iv=iv, shake_size=shake_bits)

    @staticmethod
    def _compute_mux_inputs(mux_depth: int, mux_arities: tuple[int, ...]) -> int:
        mux_inputs = 0
        for i in range(mux_depth):
            mux_inputs += mux_arities[i] - 1
        return mux_inputs

    @staticmethod
    def _compute_rsd_codim(rsd_n: int, rsd_w: int) -> int:
        # Equivalent to compute_rsd_codim() in sdith_signature.c
        log2_inv_target_density = 6.64385618977
        rsd_nsw = rsd_n // rsd_w
        rsd_min_codim = math.ceil(rsd_w * math.log2(rsd_nsw) + log2_inv_target_density)
        return (rsd_min_codim + 7) & ~7