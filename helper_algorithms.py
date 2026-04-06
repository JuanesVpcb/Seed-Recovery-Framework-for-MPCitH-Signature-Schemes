import os
import random

from abstract_oracle import MPCitHOracle

_BBLM_MODULES_READY = False

def _ensure_bblm_modules_loaded() -> None:
    """Load BBLM-Algorithms modules from the local repository path."""
    global _BBLM_MODULES_READY
    if _BBLM_MODULES_READY:
        return

    bblm_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "BBLMAlgorithms")
    if not os.path.isdir(bblm_dir):
        raise FileNotFoundError("BBLMAlgorithms directory not found in repository root")

    # Import lazily to keep startup lightweight.
    global bitarray, initialize, build_posteriors_from_tilde, generate_candidates_trimmed
    from bitarray import bitarray
    from BBLMAlgorithms.okeanode import initialize
    from BBLMAlgorithms.MonteCarlo import generate_candidates_trimmed, build_posteriors_from_tilde

    _BBLM_MODULES_READY = True

# ================================== Model-Agnostic Algorithms for Key Recovery ==================================
def introduce_noise(seed: bytes, alpha: float, beta: float) -> bytes:
    """Introduces noise to the seed based on the specified alpha and beta parameters.
    Each bit of every byte is independently flipped: 0->1 with probability alpha,
    1->0 with probability beta."""
    rand = random.random
    noisy_bytes = bytearray(len(seed))
    for byte_index, byte in enumerate(seed):
        noisy_byte = 0
        for bit_index in range(7, -1, -1):  # iterate bits MSB to LSB
            bit = (byte >> bit_index) & 1
            if bit == 0:
                noisy_bit = 1 if rand() < alpha else 0
            else:
                noisy_bit = 0 if rand() < beta else 1
            noisy_byte = (noisy_byte << 1) | noisy_bit
        noisy_bytes[byte_index] = noisy_byte
    return bytes(noisy_bytes)


# ----------------------- Connector Function for BBLM-style Reconstruction from Noisy Seeds -----------------------
def ranked_seed_candidates_from_noisy(
    noisy_seed: bytes,
    alpha: float,
    beta: float,
    w: int,
    mu: int,
    max_candidates: int,
) -> list[bytes]:
    _ensure_bblm_modules_loaded()
    observed_bits = bitarray()
    observed_bits.frombytes(noisy_seed)
    observed_bits = observed_bits[: len(noisy_seed) * 8]
    W = len(observed_bits)

    if W % w != 0:
        raise ValueError("w must divide the noisy seed bit-length")

    # Use the reference BBLM candidate-generation logic (MonteCarlo module).
    posteriors = build_posteriors_from_tilde(observed_bits, alpha, beta)
    # eta=1 keeps the same per-chunk composition shape used by the framework.
    chunk_lists = generate_candidates_trimmed(posteriors, W, w, 1, mu, scale=10000.0)

    if not chunk_lists:
        return []

    # Use OKEA from BBLM-Algorithms to enumerate global top candidates.
    okea_tree = initialize(chunk_lists, 0, len(chunk_lists) - 1, scale=10000.0)
    out = []
    for j in range(max_candidates):
        cand = okea_tree.getCandidate(j)
        if cand is None:
            break
        out.append(cand.bits.tobytes())
    return out


# ----------------------- Helper Function to Extract seedpk and y from the Public Key -------------------------
def extract_seedpk_and_y(oracle: MPCitHOracle, public_key: bytes) -> tuple[bytes, bytes]:
    # Prefer explicit oracle methods when available.
    if hasattr(oracle, "get_seedpk") and hasattr(oracle, "get_y"):
        try:
            return oracle.get_seedpk(public_key), oracle.get_y(public_key)
        except Exception:
            pass

    # SDitH fallback: public_key = seedpk || y.
    if hasattr(oracle, "deserialize_public_key"):
        try:
            return oracle.deserialize_public_key(public_key)
        except Exception:
            pass

    lam = oracle.params["lambda_bytes"]
    return public_key[:lam], public_key[lam:]


# ----------------------- Helper Function to Load Noisy Seeds from File -------------------------
def load_noisy_seeds_from_file(file_path: str, seed_bytes: int) -> list[bytes]:
    """Load all noisy seeds from a per-beta file.

    Preferred format: one hex-encoded seed per line.
    Backward compatibility: if file has one long hex string, split by seed size.
    """
    with open(file_path, "r") as f:
        raw = f.read().strip()

    if not raw:
        return []

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    seeds = []

    if len(lines) > 1:
        for line in lines:
            seeds.append(bytes.fromhex(line))
        return seeds

    single = lines[0]
    hex_len = 2 * seed_bytes
    if len(single) == hex_len:
        return [bytes.fromhex(single)]

    if len(single) % hex_len != 0:
        raise ValueError("Noisy seed file has invalid length for seed chunking")

    for i in range(0, len(single), hex_len):
        seeds.append(bytes.fromhex(single[i : i + hex_len]))
    return seeds