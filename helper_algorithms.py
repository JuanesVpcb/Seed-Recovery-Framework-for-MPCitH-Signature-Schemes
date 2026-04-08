import os
import random
import math

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

def _beam_combine_blocks(blocks, max_candidates: int, per_block_cap: int | None = None) -> list[bytes]:
    """Combine per-block candidates with bounded memory using beam search.

    blocks: list[list[ChunkCandidate]] from generate_candidates_trimmed.
    max_candidates: final top-K to return.
    per_block_cap: optional cap per block before combining.
    """
    _ensure_bblm_modules_loaded()
    k = max(1, int(max_candidates))
    if not blocks:
        return []

    # Heuristic: keep block fanout small enough to avoid quadratic blow-ups.
    if per_block_cap is None: per_block_cap = max(4, min(32, int(math.sqrt(k)) + 1))

    beam: list[tuple[float, bitarray]] = [(0.0, bitarray())]
    for block in blocks:
        if not block: continue
        local = block[:per_block_cap]
        next_beam: list[tuple[float, bitarray]] = []

        for prefix_score, prefix_bits in beam:
            for cand in local:
                bits = prefix_bits.copy()
                bits.extend(cand.bits)
                next_beam.append((prefix_score + cand.score, bits))

        # Lower score is better; keep only top-k partial candidates.
        next_beam.sort(key=lambda x: x[0])
        beam = next_beam[:k]

    return [bits.tobytes() for _, bits in beam[:k]]

def _lightweight_ranked_candidates(
    noisy_seed: bytes,
    alpha: float,
    beta: float,
    max_candidates: int,
) -> list[bytes]:
    """Memory-safe fallback candidate generator.

    Builds a small ranked list around the noisy seed by flipping the most
    uncertain bits first. This avoids OKEA tree construction.
    """
    _ensure_bblm_modules_loaded()
    bits = bitarray()
    bits.frombytes(noisy_seed)
    nbits = len(noisy_seed) * 8
    bits = bits[:nbits]

    limit = max(1, int(max_candidates))
    out: list[bytes] = [bits.tobytes()]
    if limit == 1 or nbits == 0:
        return out

    # Channel-based confidence for each observed bit.
    denom_1 = (1.0 - beta) + alpha + 1e-12
    denom_0 = (1.0 - alpha) + beta + 1e-12
    uncertainty = []
    for i, b in enumerate(bits):
        conf = ((1.0 - beta) / denom_1) if b else ((1.0 - alpha) / denom_0)
        uncertainty.append((1.0 - conf, i))
    uncertainty.sort(reverse=True)

    # Single-bit flips first.
    top_single = min(len(uncertainty), limit - 1, 256)
    top_idx = [idx for _, idx in uncertainty[:top_single]]
    for idx in top_idx:
        candidate = bitarray(bits)
        candidate[idx] = not candidate[idx]
        out.append(candidate.tobytes())
        if len(out) >= limit:
            return out

    # Then two-bit flips over the most uncertain subset.
    pair_pool = top_idx[:32]
    for i in range(len(pair_pool)):
        for j in range(i + 1, len(pair_pool)):
            candidate = bitarray(bits)
            a = pair_pool[i]
            b = pair_pool[j]
            candidate[a] = not candidate[a]
            candidate[b] = not candidate[b]
            out.append(candidate.tobytes())
            if len(out) >= limit:
                return out

    return out

# ----------------------- Connector Function for BBLM-style Reconstruction from Noisy Seeds -----------------------
def ranked_seed_candidates_from_noisy(
    noisy_seed: bytes,
    alpha: float,
    beta: float,
    w: int,
    mu: int,
    eta: int,
    max_candidates: int,
    mode: str = "lightweight",
) -> list[bytes]:
    _ensure_bblm_modules_loaded()
    observed_bits = bitarray()
    observed_bits.frombytes(noisy_seed)
    observed_bits = observed_bits[: len(noisy_seed) * 8]
    W = len(observed_bits)

    if W % w != 0:
        raise ValueError("w must divide the noisy seed bit-length")

    if mode == "lightweight":
        return _lightweight_ranked_candidates(noisy_seed, alpha, beta, max_candidates)

    if mode not in ("lightweight", "okea", "beam"):
        raise ValueError("mode must be one of: lightweight, okea, beam")

    # Memory-aware backoff: OKEA construction can overflow or be killed if the
    # candidate space is too large. Try progressively lighter settings.

    P = build_posteriors_from_tilde(observed_bits, alpha, beta)
    chunk_lists = generate_candidates_trimmed(P, W, w, eta, mu)
    if not chunk_lists: return []

    if mode == "beam":
        return _beam_combine_blocks(chunk_lists, max_candidates, mu)

    out = []
    try:
        okea_tree = initialize(chunk_lists, 0, len(chunk_lists) - 1)
        for j in range(max_candidates):
            cand = okea_tree.getCandidate(j)
            if cand is None:
                break
            out.append(cand.bits.tobytes())
    except (OverflowError, MemoryError):
        # If full OKEA blows up, fallback to beam combiner.
        return _beam_combine_blocks(chunk_lists, max_candidates, mu)

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