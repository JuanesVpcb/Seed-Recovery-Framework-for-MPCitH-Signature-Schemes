import heapq
import math
import random

from abstract_oracle import MPCitHOracle

# ================================== Model-Agnostic Algorithms for Key Recovery ==================================
def introduce_noise(seed: bytes, alpha: float, beta: float) -> bytes:
    """Introduces noise to the seed based on the specified alpha and beta parameters.
    Each bit of every byte is independently flipped: 0->1 with probability alpha,
    1->0 with probability beta."""
    noisy_bytes = []
    for byte in seed:
        noisy_byte = 0
        for i in range(7, -1, -1): # iterate bits MSB to LSB
            bit = (byte >> i) & 1
            
            # Flip the bit according to the probabilities alpha and beta
            if bit == 0: noisy_bit = 1 if random.random() < alpha else 0
            else: noisy_bit = 0 if random.random() < beta else 1
            
            # Construct the noisy byte by shifting and adding the noisy bit
            noisy_byte = (noisy_byte << 1) | noisy_bit
        noisy_bytes.append(noisy_byte)
    return bytes(noisy_bytes)

# ----------------------- Helper Functions for BBLM-style Reconstruction from Noisy Seeds -----------------------
def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def _bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be a multiple of 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)

def _build_posteriors_from_noisy_bits(observed_bits: list[int], alpha: float, beta: float) -> list[tuple[float, float]]:
    posteriors = []
    for obs in observed_bits:
        if obs == 0:
            denom = (1.0 - alpha) + beta
            posteriors.append(((1.0 - alpha) / denom, beta / denom))
        else:
            denom = alpha + (1.0 - beta)
            posteriors.append((alpha / denom, (1.0 - beta) / denom))
    return posteriors

def _top_chunk_candidates(post_chunk: list[tuple[float, float]], mu: int) -> list[tuple[float, list[int]]]:
    w = len(post_chunk)
    all_candidates = []
    for mask in range(1 << w):
        bits = [((mask >> shift) & 1) for shift in range(w - 1, -1, -1)]
        neg_log_score = 0.0
        for idx, bit in enumerate(bits):
            p0, p1 = post_chunk[idx]
            prob = p1 if bit == 1 else p0
            neg_log_score += -math.log(prob)
        all_candidates.append((neg_log_score, bits))

    all_candidates.sort(key=lambda x: x[0])
    return all_candidates[:mu]

def ranked_seed_candidates_from_noisy(
    noisy_seed: bytes,
    alpha: float,
    beta: float,
    w: int,
    mu: int,
    max_candidates: int,
) -> list[bytes]:
    observed_bits = _bytes_to_bits(noisy_seed)
    if len(observed_bits) % w != 0:
        raise ValueError("w must divide the noisy seed bit-length")

    posteriors = _build_posteriors_from_noisy_bits(observed_bits, alpha, beta)
    chunk_lists = []
    for start in range(0, len(observed_bits), w):
        chunk_lists.append(_top_chunk_candidates(posteriors[start : start + w], mu))

    num_chunks = len(chunk_lists)
    start_indices = tuple(0 for _ in range(num_chunks))
    start_score = sum(chunk_lists[i][0][0] for i in range(num_chunks))
    heap: list[tuple[float, tuple[int, ...]]] = [(start_score, start_indices)]
    visited = {start_indices}

    out = []
    while heap and len(out) < max_candidates:
        score, indices = heapq.heappop(heap)

        candidate_bits = []
        for chunk_id, cand_idx in enumerate(indices):
            candidate_bits.extend(chunk_lists[chunk_id][cand_idx][1])
        out.append(_bits_to_bytes(candidate_bits))

        for chunk_id in range(num_chunks):
            next_idx = indices[chunk_id] + 1
            if next_idx >= len(chunk_lists[chunk_id]):
                continue
            new_indices = list(indices)
            new_indices[chunk_id] = next_idx
            new_indices_t = tuple(new_indices)
            if new_indices_t in visited:
                continue

            next_score = score
            next_score -= chunk_lists[chunk_id][indices[chunk_id]][0]
            next_score += chunk_lists[chunk_id][next_idx][0]

            visited.add(new_indices_t)
            heapq.heappush(heap, (next_score, new_indices_t))

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