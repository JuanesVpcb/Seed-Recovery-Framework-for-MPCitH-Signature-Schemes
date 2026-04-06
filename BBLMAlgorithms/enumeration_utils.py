from typing import List
from BBLMAlgorithms.candidate import ChunkCandidate
from bitarray import bitarray

def combine(candidates: List[ChunkCandidate]) -> ChunkCandidate:
    total_score = sum(c.score for c in candidates)
    combined_bits = bitarray()
    for c in candidates:
        combined_bits.extend(c.bits)
    return ChunkCandidate(total_score, combined_bits)

