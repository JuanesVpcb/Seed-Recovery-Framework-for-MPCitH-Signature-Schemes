from bitarray import bitarray

class ChunkCandidate:
    def __init__(self, score: float, bits: bitarray):
        self.score = score
        self.bits = bits

    def __len__(self):
        return len(self.bits)

    def __lt__(self, other):
        return self.score < other.score

    def __repr__(self):
        return (f"ChunkCandidate(score={self.score:.4f}, "
                f"weight={self.to_weight()}, "
                f"bits={self.bits.to01()})")

    def copy(self):
        return ChunkCandidate(self.score, self.bits.copy())

    def to_weight(self, scale: float = 10000.0) -> int:
        """
        Converts the score of this candidate into a positive integer weight.
        Args:
            scale (float): Scaling factor to preserve resolution.
        Returns:
            int: Integer weight.
        """
        if self.score < 0:
            raise ValueError("Score must be non-negative")
        return int(round(self.score * scale))



