from BBLMAlgorithms.candidate import ChunkCandidate
from BBLMAlgorithms.enumeration_utils import combine

class ExtendedCandidate:
    def __init__(self, c0: ChunkCandidate, c1: ChunkCandidate, j0: int, j1: int, scale: float = 10000.0):
        """
        Represents an extended candidate (c0, c1, j0, j1), with both score and integer weight.
        
        Args:
            c0 (ChunkCandidate): Candidate from left subtree
            c1 (ChunkCandidate): Candidate from right subtree
            j0 (int): Index in left subtree
            j1 (int): Index in right subtree
            scale (float): Scaling factor for converting scores to integer weights
        """
        self.c0 = c0
        self.c1 = c1
        self.j0 = j0
        self.j1 = j1
        self.scale = scale

        self.score = c0.score + c1.score
        self.weight = c0.to_weight(scale) + c1.to_weight(scale)

    def combine(self) -> ChunkCandidate:
        """
        Combines c0 and c1 into a full candidate (bit concatenation + score addition).
        Returns:
            ChunkCandidate
        """
        return combine([self.c0, self.c1])

    def __lt__(self, other):
        """
        Tie-breaker for heapq when two weights are equal.
        Comparison based on position indices (j0, j1).
        """
        return (self.j0, self.j1) < (other.j0, other.j1)

    def __repr__(self):
        return (f"ExtendedCandidate(j0={self.j0}, j1={self.j1}, "
                f"weight={self.weight}, score={self.score:.4f}, "
                f"bits={self.c0.bits.to01()}||{self.c1.bits.to01()})")



