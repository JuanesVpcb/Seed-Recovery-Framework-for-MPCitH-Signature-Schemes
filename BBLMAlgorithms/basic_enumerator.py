import heapq
from typing import List, Optional
from BBLMAlgorithms.candidate import ChunkCandidate
from BBLMAlgorithms.enumeration_utils import combine
from BBLMAlgorithms.extended_candidate import ExtendedCandidate

class BasicKeyEnumerator:
    def __init__(self, L0: List[ChunkCandidate], L1: List[ChunkCandidate], scale: float = 10000.0):
        """
        Implements the Basic Algorithm (Algorithm 1 from the thesis) using ExtendedCandidate.
        L0 and L1 must be sorted in decreasing score order.
        """
        self.L0 = L0
        self.L1 = L1
        self.X = [0] * len(L0)
        self.Y = [0] * len(L1)
        self.Q = []
        self.scale = scale
        self._init_queue()

    def _init_queue(self):
        j0, j1 = 0, 0
        c0, c1 = self.L0[j0], self.L1[j1]
        ec = ExtendedCandidate(c0, c1, j0, j1)
        weight = -(c0.to_weight(self.scale) + c1.to_weight(self.scale))  # max-heap
        heapq.heappush(self.Q, (weight, ec))
        self.X[j0] = 1
        self.Y[j1] = 1

    def next_candidate(self) -> Optional[ChunkCandidate]:
        if not self.Q:
            return None

        _, ec = heapq.heappop(self.Q)
        j0, j1 = ec.j0, ec.j1
        c0, c1 = ec.c0, ec.c1

        self.X[j0] = 0
        self.Y[j1] = 0

        # Insert (j0+1, j1)
        if j0 + 1 < len(self.L0) and self.X[j0 + 1] == 0:
            new_c0 = self.L0[j0 + 1]
            new_ec = ExtendedCandidate(new_c0, c1, j0 + 1, j1)
            weight = -(new_c0.to_weight(self.scale) + c1.to_weight(self.scale))
            heapq.heappush(self.Q, (weight, new_ec))
            self.X[j0 + 1] = 1
            self.Y[j1] = 1

        # Insert (j0, j1+1)
        if j1 + 1 < len(self.L1) and self.Y[j1 + 1] == 0:
            new_c1 = self.L1[j1 + 1]
            new_ec = ExtendedCandidate(c0, new_c1, j0, j1 + 1)
            weight = -(c0.to_weight(self.scale) + new_c1.to_weight(self.scale))
            heapq.heappush(self.Q, (weight, new_ec))
            self.X[j0] = 1
            self.Y[j1 + 1] = 1

        return ec.combine()



