import random
from bitarray import bitarray
from BBLMAlgorithms.candidate import ChunkCandidate

def random_chunk_candidates(n: int, w: int):
    """Generate n random candidates with w-bit values."""
    return sorted([
        ChunkCandidate(
            score=random.uniform(0, 1),
            bits=bitarray(bin(random.getrandbits(w))[2:].zfill(w))
        )
        for _ in range(n)
    ], key=lambda c: -c.score)

def initialize(chunk_lists, i, f, scale=10000.0):
    """Recursively build an OKEA tree from chunk_lists[i] to chunk_lists[f]."""
    if i == f:
        return OKEANode(
            left=None,
            right=None,
            Q=[],
            X=bitarray(),  # Not used in leaves
            Y=bitarray(),
            L=chunk_lists[i],
            scale=scale
        )

    q = (i + f) // 2
    left = initialize(chunk_lists, i, q, scale)
    right = initialize(chunk_lists, q + 1, f, scale)
    

    X = bitarray(left.size())
    X.setall(0)
    Y = bitarray(right.size())
    Y.setall(0)
    
    c0=left.getCandidate(0)
    c1=right.getCandidate(0)
    ec = ExtendedCandidate(c0, c1, 0, 0, scale)

    Q=[]
    heapq.heappush(Q, (-ec.weight, ec))
    X[0] = 1
    Y[0] = 1

    return OKEANode(
        left=left,
        right=right,
        Q=Q,
        X=X,
        Y=Y,
        L=[],
        scale=scale
    )


import heapq
from typing import List, Optional
from bitarray import bitarray
from BBLMAlgorithms.candidate import ChunkCandidate
from BBLMAlgorithms.enumeration_utils import combine
from BBLMAlgorithms.extended_candidate import ExtendedCandidate

class OKEANode:
    def __init__(self,
                 left: Optional["OKEANode"],
                 right: Optional["OKEANode"],
                 Q: List,
                 X: bitarray,
                 Y: bitarray,
                 L: List[ChunkCandidate],
                 scale: float = 10000.0):
        self.left = left
        self.right = right
        self.Q = Q
        self.X = X
        self.Y = Y
        self.L = L
        self.scale = scale
        self.is_leaf = left is None and right is None
        self.enumerated = 0
        self.computed_size= None

    def size(self) -> int:
       
        if self.computed_size is None:
           if self.is_leaf:
              self.computed_size=len(self.L)
           else:
              self.computed_size=self.left.size() * self.right.size()
     
        return self.computed_size

    def getCandidate(self, j: int) -> Optional[ChunkCandidate]:
        if self.is_leaf:
            return self.L[j] if j < len(self.L) else None
        while len(self.L) <= j:
            next_cand = self.next_candidate()
            if next_cand is None:
                return None
            else:
                self.L.append(next_cand)

        return self.L[j]

    def next_candidate(self) -> Optional[ChunkCandidate]:
        if not self.Q:
           return None
        
        _, ec = heapq.heappop(self.Q)
        j0, j1 = ec.j0, ec.j1
        self.X[j0] = 0
        self.Y[j1] = 0
        full_cand = ec.combine()
        
        if (j0 + 1 < self.left.size()) and (self.X[j0 + 1] == 0):
            c0_new = self.left.getCandidate(j0 + 1)
            new_ec = ExtendedCandidate(c0_new, ec.c1, j0 + 1, j1, scale=self.scale)
            heapq.heappush(self.Q, (-new_ec.weight, new_ec))
            self.X[j0 + 1] = 1
            self.Y[j1] = 1
        if (j1 + 1 < self.right.size()) and (self.Y[j1 + 1] == 0):
            c1_new = self.right.getCandidate(j1 + 1)
            new_ec = ExtendedCandidate(ec.c0, c1_new, j0, j1 + 1, scale=self.scale)
            heapq.heappush(self.Q, (-new_ec.weight, new_ec))
            self.X[j0] = 1
            self.Y[j1 + 1] = 1
        return full_cand
