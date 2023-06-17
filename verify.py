# Contains elements from verify. These are rewritten because constant time does not hold for python anyway.
from typing import List

def verify(a:List[int], b:List[int], l:int):
    return not all([i == j for i, j in zip(a, b)])


def cmov(r:List[int], x:List[int], l:int, b:int):
    if b == 1:
        for i in range(l):
            r[i] = x[i]
