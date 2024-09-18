import math
import random
import sys

from sympy import primerange


class ByteIter:
    def __init__(self, length=5):
        self.len = length
        self.iterations = -1
        self.last_value = 0
        self.primes = list(primerange(3, 4000))
        self.max_value = pow(256, length)
        self.a = random.choice(self.primes)
        self.b = random.randint(100, 10000) + int(math.sqrt(self.max_value))
        # self.prev_=set()

    def __iter__(self):
        return self

    def __next__(self):
        self.iterations += 1
        if self.iterations >= self.max_value:
            raise StopIteration
        self.last_value = (-self.a * self.last_value + self.b) % self.max_value
        return self.last_value.to_bytes(self.len, sys.byteorder)
