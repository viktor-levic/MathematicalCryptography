import numpy as np


class State:
    def __init__(self, initial_val: np.ndarray):
        self.state = initial_val
        assert len(initial_val) == 8 and len(set(len(i) for i in initial_val)) == 1

    def addColumnMod(self, col, col_id, m=2):
        for i in range(len(self)):
            v = self[i][col_id]
            self[i][col_id] = (v + col[i]) % m

    def shiftRows(self, row_id: int, shift_n: int):
        self[row_id] = np.roll(self[row_id], shift_n)

    def __getitem__(self, *a, **kw):
        return self.state.__getitem__(*a, **kw)

    def __len__(self):
        return self.state.__len__()

    def __setitem__(self, key, value):
        return self.state.__setitem__(key, value)
