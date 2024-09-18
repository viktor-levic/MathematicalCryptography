from collections import deque
from .modes import *


class _GFPoly:
    """
    Елементи поля Галуа GF(2^8).
    """

    # Aes polynomial: x^8 + x^4 + x^3 + x + 1
    _modulo = 0x011b

    def __init__(self, digit_value: int):
        self.val = digit_value

    def __add__(self, other):
        """ Додавання це XOR.
        """
        return _GFPoly(self.val ^ other.val)

    def __mul__(self, other):
        """ Достатньо реалізувати множення на x і
        тоді просто помножте себе на інше, як моном на поліном.


        Множення на x — це просто зсув на одну позицію ліворуч.
        0x09 <-> x^7 + x^4 + x^3 + x + 1  |=*x=>   x^8 + x^5 + x^4 + x^2 + x <-> 0x136/

        Якщо результат отримує 8-й ступінь, ми просто виконуємо XOR за допомогою _modulo, наприклад:
        x^8 + x^5 + x^4 + x^2 + x  |=XOR _mod=> x^5 + x^3 + x^2 + 1
        """
        if isinstance(other, int):
            other = _GFPoly(other)
        res_val = 0
        for i in range(8):    # проходить всі ступені чужого полі
            if (1 << i) & other.val:   # перевіряє чи і-тий біт є нулем
                tmp = self.val         # (те саме, що i-й ступінь існує)
                for j in range(i):     # множимо i раз на x
                    tmp = tmp << 1
                    if tmp >= 256:     #по модулю, якщо це необхідно
                        tmp = tmp ^ _GFPoly._modulo
                res_val ^= tmp     # додаємо і-тий результат до загального результату
        return _GFPoly(res_val)

    def __pow__(self, n):
        """ Двійкове піднесення до степеня елемента.
        Якщо n дорівнює -1 - це означає, що нам потрібно знайти зворотний елемент.

        GF(2^8) має 256 елементів, отже, його мультиплікативна група має 255 елементів.
        Тобто, використовуючи теорему про порядок елементів, x ^ 255 == 1 для
        кожного x із GF(2^8),таким чином x ^ 254 == x ^ (-1).
        """
        if n == -1:
            n = 254
        res = _GFPoly(1)
        a = _GFPoly(self.val)
        while n > 0:          # двійкове підвищення
            if n & 1:
                res *= a
            a *= a
            n >>= 1
        return res

    def __rmul__(self, other):
        if isinstance(other, int):
            return _GFPoly(other) + self

    def __str__(self):
        return f"GFPoly({self.val})"

    def __repr__(self):
        return str(self)


class _GFFourTermPoly:
    """
    Елементи GF(2^8)[x] / (x^4 + 1).
    Вони виглядають як поліноми a0 + a1 x + a2 x^2 + a3 x^3, де
    ai походить від GF(2^8), тобто це просто масив із 4 байтів.
    """

    def __init__(self, *args):
        assert len(args) == 4

        self.val = []
        for el in args:
            if isinstance(el, int):
                self.val.append(_GFPoly(el))
            elif isinstance(el, _GFPoly):
                self.val.append(el)
            else:
                raise TypeError(f"Поганий тип для чотирьох членів poly: {type(el)}")

    def __mul__(self, other):
        """ Множення визначається як множення на матрицю
        A = [[b0, b3, b2, b1],
             [b1, b0, b3, b2],
             [b2, b1, b0, b3],
             [b3, b2, b1, b0]],  де bi відповідає
                                 коефіцієнт від інших поліномів.
        """
        tmp = deque([0, 3, 2, 1])
        res = [0, 0, 0, 0]
        for i in range(4):
            res[i] = _GFPoly(0)
            for j in range(4):
                res[i] += self.val[tmp[j]] * other.val[j]
            tmp.rotate(1)
        return _GFFourTermPoly(*res)

    def __str__(self):
        return f"GFFourTermPoly({self.val})"

    def __repr__(self):
        return str(self)

# ======================= AES128 functions =====================================

def _rotate_left(n, amount):
    tmp = n << amount
    tmp_right = tmp & 255
    tmp_left = tmp & ((1 << 16) - 256)
    tmp_left >>= 8
    return tmp_left | tmp_right


def _sub_byte(state):

    if isinstance(state, _GFPoly):
        res = (state ** -1).val
    else:
        res = (_GFPoly(state) ** -1).val
    res = res ^ _rotate_left(res, 4) ^ _rotate_left(res, 3) \
          ^ _rotate_left(res, 2) ^ _rotate_left(res, 1) ^ 0x63
    return res


def _inv_sub_byte(state):
    if isinstance(state, _GFPoly):
        state = state.val
    res = _rotate_left(state, 1) ^ \
          _rotate_left(state, 3) ^ _rotate_left(state, 6) ^ 0x5
    return (_GFPoly(res) ** -1).val


# просто створимо власні S_BOX і INV_S_BOX
_S_BOX = tuple([_sub_byte(i) for i in range(256)])
_INV_S_BOX = tuple([_inv_sub_byte(i) for i in range(256)])


def _subBytes(state_matrix):
    res = [[_S_BOX[state_matrix[i][j]] for j in range(len(state_matrix[0]))]
            for i in range(len(state_matrix))]
    return res


def _invSubBytes(state_matrix):
    res = [[_INV_S_BOX[state_matrix[i][j]] for j in range(len(state_matrix[0]))]
            for i in range(len(state_matrix))]
    return res


def _shiftRows(state_matrix):
    res = [state_matrix[i][i:] + state_matrix[i][:i] for i in range(len(state_matrix))]
    return res


def _invShiftRows(state_matrix):
    res = [state_matrix[i][4-i:] + state_matrix[i][:4-i] for i in range(len(state_matrix))]
    return res


def _mixColumns(state_matrix):
    a = _GFFourTermPoly(0x02, 0x01, 0x01, 0x03)
    transposed = [[state_matrix[i][j] for i in range(len(state_matrix))]
                     for j in range(len(state_matrix[0]))]
    res = [(_GFFourTermPoly(*el) * a).val for el in transposed]
    return [[res[i][j].val for i in range(len(res))] for j in range(len(res[0]))]


def _invMixColumns(state_matrix):
    inv_a = _GFFourTermPoly(0x0e, 0x09, 0x0d, 0x0b)
    transposed = [[state_matrix[i][j] for i in range(len(state_matrix))]
                     for j in range(len(state_matrix[0]))]
    res = [(_GFFourTermPoly(*el) * inv_a).val for el in transposed]
    return [[res[i][j].val for i in range(len(res))] for j in range(len(res[0]))]


def _keyExpansion(key):
    assert len(key) == 16
    res_keys = [key[i:(i+4)] for i in range(0, 16, 4)]
    res_keys += [0] * (10 * len(res_keys))
    for i in range(10):
        tmp = res_keys[4*i + 3]

        tmp = tmp[1:] + tmp[:1]

        tmp = [_S_BOX[el] for el in tmp]

        tmp[0] ^= (_GFPoly(0x02) ** i).val
        res_keys[4*i + 4] = [x ^ y for x, y in zip(tmp, res_keys[4*i])]
        res_keys[4*i + 5] = [x ^ y for x, y in zip(res_keys[4*i + 4], res_keys[4*i + 1])]
        res_keys[4*i + 6] = [x ^ y for x, y in zip(res_keys[4*i + 5], res_keys[4*i + 2])]
        res_keys[4*i + 7] = [x ^ y for x, y in zip(res_keys[4*i + 6], res_keys[4*i + 3])]
    return res_keys


def _addRoundKey(state_matrix, key):
    transposed = [[state_matrix[i][j] for i in range(len(state_matrix))]
                     for j in range(len(state_matrix[0]))]
    res = [[x ^ y for x, y in zip(el_mat, el_key)] for el_mat, el_key in zip(transposed, key)]
    return [[res[i][j] for i in range(len(res))] for j in range(len(res[0]))]


def _encrypt(in_block, key, printt=False):
    in_block = list(in_block)
    key = list(key)

    if printt:                # для дебагу :)
        print(f'\n[*] Encrypting...')

    keys = _keyExpansion(key)
    state = [[in_block[r + 4*c] for c in range(4)] for r in range(4)]

    if printt:
        print(f'Initial state: {state}')

    state = _addRoundKey(state, keys[:4])

    for i in range(1, 10):
        state = _subBytes(state)
        state = _shiftRows(state)
        state = _mixColumns(state)
        state = _addRoundKey(state, keys[4 * i: 4 * i + 4])

        if printt:
            print(f'Round: {i}, state: {state}')

    state = _subBytes(state)
    state = _shiftRows(state)
    state = _addRoundKey(state, keys[10 * 4:])

    if printt:
        print(f'Result state: {state}')
    return [state[i][j] for j in range(len(state[0])) for i in range(len(state))]


def _decrypt(out_block, key, printt=False):
    out_block = list(out_block)
    key = list(key)

    if printt:
        print(f'\n[*] Декриптування...')

    keys = _keyExpansion(key)
    state = [[out_block[r + 4*c] for c in range(4)] for r in range(4)]
    if printt:
        print(f'Початковий стан: {state}')

    state = _addRoundKey(state, keys[10 * 4:])
    for i in range(9, 0, -1):
        state = _invShiftRows(state)
        state = _invSubBytes(state)

        if printt:
            print(f'Раунд: {i}, стан: {state}')
        state = _addRoundKey(state, keys[4 * i: 4 * i + 4])
        state = _invMixColumns(state)

    state = _invShiftRows(state)
    state = _invSubBytes(state)
    state = _addRoundKey(state, keys[0:4])

    if printt:
        print(f"Кінцевий стан: {state}")
    return [state[i][j] for j in range(len(state[0])) for i in range(len(state))]

# ======================= end of AES128 functions ==============================

class _AES_cipher:
    """ Клас, який представляє шифр AES із вибраним режимом шифрування
    блокові шифри. Структура цього класу схожа на Crypto.Cipher.AES
    (або принаймні має бути схожа)

    :param key:  будь-які 16 байт. Викидає виняток, якщо ключ має недійсну довжину
    :param mode: один із режимів із aes.modes (MODE_CBC, MODE_ECB, MODE_CTR)
    :param IV:   вектор ініціалізації, необхідний MODE_ECB і MODE_CTR.
                 якщо IV дорівнює None, його буде вибрано випадковим чином.
                 марно лише для режиму дешифрування
    """

    def __init__(self, key, mode=MODE_ECB, IV=None):
        self.key = key
        self._encrypt, self._decrypt, self.IV = mode(_encrypt, _decrypt, IV)

    def encrypt(self, message) -> bytes:
        return self._encrypt(message, self.key)

    def decrypt(self, message) -> bytes:
        return self._decrypt(message, self.key)


def new(key, mode=MODE_ECB, IV=None) -> _AES_cipher:
    """ Створимо новий шифр AES із заданим режимом.

    :param key:  будь-які 16 байт. Викидає виняток, якщо ключ має недійсну довжину
    :param mode: один із режимів із aes.modes (MODE_CBC, MODE_ECB, MODE_CTR)
    :param IV:   вектор ініціалізації, необхідний MODE_ECB і MODE_CTR.
                 якщо IV дорівнює None, його буде вибрано випадковим чином.
                 марно лише для режиму дешифрування
    :return: _AES_cipher об'єкт
    """
    return _AES_cipher(key, mode, IV)
