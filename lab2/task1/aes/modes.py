""" Операції в режимах блокового шифрування.

Кожен режим є функцією, яка має шаблон

mode(<block_encrypt>, <block_decrypt>, <IV>)
            -> <stream_encrypt>, <stream_decryp>, <IV>
"""

import warnings
from Crypto.Random import get_random_bytes
from typing import Callable


# ============================ CBC MODE ========================================
def MODE_ECB(sym_cipher_enc_func: Callable[[bytes, bytes], list],
             sym_cipher_dec_func: Callable[[bytes, bytes], list],
             IV: bytes):
    """ Режим шифрування електронної кодової книги для блокових шифрів.

    :param sym_cipher_enc_func: функція, яка отримує 16-байтовий блок відкритого тексту
                                з 16-байтовим ключем і повертає 16-байтовий зашифрований текст
    :param sym_cipher_dec_func: функція, яка отримує 16-байтовий блоковий зашифрований текст
                                з 16-байтовим ключем і повертає 16-байтовий відкритий текст
    :param IV: тут непотрібен , лише для формату гарного темплейту
    :return: <stream_encrypt_func>, <stream_decrypt_func>, None
    """

    if IV is not None:
        warnings.warn("ECB мод не вимагає потребує ініціалізації!", Warning)

    def ecb_encrypt(message: bytes, key: bytes):
        if len(message) % 16:
            raise ValueError(f"Помилкова довжина повідомлення: {len(message)}. Використовуйте відступи.")
        blocks = [message[i: i + 16] for i in range(0, len(message), 16)]
        res = b''
        for block in blocks:
            res += bytes(sym_cipher_enc_func(block, key))
        return res

    def ecb_decrypt(ciphertext: bytes, key: bytes):
        if len(ciphertext) % 16:
            raise ValueError(f"Помилкова довжина зашифрованого тексту: {len(ciphertext)}.")
        blocks = [ciphertext[i: i+16] for i in range(0, len(ciphertext), 16)]
        res = b''
        for block in blocks:
            res += bytes(sym_cipher_dec_func(block, key))
        return res

    return ecb_encrypt, ecb_decrypt, None


# ============================ CBC MODE ========================================
def MODE_CBC(sym_cipher_enc_func: Callable[[bytes, bytes], list],
             sym_cipher_dec_func: Callable[[bytes, bytes], list],
             IV: bytes):
    """ Режим ланцюжка блоків шифру.

    :param sym_cipher_enc_func: функція, яка отримує 16-байтовий блок відкритого тексту
                                з 16-байтовим ключем і повертає 16-байтовий зашифрований текст
    :param sym_cipher_dec_func: функція, яка отримує 16-байтовий блоковий зашифрований текст
                                з 16-байтовим ключем і повертає 16-байтовий відкритий текст
    :param IV: вектор ініціалізації. Має бути 16-байтовий блок.
               якщо значення None, IV буде вибрано випадковим чином і повернено абоненту.
    :return: <stream_encrypt_func>, <stream_decrypt_func>, IV
    """
    if IV is None:
        IV = get_random_bytes(16)

    if not isinstance(IV, bytes) or len(IV) != 16:
        raise ValueError(f"Невірний вектор ініціалізації для CBC моду: {IV}")

    def cbc_encrypt(message: bytes, key: bytes):
        if len(message) % 16:
            raise ValueError(f"Помилкова довжина повідомлення: {len(message)}. Використовуйте відступи.")

        assert len(IV) == 16
        res = IV
        prev_block = list(IV)

        blocks = [message[i: i + 16] for i in range(0, len(message), 16)]
        for block in blocks:
            block = bytes([x ^ y for x, y in zip(prev_block, block)])
            block = sym_cipher_enc_func(block, key)
            res += bytes(block)
            prev_block = block
        return res

    def cbc_decrypt(ciphertext: bytes, key: bytes):
        if len(ciphertext) % 16:
            raise ValueError(f"Помилкова довжина зашифрованого тексту: {len(ciphertext)}.")
        res = b''
        blocks = [ciphertext[i: i + 16] for i in range(0, len(ciphertext), 16)]
        for i in range(len(blocks) - 1, 0, -1):
            mi = sym_cipher_dec_func(blocks[i], key)
            mi = [x ^ y for x, y in zip(mi, blocks[i - 1])]
            res = bytes(mi) + res
        return res

    return cbc_encrypt, cbc_decrypt, IV


# ============================ CTR MODE ========================================
def MODE_CTR(sym_cipher_enc_func: Callable[[bytes, bytes], list],
             sym_cipher_dec_func: Callable[[bytes, bytes], list],
             IV: bytes):
    """ Counter мод.

    :param sym_cipher_enc_func: функція, яка отримує 16-байтовий блок відкритого тексту
                                з 16-байтовим ключем і повертає 16-байтовий зашифрований текст
    :param sym_cipher_dec_func: потрібне тільки для гарного темплейту

    :param IV: вектор ініціалізації - nonce для лічильника. Має бути 8-байтовий блок.
           якщо значення None, IV буде вибрано випадковим чином і повернено абоненту.
    :return: <stream_encrypt_func>, <stream_decrypt_func>, IV
    """
    if IV is None:
        IV = get_random_bytes(8)

    if not isinstance(IV, bytes) or len(IV) != 8:
        raise ValueError(f"Невірний вектор ініціалізації для CTR мо: {IV}")

    def ctr_encrypt(message: bytes, key: bytes):
        if len(message) % 16:
            raise ValueError(f"Помилкова довжина повідомлення: {len(message)}. Використовуйте відступи.")

        res = IV
        blocks = [message[i: i + 16] for i in range(0, len(message), 16)]
        for i in range(len(blocks)):
            block = blocks[i]
            hex_i = hex(i)[2:]
            cur_count = IV.hex() + '0' * (16 - len(hex_i)) + hex_i
            cur_count = bytes.fromhex(cur_count)
            salt = sym_cipher_enc_func(cur_count, key)
            res += bytes([x ^ y for x, y in zip(salt, block)])
        return res

    def ctr_decrypt(ciphertext: bytes, key: bytes):
        if len(ciphertext) % 16 != 8:
            raise ValueError(f"Помилкова довжина зашифрованого тексту: {len(ciphertext)}.")

        nonce = ciphertext[:8]
        blocks = [ciphertext[i: i + 16] for i in range(8, len(ciphertext), 16)]
        res = b''

        for i in range(len(blocks)):
            block = blocks[i]

            hex_i = hex(i)[2:]
            cur_count = nonce.hex() + '0' * (16 - len(hex_i)) + hex_i
            cur_count = bytes.fromhex(cur_count)
            salt = sym_cipher_enc_func(cur_count, key)
            res += bytes([x ^ y for x, y in zip(salt, block)])
        return res

    return ctr_encrypt, ctr_decrypt, IV
