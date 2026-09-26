"""The two block ciphers SNMPv3 needs, in Python, with no dependencies.

SNMPv3's privacy protocols are AES-CFB128 and CBC-DES. `hashlib` and `hmac` cover the
authentication half; encryption is the one piece the standard library does not have, and
it is a few hundred lines of block cipher rather than a dependency with a build step —
which matters, because this tool is meant to be dropped onto a switch-closet server with
a system Python and no package index.

Both ciphers are checked against published vectors in the test suite (FIPS-197 for AES,
the classic NBS vector for DES) and cross-checked against `openssl` where it is
installed. Speed is not a concern and never was: one SNMP privacy key encrypts a scoped
PDU of a few hundred bytes, a few times a minute.

DES lives here only because Cisco gear defaults to `des` in configs written years ago,
and a monitoring tool that cannot talk to that gear does not get installed. Prefer AES
on anything offering it.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

__all__ = ["CipherError", "aes_encrypt_block", "aes_cfb128", "aes_cfb128_decrypt",
           "des_encrypt_block", "des_cbc_encrypt", "des_cbc_decrypt", "xor_bytes"]


class CipherError(ValueError):
    """A key or payload that cannot be used with the cipher that was asked for."""


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


# ------------------------------------------------------------------------------ AES


def _aes_sbox() -> List[int]:
    """The S-box, computed rather than transcribed.

    A 256-entry table typed by hand is a typo waiting to happen; the construction
    (multiplicative inverse in GF(2^8), then the affine transform) is short enough to
    write down, and the tests pin the first bytes against the published table.
    """
    def multiply(a: int, b: int) -> int:
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            high = a & 0x80
            a = ((a << 1) & 0xFF) ^ (0x1B if high else 0)
            b >>= 1
        return result

    inverse = [0] * 256
    for value in range(1, 256):
        for candidate in range(1, 256):
            if multiply(value, candidate) == 1:
                inverse[value] = candidate
                break

    table: List[int] = []
    for byte in range(256):
        inv = inverse[byte]
        bits = [(inv >> i) & 1 for i in range(8)]
        out = [(bits[i] ^ bits[(i + 4) % 8] ^ bits[(i + 5) % 8] ^ bits[(i + 6) % 8]
                ^ bits[(i + 7) % 8] ^ ((0x63 >> i) & 1)) & 1 for i in range(8)]
        table.append(sum(bit << i for i, bit in enumerate(out)))
    return table


AES_SBOX = _aes_sbox()
AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8,
            0xAB, 0x4D]


def _aes_round_keys(key: bytes) -> List[List[int]]:
    """Key expansion, FIPS-197 §5.2, for 128, 192 and 256-bit keys."""
    if len(key) not in (16, 24, 32):
        raise CipherError("AES needs a 16, 24 or 32 byte key, not %d" % len(key))
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for index in range(nk, 4 * (rounds + 1)):
        temp = list(words[index - 1])
        if index % nk == 0:
            temp = [AES_SBOX[temp[1]], AES_SBOX[temp[2]], AES_SBOX[temp[3]],
                    AES_SBOX[temp[0]]]
            temp[0] ^= AES_RCON[index // nk - 1]
        elif nk > 6 and index % nk == 4:
            temp = [AES_SBOX[value] for value in temp]
        words.append([words[index - nk][i] ^ temp[i] for i in range(4)])
    return [sum((words[4 * r + c] for c in range(4)), []) for r in range(rounds + 1)]


def _aes_shift_rows(state: List[int]) -> List[int]:
    out = list(state)
    for row in range(4):
        for column in range(4):
            out[4 * column + row] = state[4 * ((column + row) % 4) + row]
    return out


def _aes_mix_columns(state: List[int]) -> List[int]:
    out = list(state)
    for column in range(4):
        a = state[4 * column:4 * column + 4]
        out[4 * column + 0] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * column + 1] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
        out[4 * column + 2] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
        out[4 * column + 3] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
    return out


def _gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if high else 0)
        b >>= 1
    return result


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """One AES block (FIPS-197 §5.1). Only encryption: SNMP never decrypts a block."""
    if len(block) != 16:
        raise CipherError("AES works on 16 byte blocks, not %d" % len(block))
    round_keys = _aes_round_keys(key)
    state = list(xor_bytes(block, bytes(round_keys[0])))
    for round_index in range(1, len(round_keys)):
        state = [AES_SBOX[value] for value in state]
        state = _aes_shift_rows(state)
        if round_index != len(round_keys) - 1:
            state = _aes_mix_columns(state)
        state = list(xor_bytes(bytes(state), bytes(round_keys[round_index])))
    return bytes(state)


def _aes_cfb128(key: bytes, iv: bytes, data: bytes, decrypt: bool) -> bytes:
    """CFB with a 128-bit segment (RFC 3826 §3.1.2).

    The encryption and decryption loops differ in one line, and the difference is the
    whole trick: in both directions the keystream is `E(previous ciphertext block)`, so
    when decrypting it is the *input* chunk that gets fed back, not the output. Feed the
    output back and the first block is right and every later one is noise — which is
    exactly the bug this file shipped for an afternoon, caught by an agent that
    authenticated and encrypted its answers for real.
    """
    if len(iv) != 16:
        raise CipherError("AES-CFB needs a 16 byte IV, not %d" % len(iv))
    out = bytearray()
    feedback = bytes(iv)
    for start in range(0, len(data), 16):
        chunk = data[start:start + 16]
        stream = aes_encrypt_block(key, feedback)
        out += xor_bytes(chunk, stream[:len(chunk)])
        if len(chunk) < 16:                     # a last, short block still feeds back
            feedback = (chunk if decrypt else bytes(out[-len(chunk):])) \
                + feedback[len(chunk):]
            break
        feedback = chunk if decrypt else bytes(out[-16:])
    return bytes(out)


def aes_cfb128(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Encrypt with AES-CFB128."""
    return _aes_cfb128(key, iv, data, decrypt=False)


def aes_cfb128_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Decrypt with AES-CFB128: the same keystream, fed from the ciphertext."""
    return _aes_cfb128(key, iv, data, decrypt=True)


# ------------------------------------------------------------------------------ DES


def _permute(bits: List[int], table: List[int]) -> List[int]:
    """`table` holds 1-based source positions, the way the DES paper writes them."""
    return [bits[position - 1] for position in table]


DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

DES_SBOXES: List[List[List[int]]] = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

#: The final permutation is the inverse of the initial one, so it is derived rather
#: than typed: another 64 numbers to get wrong, for nothing.
DES_FP = [0] * 64
for _index, _position in enumerate(DES_IP):
    DES_FP[_position - 1] = _index + 1


def _bytes_to_bits(data: bytes) -> List[int]:
    return [(byte >> (7 - bit)) & 1 for byte in data for bit in range(8)]


def _bits_to_bytes(bits: List[int]) -> bytes:
    return bytes(sum(bits[i + j] << (7 - j) for j in range(8))
                 for i in range(0, len(bits), 8))


def _des_subkeys(key: bytes) -> List[List[int]]:
    if len(key) != 8:
        raise CipherError("DES needs an 8 byte key, not %d" % len(key))
    bits = _permute(_bytes_to_bits(key), DES_PC1)
    left, right = bits[:28], bits[28:]
    subkeys = []
    for shift in DES_SHIFTS:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        subkeys.append(_permute(left + right, DES_PC2))
    return subkeys


def _des_feistel(right: List[int], subkey: List[int]) -> List[int]:
    mixed = [a ^ b for a, b in zip(_permute(right, DES_E), subkey)]
    out: List[int] = []
    for box in range(8):
        chunk = mixed[box * 6:box * 6 + 6]
        row = (chunk[0] << 1) | chunk[5]
        column = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        value = DES_SBOXES[box][row][column]
        out += [(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1]
    return _permute(out, DES_P)


def des_encrypt_block(key: bytes, block: bytes) -> bytes:
    """One DES block, encryption direction (FIPS 46-3)."""
    if len(block) != 8:
        raise CipherError("DES works on 8 byte blocks, not %d" % len(block))
    bits = _permute(_bytes_to_bits(block), DES_IP)
    left, right = bits[:32], bits[32:]
    for subkey in _des_subkeys(key):
        left, right = right, [a ^ b for a, b in zip(left, _des_feistel(right, subkey))]
    return _bits_to_bytes(_permute(right + left, DES_FP))


def des_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 8:
        raise CipherError("DES-CBC needs an 8 byte IV, not %d" % len(iv))
    if len(data) % 8:
        raise CipherError("DES-CBC payload must be a multiple of 8 bytes")
    out = bytearray()
    previous = iv
    for start in range(0, len(data), 8):
        block = xor_bytes(data[start:start + 8], previous)
        previous = des_encrypt_block(key, block)
        out += previous
    return bytes(out)


def des_decrypt_block(key: bytes, block: bytes) -> bytes:
    """The inverse permutation of `des_encrypt_block`: same rounds, reversed subkeys."""
    if len(block) != 8:
        raise CipherError("DES works on 8 byte blocks, not %d" % len(block))
    bits = _permute(_bytes_to_bits(block), DES_IP)
    left, right = bits[:32], bits[32:]
    for subkey in reversed(_des_subkeys(key)):
        left, right = right, [a ^ b for a, b in zip(left, _des_feistel(right, subkey))]
    return _bits_to_bytes(_permute(right + left, DES_FP))


def des_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 8:
        raise CipherError("DES-CBC needs an 8 byte IV, not %d" % len(iv))
    if len(data) % 8:
        raise CipherError("DES-CBC payload must be a multiple of 8 bytes")
    out = bytearray()
    previous = iv
    for start in range(0, len(data), 8):
        block = data[start:start + 8]
        out += xor_bytes(des_decrypt_block(key, block), previous)
        previous = block
    return bytes(out)
