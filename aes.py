# -*- coding: utf-8 -*-
# Author: THUZLB

"""
    AES encryption and decryption module.
"""

import numpy as np


class AesConstant:
    SBox = np.array([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ])

    InvSBox = np.array([
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ])

    ShiftRow = np.array([
        0, 5, 10, 15,
        4, 9, 14, 3,
        8, 13, 2, 7,
        12, 1, 6, 11
    ])

    InvShiftRow = np.array([
        0, 13, 10, 7,
        4, 1, 14, 11,
        8, 5, 2, 15,
        12, 9, 6, 3
    ])

    RC = np.array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36], dtype=np.uint8)


class AesSubFunction:
    @staticmethod
    def addroundkey(data, key):
        return data ^ key

    @staticmethod
    def invaddroundkey(data, key):
        return data ^ key

    @staticmethod
    def subbytes(data):
        return AesConstant.SBox[data]

    @staticmethod
    def invsubbytes(data):
        return AesConstant.InvSBox[data]

    @staticmethod
    def shiftrows(data):
        return data[:, AesConstant.ShiftRow]

    @staticmethod
    def invshiftrows(data):
        return data[:, AesConstant.InvShiftRow]

    @staticmethod
    def modgf(data):
        return np.asarray([(((data_tmp << 1) ^ 0x1B) & 0xFF) if (data_tmp & 0x80) else (data_tmp << 1)
                           for data_tmp in data], dtype=np.uint8)

    @staticmethod
    def mixcolumn_0(data):  # 2, 3, 1, 1
        return AesSubFunction.modgf(data[:, 0] ^ data[:, 1]) ^ data[:, 1] ^ data[:, 2] ^ data[:, 3]

    @staticmethod
    def invmixcolumn_0(data):  # E, B, D, 9, [1110, 1011, 1101, 1001]
        result = (AesSubFunction.modgf(AesSubFunction.modgf(AesSubFunction.modgf(
            data[:, 0] ^ data[:, 1] ^ data[:, 2] ^ data[:, 3]))) ^
                  AesSubFunction.modgf(AesSubFunction.modgf(data[:, 0] ^ data[:, 2])) ^
                  AesSubFunction.modgf(data[:, 0] ^ data[:, 1]) ^ (data[:, 1] ^ data[:, 2] ^ data[:, 3]))

        return result

    @staticmethod
    def mixcolumn_1(data):  # 1, 2, 3, 1
        return AesSubFunction.modgf(data[:, 1] ^ data[:, 2]) ^ data[:, 0] ^ data[:, 2] ^ data[:, 3]

    @staticmethod
    def invmixcolumn_1(data):  # 9, E, B, D, [1001, 1110, 1011, 1101]
        result = (AesSubFunction.modgf(AesSubFunction.modgf(AesSubFunction.modgf(
            data[:, 0] ^ data[:, 1] ^ data[:, 2] ^ data[:, 3]))) ^
                  AesSubFunction.modgf(AesSubFunction.modgf(data[:, 1] ^ data[:, 3])) ^
                  AesSubFunction.modgf(data[:, 1] ^ data[:, 2]) ^ (data[:, 0] ^ data[:, 2] ^ data[:, 3]))

        return result

    @staticmethod
    def mixcolumn_2(data):  # 1, 1, 2, 3
        return AesSubFunction.modgf(data[:, 2] ^ data[:, 3]) ^ data[:, 0] ^ data[:, 1] ^ data[:, 3]

    @staticmethod
    def invmixcolumn_2(data):  # D, 9, E, B, [1101, 1001, 1110, 1011]
        result = (AesSubFunction.modgf(AesSubFunction.modgf(AesSubFunction.modgf(
            data[:, 0] ^ data[:, 1] ^ data[:, 2] ^ data[:, 3]))) ^
                  AesSubFunction.modgf(AesSubFunction.modgf(data[:, 0] ^ data[:, 2])) ^
                  AesSubFunction.modgf(data[:, 2] ^ data[:, 3]) ^ (data[:, 0] ^ data[:, 1] ^ data[:, 3]))

        return result

    @staticmethod
    def mixcolumn_3(data):  # 3, 1, 1, 2
        return AesSubFunction.modgf(data[:, 3] ^ data[:, 0]) ^ data[:, 0] ^ data[:, 1] ^ data[:, 2]

    @staticmethod
    def invmixcolumn_3(data):  # B, D, 9, E, [1011, 1101, 1001, 1110]
        result = (AesSubFunction.modgf(AesSubFunction.modgf(AesSubFunction.modgf(
            data[:, 0] ^ data[:, 1] ^ data[:, 2] ^ data[:, 3]))) ^
                  AesSubFunction.modgf(AesSubFunction.modgf(data[:, 1] ^ data[:, 3])) ^
                  AesSubFunction.modgf(data[:, 0] ^ data[:, 3]) ^ (data[:, 0] ^ data[:, 1] ^ data[:, 2]))

        return result

    @staticmethod
    def mixcolumns(data):
        mixcolumns_data = np.zeros(data.shape, dtype=np.uint8)
        for i in range(4):
            mixcolumns_data[:, 4 * i + 0] = AesSubFunction.mixcolumn_0(data[:, 4 * i: 4 * (i + 1)])
            mixcolumns_data[:, 4 * i + 1] = AesSubFunction.mixcolumn_1(data[:, 4 * i: 4 * (i + 1)])
            mixcolumns_data[:, 4 * i + 2] = AesSubFunction.mixcolumn_2(data[:, 4 * i: 4 * (i + 1)])
            mixcolumns_data[:, 4 * i + 3] = AesSubFunction.mixcolumn_3(data[:, 4 * i: 4 * (i + 1)])

        return mixcolumns_data

    @staticmethod
    def invmixcolumns(data):
        invmixcolumns_data = np.zeros(data.shape, dtype=np.uint8)
        for i in range(4):
            invmixcolumns_data[:, 4 * i + 0] = AesSubFunction.invmixcolumn_0(data[:, 4 * i: 4 * (i + 1)])
            invmixcolumns_data[:, 4 * i + 1] = AesSubFunction.invmixcolumn_1(data[:, 4 * i: 4 * (i + 1)])
            invmixcolumns_data[:, 4 * i + 2] = AesSubFunction.invmixcolumn_2(data[:, 4 * i: 4 * (i + 1)])
            invmixcolumns_data[:, 4 * i + 3] = AesSubFunction.invmixcolumn_3(data[:, 4 * i: 4 * (i + 1)])

        return invmixcolumns_data

    @staticmethod
    def round_encrypt(data, key):
        data = AesSubFunction.subbytes(data)
        data = AesSubFunction.shiftrows(data)
        data = AesSubFunction.mixcolumns(data)
        data = AesSubFunction.addroundkey(data, key)

        return data

    @staticmethod
    def round_decrypt(data, key):
        data = AesSubFunction.invaddroundkey(data, key)
        data = AesSubFunction.invmixcolumns(data)
        data = AesSubFunction.invshiftrows(data)
        data = AesSubFunction.invsubbytes(data)

        return data


class AesGenerate:
    @staticmethod
    def generate(key, rounds):
        key = np.concatenate((key[:, 1:4], key[:, 0:1]), axis=1)
        key = AesSubFunction.subbytes(key)
        key[:, 0] ^= AesConstant.RC[rounds - 1]

        return key

    @staticmethod
    def generate_roundkeys128(key):
        roundkeys = np.zeros(shape=(len(key), 16 * 11), dtype=np.uint8)
        roundkeys[:, 0:16] = key
        for i in range(1, 11):
            roundkeys[:, 16 * i: 16 * i + 4] = roundkeys[:, 16 * (i - 1):16 * (i - 1) + 4] ^ \
                                               AesGenerate.generate(roundkeys[:, 16 * (i - 1) + 12:16 * i], rounds=i)
            roundkeys[:, 16 * i + 4: 16 * i + 8] = \
                roundkeys[:, 16 * i: 16 * i + 4] ^ roundkeys[:, 16 * (i - 1) + 4: 16 * (i - 1) + 8]
            roundkeys[:, 16 * i + 8: 16 * i + 12] = \
                roundkeys[:, 16 * i + 4: 16 * i + 8] ^ roundkeys[:, 16 * (i - 1) + 8: 16 * (i - 1) + 12]
            roundkeys[:, 16 * i + 12: 16 * i + 16] = \
                roundkeys[:, 16 * i + 8: 16 * i + 12] ^ roundkeys[:, 16 * (i - 1) + 12: 16 * (i - 1) + 16]

        return roundkeys

    @staticmethod
    def generate_roundkeys192(key):
        roundkeys = np.zeros(shape=(len(key), 16 * 13), dtype=np.uint8)
        roundkeys[:, 0:24] = key
        for i in range(1, 9):
            roundkeys[:, 24 * i: 24 * i + 4] = roundkeys[:, 24 * (i - 1):24 * (i - 1) + 4] ^ \
                                               AesGenerate.generate(roundkeys[:, 24 * (i - 1) + 20:24 * i], rounds=i)
            words = 4 if i == 8 else 6
            for j in range(1, words):
                roundkeys[:, 24 * i + 4 * j: 24 * i + 4 * (j + 1)] = \
                    roundkeys[:, 24 * i + 4 * (j - 1): 24 * i + 4 * j] ^ \
                    roundkeys[:, 24 * (i - 1) + 4 * j: 24 * (i - 1) + 4 * (j + 1)]

        return roundkeys

    @staticmethod
    def generate_roundkeys256(key):
        roundkeys = np.zeros(shape=(len(key), 16 * 15), dtype=np.uint8)
        roundkeys[:, 0:32] = key
        for i in range(1, 8):
            roundkeys[:, 32 * i: 32 * i + 4] = roundkeys[:, 32 * (i - 1):32 * (i - 1) + 4] ^ \
                                               AesGenerate.generate(roundkeys[:, 32 * (i - 1) + 28:32 * i], rounds=i)
            words = 4 if i == 7 else 8
            for j in range(1, words):
                roundkeys[:, 32 * i + 4 * j: 32 * i + 4 * (j + 1)] = \
                    roundkeys[:, 32 * i + 4 * (j - 1): 32 * i + 4 * j] ^ \
                    roundkeys[:, 32 * (i - 1) + 4 * j: 32 * (i - 1) + 4 * (j + 1)]

        return roundkeys


class AesEncrypt:
    @staticmethod
    def encrypt(plaintext, key):
        if plaintext.shape[-1] != 16:
            raise ValueError('The last demension of plaintext should be 16 but we got %s.' % plaintext.shape[-1])
        if key.shape[-1] not in [16, 24, 32]:
            raise ValueError('The last demension of key should be in [16, 24, 32] but we got %s.' % key.shape[-1])

        if plaintext.ndim == 1:
            plaintext = np.expand_dims(plaintext, axis=0)
        if key.ndim == 1:
            key = np.tile(key, (len(plaintext), 1))

        if len(key) != len(plaintext):
            raise ValueError('The shape of key(%s) is not compatible with the shape of plaintext(%s).' % (
                key.shpae, plaintext.shape))

        if key.shape[1] == 16:
            return AesEncrypt.encrypt128(plaintext, key)
        elif key.shape[1] == 24:
            return AesEncrypt.encrypt192(plaintext, key)
        else:
            return AesEncrypt.encrypt256(plaintext, key)

    @staticmethod
    def encrypt128(plaintext, key):
        roundkeys = AesGenerate.generate_roundkeys128(key)
        ciphertext = AesSubFunction.addroundkey(plaintext, roundkeys[:, 0:16])
        print(0, ciphertext)
        for i in range(1, 10):
            ciphertext = AesSubFunction.round_encrypt(ciphertext, roundkeys[:, 16 * i:16 * (i + 1)])
            print(i, ciphertext)
        ciphertext = AesSubFunction.subbytes(ciphertext)
        ciphertext = AesSubFunction.shiftrows(ciphertext)
        ciphertext = AesSubFunction.addroundkey(ciphertext, roundkeys[:, 16 * 10:16 * 11])
        print(10, ciphertext)

        return ciphertext

    # @staticmethod
    # def parameter_encrypt128(plaintext, key, round_start=-1, round_stop=10):
    #     if not round_start in range(-1, 11):
    #         raise ValueError('round_start should be in range(-1, 10) but we got %s.' %round_start)
    #     if not round_stop in range(-1, 11):
    #         raise ValueError('round_stop should be in range(-1, 10) but we got %s.' %round_stop)
    #     if round_start > round_stop:
    #         raise ValueError('round_start should not be larger than round_stop.')
    #
    #     if round_start == round_stop:
    #         return plaintext
    #     else:
    #         roundkeys = AesGenerate.generate_roundkeys128(key)
    #         if round_start == -1:
    #             ciphertext = AesSubFunction.addroundkey(plaintext, roundkeys[:, 0:16])
    #         else:
    #         for i in range(round_start, round_stop):
    #
    #     ciphertext = AesSubFunction.addroundkey(plaintext, roundkeys[:, 0:16])
    #     for j in range(1, 10):
    #         ciphertext = AesSubFunction.round_encrypt(ciphertext, roundkeys[:, 16 * j:16 * (j + 1)])
    #     ciphertext = AesSubFunction.subbytes(ciphertext)
    #     ciphertext = AesSubFunction.shiftrows(ciphertext)
    #     ciphertext = AesSubFunction.addroundkey(ciphertext, roundkeys[:, 16 * 10:16 * 11])
    #
    #     return ciphertext

    @staticmethod
    def encrypt192(plaintext, key):
        roundkeys = AesGenerate.generate_roundkeys192(key)
        ciphertext = AesSubFunction.addroundkey(plaintext, roundkeys[:, 0:16])
        for j in range(1, 12):
            ciphertext = AesSubFunction.round_encrypt(ciphertext, roundkeys[:, 16 * j:16 * (j + 1)])
        ciphertext = AesSubFunction.subbytes(ciphertext)
        ciphertext = AesSubFunction.shiftrows(ciphertext)
        ciphertext = AesSubFunction.addroundkey(ciphertext, roundkeys[:, 16 * 12:16 * 13])

        return ciphertext

    @staticmethod
    def encrypt256(plaintext, key):
        roundkeys = AesGenerate.generate_roundkeys256(key)
        ciphertext = AesSubFunction.addroundkey(plaintext, roundkeys[:, 0:16])
        for j in range(1, 14):
            ciphertext = AesSubFunction.round_encrypt(ciphertext, roundkeys[:, 16 * j:16 * (j + 1)])
        ciphertext = AesSubFunction.subbytes(ciphertext)
        ciphertext = AesSubFunction.shiftrows(ciphertext)
        ciphertext = AesSubFunction.addroundkey(ciphertext, roundkeys[:, 16 * 14:16 * 15])

        return ciphertext


class AesDecrypt:
    @staticmethod
    def decrypt(ciphertext, key):
        if ciphertext.shape[-1] != 16:
            raise ValueError('The last demension of ciphertext should be 16 but we got %s.' % ciphertext.shape[-1])
        if key.shape[-1] not in [16, 24, 32]:
            raise ValueError('The last demension of key should be in [16, 24, 32] but we got %s.' % key.shape[-1])

        if ciphertext.ndim == 1:
            ciphertext = np.expand_dims(ciphertext, axis=0)

        if key.ndim == 1:
            key = np.tile(key, (len(ciphertext), 1))

        if len(key) != len(ciphertext):
            raise ValueError('The shape of key(%s) is not compatible with the shape of ciphertext(%s).' % (
                key.shpae, ciphertext.shape))

        if key.shape[1] == 16:
            return AesDecrypt.decrypt128(ciphertext, key)
        elif key.shape[1] == 24:
            return AesDecrypt.decrypt192(ciphertext, key)
        else:
            return AesDecrypt.decrypt256(ciphertext, key)

    @staticmethod
    def decrypt128(ciphertext, key):
        print(10, ciphertext)
        roundkeys = AesGenerate.generate_roundkeys128(key)
        plaintext = AesSubFunction.invaddroundkey(ciphertext, roundkeys[:, 16 * 10: 16 * 11])
        plaintext = AesSubFunction.invshiftrows(plaintext)
        plaintext = AesSubFunction.invsubbytes(plaintext)
        print(9, plaintext)
        for i in range(9, 0, -1):
            plaintext = AesSubFunction.round_decrypt(plaintext, roundkeys[:, 16 * i: 16 * (i + 1)])
            print(i - 1, plaintext)
        plaintext = AesSubFunction.invaddroundkey(plaintext, roundkeys[:, 0: 16])
        print(-1, plaintext)

        return plaintext

    @staticmethod
    def decrypt192(cihertext, key):
        pass

    @staticmethod
    def decrypt256(ciphertext, key):
        pass


if __name__ == '__main__':
    p = np.arange(16, dtype=np.uint8).reshape(-1, 16)
    k = np.arange(16, dtype=np.uint8).reshape(-1, 16)
    c = AesEncrypt.encrypt(p, k)
    print('c=:', c)
    # [[  0  96 191 254  70 131  75 184 218  92 249 166  31 242  32 174]]
    # [[106 255 243 202 118  64 203 129 156 212  11  94 221  26 164 254]]

    p_i = AesDecrypt.decrypt(c, k)
    print('p_i=: ', p_i)

    # p_sub = AesSubFunction.subbytes(p)
    # print('p_sub=: \n    ', p_sub)
    # p_sub_i = AesSubFunction.invsubbytes(p_sub)
    # print('p_sub_i=: \n    ', p_sub_i)
    #
    # p_shift = AesSubFunction.shiftrows(p)
    # print('p_shift=: \n    ', p_shift)
    # p_shift_i = AesSubFunction.invshiftrows(p_shift)
    # print('p_shift_i=: \n    ', p_shift_i)
    #
    # p_mix = AesSubFunction.mixcolumns(p)
    # print('p_mix=: \n    ', p_mix)
    # p_mix_i = AesSubFunction.invmixcolumns(p_mix)
    # print('p_mix_i=: \n    ', p_mix_i)
    #
    # p_add = AesSubFunction.addroundkey(p, k)
    # print('p_add=: \n    ', p_add)
    # p_add_i = AesSubFunction.invaddroundkey(p_add, k)
    # print('p_add_i=: \n    ', p_add_i)
    # [[142 193 102  72  26 103 122 169 106  20 255 110 206 136 192  16]]
    # [[ 16 110 234 136 148 247 131  51 181  40 122 136  88 240  36 178]]
    roundkeys = AesGenerate.generate_roundkeys128(k)
    # print(roundkeys.shape)
    print('inverse analysis-------------------------------------------')
    c_9 = np.array([[142, 193, 102, 72, 26, 103, 122, 169, 106, 20, 255, 110, 206, 136, 192, 16]], dtype=np.uint8)
    print(c_9)
    c_9_invadd = AesSubFunction.invaddroundkey(c_9, roundkeys[:, 16 * 9: 16 * 10])
    print(c_9_invadd)
    c_9_invmix = AesSubFunction.invmixcolumns(c_9_invadd)
    print(c_9_invmix)
    c_9_invshift = AesSubFunction.invshiftrows(c_9_invmix)
    print(c_9_invshift)
    c_9_invsub = AesSubFunction.invsubbytes(c_9_invshift)
    print(c_9_invsub)
    print('inverse analysis-------------------------------------------')
    c_9_add = AesSubFunction.addroundkey(c_9_invadd, roundkeys[:, 16 * 9: 16 * 10])
    print(c_9_add)
    c_9_mix = AesSubFunction.mixcolumns(c_9_invmix)
    print(c_9_mix)
    c_9_shift = AesSubFunction.shiftrows(c_9_invshift)
    print(c_9_shift)
    c_9_sub = AesSubFunction.subbytes(c_9_invsub)
    print(c_9_sub)

    print(AesSubFunction.round_decrypt(c_9, roundkeys[:, 16 * 9: 16 * 10]))

    print('mixtest---------------------------------------------------------')
    a = np.array([[202, 104, 218, 55, 34, 52, 54, 196, 213, 140, 135, 195, 106, 159, 236, 196]], dtype=np.uint8)
    print(a)
    a_m = AesSubFunction.mixcolumns(a)
    print(a_m)
    a_i = AesSubFunction.invmixcolumns(a_m)
    print(a_i)
    # [[202 104 218  55  34  52  54 196 213 140 135 195 106 159 236 196]]
    # [[218  88  84 153 234 212  45 247 122 135  18 242  70 164  97  94]]
    # [[202 104 218  55  78 110  90 158 213 140 135 195  48 243 182 168]]
