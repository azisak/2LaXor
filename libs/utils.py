"""
Utils function
"""

__author__ = "Azis Adi Kuncoro"

import sys

_PADDING_CHAR = b'\x00'


def plain_pad(text, block_size):
    _len = block_size
    return text + bytes((_len - len(text) % _len) * chr(_len - len(text) % _len), "utf-8")


def plain_unpad(text):
    return text[:-ord(text[len(text)-1:])]


def create_block_of_bytes(text, block_size, padding=True):

    if (padding):
        text = plain_pad(text, block_size)

    blocks = bytearray(text)
    return [blocks[i:i+block_size] for i in range(0, len(blocks), block_size)]


def xor_elmt_wise(byte_1, byte_2):
    i_1 = int.from_bytes(byte_1, sys.byteorder)
    i_2 = int.from_bytes(byte_2, sys.byteorder)
    res = i_1 ^ i_2

    return res.to_bytes(len(byte_1), sys.byteorder)
