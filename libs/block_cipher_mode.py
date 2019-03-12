"""
Block cipher mode
"""
__author__ = "Azis Adi Kuncoro"

from .utils import *


class BlockCipherMode(object):
    BLOCK_SIZE = 32

    def __init__(self):
        pass


class ECB(BlockCipherMode):
    """
    Implementation of ECB Block cipher
    """

    def __init__(self):
        super().__init__()

    def encrypt(self, plaintext, cipher):
        block_of_bytes = create_block_of_bytes(plaintext, self.BLOCK_SIZE)

        # ECB things
        for i in range(len(block_of_bytes)):
            block_of_bytes[i] = cipher.encrypt(block_of_bytes[i])

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return bytes(block_of_bytes)

    def decrypt(self, ciphertext, cipher):
        block_of_bytes = create_block_of_bytes(
            ciphertext, self.BLOCK_SIZE, padding=False)

        # ECB things
        for i in range(len(block_of_bytes)):
            block_of_bytes[i] = cipher.decrypt(block_of_bytes[i])

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return plain_unpad(bytes(block_of_bytes))


class CBC(BlockCipherMode):
    """
    Implementation of CBC Block cipher
    """

    def __init__(self):
        super().__init__()

    def encrypt(self, plaintext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(plaintext, self.BLOCK_SIZE)

        # CBC things
        for i in range(len(block_of_bytes)):
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], initialization_vec)
            block_of_bytes[i] = cipher.encrypt(block_of_bytes[i])
            initialization_vec = block_of_bytes[i]

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return bytes(block_of_bytes)

    def decrypt(self, ciphertext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(
            ciphertext, self.BLOCK_SIZE, padding=False)

        # CBC things
        for i in range(len(block_of_bytes)):
            temp = block_of_bytes[i].copy()
            block_of_bytes[i] = xor_elmt_wise(
                cipher.decrypt(block_of_bytes[i]), initialization_vec)
            initialization_vec = temp

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return plain_unpad(bytes(block_of_bytes))


class CFB(BlockCipherMode):
    """
    Implementation of CFB Block cipher
    """

    def __init__(self):
        super().__init__()

    def encrypt(self, plaintext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(plaintext, self.BLOCK_SIZE)

        # CFB things
        for i in range(len(block_of_bytes)):
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], cipher.encrypt(initialization_vec))
            initialization_vec = block_of_bytes[i]

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return bytes(block_of_bytes)

    def decrypt(self, ciphertext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(
            ciphertext, self.BLOCK_SIZE, padding=False)

        # CFB things
        for i in range(len(block_of_bytes)):
            temp = block_of_bytes[i].copy()
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], cipher.encrypt(initialization_vec))
            initialization_vec = temp

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return plain_unpad(bytes(block_of_bytes))


class OFB(BlockCipherMode):
    """
    Implementation of CFB Block cipher
    """

    def __init__(self):
        super().__init__()

    def encrypt(self, plaintext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(plaintext, self.BLOCK_SIZE)

        # OFB things
        for i in range(len(block_of_bytes)):
            initialization_vec = cipher.encrypt(initialization_vec)
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], initialization_vec)

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return bytes(block_of_bytes)

    def decrypt(self, ciphertext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(
            ciphertext, self.BLOCK_SIZE, padding=False)

        # OFB things
        for i in range(len(block_of_bytes)):
            initialization_vec = cipher.encrypt(initialization_vec)
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], initialization_vec)

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return plain_unpad(bytes(block_of_bytes))


class CTR(BlockCipherMode):
    def __init__(self):
        super().__init__()

    def encrypt(self, plaintext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(plaintext, self.BLOCK_SIZE)

        # OFB things
        for i in range(len(block_of_bytes)):
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], cipher.encrypt(initialization_vec))
            int_i_vec = int.from_bytes(initialization_vec, sys.byteorder)
            initialization_vec = (
                int_i_vec + 1).to_bytes(len(initialization_vec), sys.byteorder)

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return bytes(block_of_bytes)

    def decrypt(self, ciphertext, initialization_vec, cipher):
        block_of_bytes = create_block_of_bytes(
            ciphertext, self.BLOCK_SIZE, padding=False)

        # OFB things
        for i in range(len(block_of_bytes)):
            block_of_bytes[i] = xor_elmt_wise(
                block_of_bytes[i], cipher.encrypt(initialization_vec))
            int_i_vec = int.from_bytes(initialization_vec, sys.byteorder)
            initialization_vec = (
                int_i_vec + 1).to_bytes(len(initialization_vec), sys.byteorder)

        # Flatten block_of_bytes
        block_of_bytes = bytes([c for item in block_of_bytes for c in item])

        return plain_unpad(bytes(block_of_bytes))
