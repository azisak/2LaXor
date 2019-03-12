from libs.Cipher import VigenereExtended
import libs.block_cipher_mode as cipher_mode
from libs.utils import *


def main():
    with open('samples/text.txt', 'r') as file:
        plaintext = bytes(file.read().replace('\n', '').encode())

    print("\nPlainTeks")
    print(plaintext)

    key = b'argarg3r9i2p9tuslernsbgaeiga4tq2'
    init_vector = b'lkj2klj21kj3u89sjafk790213hj21kk'

    cipher = VigenereExtended("ASD")

    res = cipher_mode.CFB().encrypt(plaintext, init_vector, cipher)
    print("\nDone Encrypting")
    print(res)

    res = cipher_mode.CFB().decrypt(res, init_vector, cipher)
    print("\nDone Decrypting")
    print(res)


if __name__ == "__main__":
    main()
