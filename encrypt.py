"""
encrypt.py

@author: derricw

simple pure-python public-key cryptography implementation

"""

BLOCK_SIZE = 128 # in bytes

def text2int(msg, block_size=BLOCK_SIZE):
    """ Converts a message into integer blocks that can be encoded.
    WARNING: TRAILING NULL TERMINATORS WILL BE STRIPPED.
    """
    msg = msg.rstrip("\0").encode("ascii")
    ints = []
    for block in range(0, len(msg), block_size):
        block_val = 0
        for i in range(block, min(block + block_size, len(msg))):
            # create int repr for block by adding bytes raised to their index
            #    C0 * (256^0) + C1 * (256^1) + ... + Cn * (256^n)
            block_val += msg[i] * (256 ** (i % block_size))
        ints.append(block_val)
    return ints

def int2text(ints, block_size=BLOCK_SIZE):
    """ Converts integer blocks back into messages.
    """
    msg = []
    for block_int in ints:
        block_msg = []
        for i in range(block_size - 1, -1, -1):
                char = block_int // (256 ** i)
                block_int %= (256 ** i)
                block_msg.append(chr(char))
        msg.extend(block_msg[::-1])
    return "".join(msg).rstrip("\0")

def encrypt(msg, key, block_size=BLOCK_SIZE):
    """ Encodes a message using a public key.
    """
    e, n = key
    blocks = text2int(msg, block_size)
    return [pow(block, e, n) for block in blocks]


def decrypt(encrypted_blocks, key, block_size=BLOCK_SIZE):
    """ Decryptes a message using a private key.
    """
    d, n = key
    decrypted_blocks = [pow(block, d, n) for block in encrypted_blocks]
    return int2text(decrypted_blocks, block_size)


def main():
    #print(text2int("a")) # should be [97]
    #print(text2int("aaa"))  # should be [97 * 256^0 + 97 * 256^1 + 97 * 256^2 = 6381921]
    #print(text2int("a"*(BLOCK_SIZE+1))) # smallest msg that produces 2 ints [X, 97]

    msg = "abcdefghijklmnopqrstuvwxyz"
    print("Message: {}".format(msg))
    encoded = text2int(msg)
    print("Encoded: {}".format(encoded))
    plaintext = int2text(encoded)
    assert len(plaintext) == len(msg)
    assert plaintext == msg

    # sample keys from:
    # https://stackoverflow.com/questions/8539441/private-public-encryption-in-python-with-standard-library
    sample_public_key = (65537, 5551201688147)
    sample_private_key = (109182490673, 5551201688147)

    cyphertext = encrypt(msg, sample_public_key, block_size=5)
    print("Encrypted: {}".format(cyphertext))
    plaintext = decrypt(cyphertext, sample_private_key, block_size=5)
    print("Plaintext: {}".format(plaintext))




if __name__ == '__main__':
    main()
