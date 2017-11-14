"""
encrypt.py

@author: derricw

simple pure-python public-key block cypher implementation

"""
from maths import find_random_prime, find_random_coprime, multinv

DEFAULT_EXP = 65537
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
    n, e = key
    blocks = text2int(msg, block_size)
    return [pow(block, e, n) for block in blocks]

def decrypt(encrypted_blocks, key, block_size=BLOCK_SIZE):
    """ Decryptes a message using a private key.
    """
    n, d = key
    decrypted_blocks = [pow(block, d, n) for block in encrypted_blocks]
    return int2text(decrypted_blocks, block_size)

def encrypt_to_file(msg, key, path, block_size=BLOCK_SIZE):
    data = encrypt(msg, key, block_size)
    with open(path, 'w') as f:
        f.write("message_length: {}".format(len(msg)))
        f.write("public_key_used: {}".format(key))
        f.write("block_size: {}".format(block_size))
        f.write("\n")
        f.write("message: \n{}".format("\n".join(data)))

def get_key_prime(size=1024):
    """ Gets a random prime of the specified key size (bits).
    """
    return find_random_prime(2**(size-1), 2**size)

def get_key_coprime(n, size):
    """ Gets a random coprime for N that is the specified key size (bits).
    """
    return find_random_coprime(n, DEFAULT_EXP, 2**size)

def generate_key_pair(key_size, use_default_exponent=True):
    """ Generates a public and private key of the specified size (bits).
    """
    # find p, q, n
    p, q = 0, 0
    while p == q:
        p = get_key_prime(key_size)
        q = get_key_prime(key_size)

    n = p * q

    # create e that is coprime to (p-1)*(q-1)
    x = (p-1)*(q-1)
    if use_default_exponent:
        e = DEFAULT_EXP
    else:
        e = get_key_coprime(x, key_size)

    # create d that is multiplicative inverse of e mod x
    d = multinv(x, e)

    public_key = n, e
    private_key = n, d

    return public_key, private_key




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
    sample_public_key = (5551201688147, 65537)
    sample_private_key = (5551201688147, 109182490673)

    cyphertext = encrypt(msg, sample_public_key, block_size=5)
    print("Encrypted: {}".format(cyphertext))
    plaintext = decrypt(cyphertext, sample_private_key, block_size=5)
    print("Plaintext: {}".format(plaintext))

    print("Little Prime: {}".format(get_key_prime(32)))
    print("Medium Prime: {}".format(get_key_prime(256)))
    print("Big Prime: {}".format(get_key_prime(1024)))

    # generate some real keys and encrype/decrypt
    public, private = generate_key_pair(512)
    cyphertext = encrypt(msg, public, block_size=64)
    print("Encrypted: {}".format(cyphertext))
    plaintext = decrypt(cyphertext, private, block_size=64)
    print("Plaintext: {}".format(plaintext))



if __name__ == '__main__':
    main()
