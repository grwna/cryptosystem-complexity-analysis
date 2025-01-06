from src.aes_rounds import *
from src.variables import RCON, S_BOX
from src.utility import generate_aes_key, read_file, write_file
import time

# Rotate word left by one byte
def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [S_BOX[b] for b in word]

def key_expansion(key, key_size=128):
    Nk = key_size // 32
    Nr = {128: 10, 192: 12, 256: 14}[key_size]
    Nb = 4  # State Columns

    expanded_key = [key[i:i+4] for i in range(0, len(key), 4)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = expanded_key[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[(i // Nk) - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        
        expanded_key.append([x ^ y for x, y in zip(expanded_key[i - Nk], temp)])
    return [expanded_key[i:i+Nb] for i in range(0, len(expanded_key), Nb)]

def plaintext_to_blocks(plaintext):
    blocks = []
    while plaintext:
        block = plaintext[:16]
        if len(block) < 16:
            block += '\x00' * (16 - len(block))
        blocks.append([[ord(block[i + j * 4]) for i in range(4)] for j in range(4)])  # Convert to 4x4 matrix
        plaintext = plaintext[16:]
    return blocks

def ciphertext_to_blocks(ciphertext):
        bytes_list = list(map(int, ciphertext.split()))
        blocks = []
        for i in range(0, len(bytes_list), 16):
            block = bytes_list[i:i + 16]
            matrix = [block[j * 4:(j + 1) * 4] for j in range(4)]
            blocks.append(matrix)
        return blocks

def encrypt(plaintext, key, key_size=128):
    round_keys = key_expansion(key, key_size)
    state = add_round_key(plaintext, round_keys[0])
    
    # Main rounds
    Nr = {128: 10, 192: 12, 256: 14}[key_size]  # Number of rounds
    for round_num in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])
    
    return state

def decrypt(ciphertext, key, key_size=128):
    round_keys = key_expansion(key, key_size)
    state = add_round_key(ciphertext, round_keys[-1])
    
    # Final round ( no MixColumns)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[-2])
    
    #  Main rounds
    Nr = {128: 10, 192: 12, 256: 14}[key_size]  # Number of rounds
    for round_num in range(Nr - 2, -1, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
    
    return state

def aes_encryption_runtime(key, key_size=128):
    plaintext = read_file("plaintext.txt")
    
    # Encryption
    start = time.time()
    blocks = plaintext_to_blocks(plaintext)
    ciphertext_blocks = []
    
    # Encrypt each block
    for state in blocks:
        ciphertext = encrypt(state, key, key_size)
        ciphertext_blocks.append(ciphertext)
    encryption_time = time.time() - start

    ciphertext_string = ' '.join(
        str(byte) for block in ciphertext_blocks for row in block for byte in row
    )
    print(f"Encryption Time: {encryption_time:.9f} seconds")

    write = f"K = 0x{key.hex()}\n\nC = {ciphertext_string}\n\nEncryption Time: {encryption_time:.9f} seconds"
    write_file(f"aes/ciphertext-aes-{key_size}.txt", write.encode(), mode='wb')

    return ciphertext_string, key

def aes_decryption_runtime(key, ciphertext, key_size=128):
    # Convert space-delimited ciphertext back to a 4x4 matrix
    
    # Decryption
    start = time.time()
    ciphertext_blocks = ciphertext_to_blocks(ciphertext)
    plaintext_blocks = []
    for state in ciphertext_blocks:
        plaintext_block = decrypt(state, key, key_size)
        plaintext_blocks.append(plaintext_block)
    decryption_time = time.time() - start

    # Convert decrypted plaintext matrix to string
    plaintext = ''.join(
        chr(byte) for block in plaintext_blocks for row in block for byte in row
    ).rstrip('\x00')
    print(plaintext)
    print(f"Decryption Time: {decryption_time:.9f} seconds")

    # Save plaintext to file
    write = f"P = {plaintext}\n\nDecryption Time: {decryption_time:.9f} seconds"
    write_file(f"aes/decrypted-aes-{key_size}.txt", write.encode(), mode='wb')

    return plaintext

if __name__ == "__main__":
    key_sizes = [128, 192, 256]

    for key_size in key_sizes:
        print(f"\nTesting AES with {key_size}-bit key:")

        key = generate_aes_key(key_size)

        ciphertext, key = aes_encryption_runtime(key, key_size)
        print(f"Encryption saved to ciphertext-aes-{key_size}.txt")

        plaintext = aes_decryption_runtime(key, ciphertext, key_size)
        print(f"Decryption saved to decrypted-aes-{key_size}.txt")