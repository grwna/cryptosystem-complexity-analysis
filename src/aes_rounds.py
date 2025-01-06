from src.variables import S_BOX, INV_S_BOX

# Galois multiplication in GF(2^8)
def galois_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80 
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

def sub_bytes(state):
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] = S_BOX[state[i][j]]
    return state

def shift_rows(state):
    for i in range(1, len(state)):
        state[i] = state[i][i:] + state[i][:i] 
    return state

def mix_columns(state):
    for i in range(4):
        col = state[i]
        state[i] = [
            galois_mult(col[0], 2) ^ galois_mult(col[1], 3) ^ col[2] ^ col[3],
            col[0] ^ galois_mult(col[1], 2) ^ galois_mult(col[2], 3) ^ col[3],
            col[0] ^ col[1] ^ galois_mult(col[2], 2) ^ galois_mult(col[3], 3),
            galois_mult(col[0], 3) ^ col[1] ^ col[2] ^ galois_mult(col[3], 2),
        ]
    return state

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def inv_sub_bytes(state):
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] = INV_S_BOX[state[i][j]]
    return state

def inv_shift_rows(state):
    for i in range(1, len(state)):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

def inv_mix_columns(state):
    for i in range(4):
        col = state[i]
        state[i] = [
            galois_mult(col[0], 14) ^ galois_mult(col[1], 11) ^ galois_mult(col[2], 13) ^ galois_mult(col[3], 9),
            galois_mult(col[0], 9) ^ galois_mult(col[1], 14) ^ galois_mult(col[2], 11) ^ galois_mult(col[3], 13),
            galois_mult(col[0], 13) ^ galois_mult(col[1], 9) ^ galois_mult(col[2], 14) ^ galois_mult(col[3], 11),
            galois_mult(col[0], 11) ^ galois_mult(col[1], 13) ^ galois_mult(col[2], 9) ^ galois_mult(col[3], 14),
        ]
    return state
