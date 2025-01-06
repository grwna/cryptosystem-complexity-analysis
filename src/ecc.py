import random
import time
from src.utility import *
from src.variables import *

class EllipticCurve:
    def __init__(self, a=a128, b=b128, p=p128):
        """
        Elliptic curve: y^2 = x^3 + ax + b (mod p).
        """
        self.a = a
        self.b = b
        self.p = p

    def is_on_curve(self, x, y):
        return (y**2 - (x**3 + self.a * x + self.b)) % self.p == 0
    
def point_addition(P, Q, curve):
    if P is None: return Q
    if Q is None: return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2:
        if (y1 != y2): return None
        else: return point_doubling(P, curve)
    
    m = ((y2 - y1) * pow(x2 - x1, -1, curve.p)) % curve.p
    x3 = (m**2 - x1 - x2) % curve.p
    y3 = (m * (x1 - x3) - y1) % curve.p
    return (x3, y3)  # Return new point

def point_doubling(P, curve):
    if P is None: return None
    
    x, y = P

    m = ((3 * x**2 + curve.a) * pow(2 * y, -1, curve.p)) % curve.p
    x3 = (m**2 - 2 * x) % curve.p
    y3 = (m * (x - x3) - y) % curve.p
    return (x3, y3)  # Return new point

def scalar_multiplication(k, P, curve):
    """
    k * P on the elliptic curve using the double-and-add algorithm.
    """
    if k == 0 or P is None:  return None

    result = None  # Start with the point at infinity
    addend = P

    while k:
        if k & 1:  # if bit of k == 1
            result = point_addition(result, addend, curve)
        addend = point_doubling(addend, curve)
        k >>= 1  # divide by 2

    return result

def generate_keys(curve, G=G128):
    # Private key
    d = random.randint(1, curve.p - 1)
    
    # Public key
    Q = scalar_multiplication(d, G, curve)
    
    return d, Q

def encrypt_ecc(plaintext, public_key, curve, G):
    k = random.randint(1, curve.p - 1)
    C1 = scalar_multiplication(k, G, curve)
    kQ = scalar_multiplication(k, public_key, curve)
    
    shared_x = kQ[0]  # Use the x-coordinate of S as the shared secret
    ciphertext_list = [str(ord(M) + shared_x) for M in plaintext]
    ciphertext = ' '.join(ciphertext_list)  # C2
    return C1, ciphertext

def decrypt_ecc(ciphertext, R, private_key, curve):
    kQ = scalar_multiplication(private_key, R, curve)
    
    shared_x = kQ[0]  # Use the x-coordinate of S as the shared secret
    ciphertext_list = list(map(int, ciphertext.split()))
    plaintext_list = [chr(char - shared_x) for char in ciphertext_list]
    plaintext = ''.join(plaintext_list)
    return plaintext

def ecc_encryption_runtime(curve, G, bits=128):
    start = time.time()
    private_key, public_key = generate_keys(curve, G)
    keygen_time = time.time() - start

    plaintext = read_file("plaintext.txt")

    start = time.time()
    C1, ciphertext = encrypt_ecc(plaintext, public_key, curve, G)
    encryption_time = time.time() - start

    print(f"Key Generation Time: {keygen_time:.9f} seconds")
    print(f"Encryption Time: {encryption_time:.9f} seconds")

    write = f"d = {private_key}\n\nC1 = {C1}\n\nC2 = {ciphertext}\n\nKey Generation Time: {keygen_time:.9f} seconds\nEncryption Time: {encryption_time:.9f} seconds"
    write_file(f"ecc/ciphertext-ecc-{bits}.txt", write)

    return C1, ciphertext, private_key

def ecc_decryption_runtime(curve, bits, private_key, R, ciphertext):
    start = time.time()
    plaintext = decrypt_ecc(ciphertext, R, private_key, curve)
    decryption_time = time.time() - start

    print(f"Decryption Time: {decryption_time:.9f} seconds")

    write = f"P = {plaintext}\n\nDecryption Time: {decryption_time:.9f} seconds"
    write_file(f"ecc/decrypted-ecc-{bits}.txt", write)

    return plaintext

if __name__ == "__main__":
    # NIST curves and generator points
    curves = {
        128: EllipticCurve(a=-3, b=b128, p=p128),
        192: EllipticCurve(a=-3, b=b192, p=p192),
        256: EllipticCurve(a=-3, b=b256, p=p256)
    }
    generators = {
        128: G128,
        192: G192,
        256: G256
    }

    key_sizes = [128, 192, 256]
    for bits in key_sizes:
        print(f"\nTesting ECC with {bits}-bit keys:")

        curve = curves[bits]
        G = generators[bits]

        R, ciphertext, private_key = ecc_encryption_runtime(curve, G, bits)
        print(f"Encryption saved to ciphertext-ecc-{bits}.txt")
        plaintext = ecc_decryption_runtime(curve, bits, private_key, R, ciphertext)
        print(f"Decryption saved to decrypted-ecc-{bits}.txt")
