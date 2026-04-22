# Simplified DES (S-DES) Implementation in Python

# -----------------------------
# Permutation tables
# -----------------------------
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

# -----------------------------
# S-Boxes
# -----------------------------
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]

# -----------------------------
# Helper functions
# -----------------------------
def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2))

def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(sbox[row][col], '02b')

def fk(bits, subkey):
    left = bits[:4]
    right = bits[4:]

    expanded = permute(right, EP)
    xored = xor(expanded, subkey)

    left_half = xored[:4]
    right_half = xored[4:]

    s0_result = sbox_lookup(left_half, S0)
    s1_result = sbox_lookup(right_half, S1)

    sbox_output = s0_result + s1_result
    p4_result = permute(sbox_output, P4)

    left_result = xor(left, p4_result)
    return left_result + right

def switch(bits):
    return bits[4:] + bits[:4]

# -----------------------------
# Key generation
# -----------------------------
def generate_keys(key10):
    p10_key = permute(key10, P10)

    left = p10_key[:5]
    right = p10_key[5:]

    # LS-1
    left1 = left_shift(left, 1)
    right1 = left_shift(right, 1)
    k1 = permute(left1 + right1, P8)

    # LS-2 (2 more shifts from LS-1 result)
    left2 = left_shift(left1, 2)
    right2 = left_shift(right1, 2)
    k2 = permute(left2 + right2, P8)

    return k1, k2

# -----------------------------
# Encryption
# -----------------------------
def encrypt(plaintext8, key10):
    k1, k2 = generate_keys(key10)

    temp = permute(plaintext8, IP)
    temp = fk(temp, k1)
    temp = switch(temp)
    temp = fk(temp, k2)
    ciphertext = permute(temp, IP_INV)

    return ciphertext

# -----------------------------
# Decryption
# -----------------------------
def decrypt(ciphertext8, key10):
    k1, k2 = generate_keys(key10)

    temp = permute(ciphertext8, IP)
    temp = fk(temp, k2)
    temp = switch(temp)
    temp = fk(temp, k1)
    plaintext = permute(temp, IP_INV)

    return plaintext

# -----------------------------
# Main program
# -----------------------------
def is_binary_string(value, length):
    return len(value) == length and all(bit in '01' for bit in value)

def main():
    print("S-DES Encryption/Decryption Program")
    print("-----------------------------------")

    key = input("Enter a 10-bit binary key: ").strip()
    if not is_binary_string(key, 10):
        print("Error: Key must be exactly 10 bits of 0s and 1s.")
        return

    choice = input("Type 'e' to encrypt or 'd' to decrypt: ").strip().lower()

    if choice == 'e':
        plaintext = input("Enter an 8-bit binary plaintext: ").strip()
        if not is_binary_string(plaintext, 8):
            print("Error: Plaintext must be exactly 8 bits of 0s and 1s.")
            return

        ciphertext = encrypt(plaintext, key)
        print(f"Ciphertext: {ciphertext}")

    elif choice == 'd':
        ciphertext = input("Enter an 8-bit binary ciphertext: ").strip()
        if not is_binary_string(ciphertext, 8):
            print("Error: Ciphertext must be exactly 8 bits of 0s and 1s.")
            return

        plaintext = decrypt(ciphertext, key)
        print(f"Plaintext: {plaintext}")

    else:
        print("Error: Invalid choice. Enter 'e' or 'd'.")

if __name__ == "__main__":
    main()
