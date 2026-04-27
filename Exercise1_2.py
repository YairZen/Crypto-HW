import math


def verify_key(k):
    # 1. show key
    print(f"Key numbers: {k}")

    # 2. Formula for 2x2 determinant: (ad - bc)
    # Key positions: 0, 1 (row 1)
    #                2, 3 (row 2)
    det = (k[0] * k[3] - k[1] * k[2]) % 26  # we are in Z 26 space
    print(f"Determinant: {det}")

    # 3. Check if valid (not 0 and no common factors with 26)
    if math.gcd(det, 26) == 1:                      # det!=0 is included (gcd(0,26) = 26..
        print("gcd == 1, Key is VALID\n")
        return True
    else:
        print("gcd != 1, Key is INVALID\n")
        return False


def get_inverse_matrix(k):
    # Mapping the list to matrix variables:
    # [a, b]
    # [c, d]
    a, b, c, d = k[0], k[1], k[2], k[3]

    # 1. Calculate the determinant (ad - bc)
    det = (a * d - b * c) % 26

    # 2. Find the Modular Inverse of the determinant
    # We need a number 'inv' such that (det * inv) % 26 == 1
    det_inv = -1
    for x in range(1, 26):
        if (det * x) % 26 == 1:
            det_inv = x
            break

    # 3. Build the Inverse Matrix: det_inv * adj(K) mod 26
    # The adjugate of [[a, b], [c, d]] is [[d, -b], [-c, a]]
    inv = []
    inv.append((d * det_inv) % 26)   # New 'a' position
    inv.append((-b * det_inv) % 26)  # New 'b' position
    inv.append((-c * det_inv) % 26)  # New 'c' position
    inv.append((a * det_inv) % 26)   # New 'd' position

    return inv

def NameCipher_decryption(ciphertext, key1, key2, is_padded):
    # Student names: Yair, Matan, Y = 24, M = 12
    a = 24
    b = 12

    # Show Input
    print(f"--- Decryption Input ---")
    print(f"Ciphertext: {ciphertext}")
    print(f"Key 1: {key1}, Key 2: {key2}")
    print(f"Is Padded Flag: {is_padded}")
    print(f"Parameters: a={a}, b={b}\n")


    # Convert strings keys to matrix
    key1_matrix = []
    for char in key1:
        number = ord(char.upper()) - ord('A')
        key1_matrix.append(number)

    key2_matrix = []
    for char in key2:
        number = ord(char.upper()) - ord('A')
        key2_matrix.append(number)

    if  not verify_key(key1_matrix) or not verify_key(key2_matrix):
        return "Decryption failed: One of the keys is invalid"

    # Get inverse matrices for decryption
    k1_inv = get_inverse_matrix(key1_matrix)
    k2_inv = get_inverse_matrix(key2_matrix)

    # Convert ciphertext to numbers
    cipher_nums = []
    for char in ciphertext:
        number = ord(char.upper()) - ord('A')
        cipher_nums.append(number)

    # First Decryption Step: Reverse Key 2 (The last encryption)
    step1_nums = []
    for i in range(0, len(cipher_nums), 2):
        z1 = cipher_nums[i]
        z2 = cipher_nums[i+1]

        # Substract (a, b) first: (Z - (a, b))
        val1 = (z1 - a) % 26
        val2 = (z2 - b) % 26

        # Multiply by inverse matrix K2
        y1 = (val1 * k2_inv[0] + val2 * k2_inv[2]) % 26
        y2 = (val1 * k2_inv[1] + val2 * k2_inv[3]) % 26
        step1_nums.extend([y1, y2])

    print(f"First decryption step: {step1_nums}")

    # Second Decryption Step: Reverse Key 1
    step2_nums = []
    for i in range(0, len(step1_nums), 2):
        y1_val = step1_nums[i]
        y2_val = step1_nums[i+1]

        # Substract (a, b)
        val1 = (y1_val - a) % 26
        val2 = (y2_val - b) % 26

        # Multiply by inverse matrix K1
        x1 = (val1 * k1_inv[0] + val2 * k1_inv[2]) % 26
        x2 = (val1 * k1_inv[1] + val2 * k1_inv[3]) % 26
        step2_nums.extend([x1, x2])

    print(f"Second decryption step: {step2_nums}")

    # Convert numbers back to plaintext string
    plaintext = ""
    for num in step2_nums:
        plaintext += chr(num + ord('A'))

    if is_padded:
        plaintext = plaintext[:-1]

    return plaintext

# Run example
print("Plaintext for EQQB:", NameCipher_decryption("EQQB", "road", "door", False))
print("\n")
print("Plaintext for EYRCVJ:", NameCipher_decryption("EYRCVJ", "road", "door", True))