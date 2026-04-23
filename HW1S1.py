import numpy as np
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

def NameCipher_encryption(plaintext, key1, key2):
    # Student names: Yair, Matan,  Y = 24, M = 12
    a = 24
    b = 12

    # Convert strings keys to matrix and validate
    key1_matrix = []
    for char in key1:
        number = ord(char.upper()) - ord('A')
        key1_matrix.append(number)
    verify_key(key1_matrix)

    key2_matrix = []
    for char in key2:
        number = ord(char.upper()) - ord('A')
        key2_matrix.append(number)
    verify_key(key2_matrix)

    # Convert plaintext to numbers
    text_nums = []
    for char in plaintext:
        number = ord(char.upper()) - ord('A')
        text_nums.append(number)

    # First Encryption Step: Y = (X * K1 + (a, b)) mod N
    step1_nums = []
    for i in range(0, len(text_nums), 2):
        # Taking block of m=2
        x1 = text_nums[i]
        x2 = text_nums[i+1]

        # Matrix multiplication for K1: Y = (X * K1 + (a, b))
        y1 = (x1 * key1_matrix[0] + x2 * key1_matrix[2] + a) % 26
        y2 = (x1 * key1_matrix[1] + x2 * key1_matrix[3] + b) % 26
        step1_nums.extend([y1, y2])

    print(f"First encryption: {step1_nums}")

    # Second Encryption Step: Z = (Y * K2 + (a, b)) mod N
    step2_nums = []
    for i in range(0, len(step1_nums), 2):
        y1_val = step1_nums[i]
        y2_val = step1_nums[i+1]

        # Matrix multiplication for K2: Z = (Y * K2 + (a, b))
        z1 = (y1_val * key2_matrix[0] + y2_val * key2_matrix[2] + a) % 26
        z2 = (y1_val * key2_matrix[1] + y2_val * key2_matrix[3] + b) % 26
        step2_nums.extend([z1, z2])

    print(f"Second encryption: {step2_nums}")

    # Convert numbers back to ciphertext string
    ciphertext = ""
    for num in step2_nums:
        ciphertext += chr(num + ord('A'))

    return ciphertext



# Run example
print("Ciphertext for YAIR:", NameCipher_encryption("YAIR", "road", "door"))
print("\n")
print("Ciphertext for MATN:", NameCipher_encryption("MATA", "road", "door"))