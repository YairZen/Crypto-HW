import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def count_differing_bits(bytes1, bytes2):
    # פונקציה הסופרת כמה ביטים שונים יש בין שני מערכי בתים באמצעות פעולת XOR
    total_diff_bits = 0
    for b1, b2 in zip(bytes1, bytes2):
        xor_result = b1 ^ b2
        # ספירת מספר ה-1-ים בתוצאת ה-XOR (כל 1 מייצג ביט שהתהפך)
        total_diff_bits += bin(xor_result).count('1')
    return total_diff_bits

def avalanche_effect_experiment():
    print("--- תחילת ניסוי: אפקט האוואלנש ב-AES ---")

    # 1. הגדרת מפתח קבוע של 128 ביט (16 בתים) לכל אורך הניסוי
    fixed_key = os.urandom(16)
    print(f"מפתח קבוע שנבחר לניסוי (Hex): {fixed_key.hex()}\n")

    # נשתמש במצב ECB לצורך ניסוי על בלוק בודד של 16 בתים
    cipher = Cipher(algorithms.AES(fixed_key), modes.ECB())

    # 4. חזרה על התהליך 5 פעמים עם קלטים אקראיים שונים
    for i in range(1, 6):
        # יצירת טקסט מקורי אקראי (Plaintext 1) בגודל בלוק קבוע (16 בתים)
        pt1 = os.urandom(16)

        # 2. יצירת טקסט שני (Plaintext 2) השונה בביט אחד בדיוק (היפוך הביט האחרון בבית הראשון)
        pt2 = bytearray(pt1)
        pt2[0] = pt2[0] ^ 1  # שינוי ביט בודד בעזרת XOR עם 1
        pt2 = bytes(pt2)

        # הצפנת שני הטקסטים עם המפתח הקבוע
        encryptor = cipher.encryptor()
        ct1 = encryptor.update(pt1) + encryptor.finalize()

        encryptor = cipher.encryptor()
        ct2 = encryptor.update(pt2) + encryptor.finalize()

        # 3. השוואת שני הטקסטים המוצפנים וספירת הביטים השונים
        diff_bits = count_differing_bits(ct1, ct2)

        # 5. הצגת התוצאות עבור כל סיבוב
        print(f"סיבוב {i}:")
        print(f"  Plaintext 1 (Hex): {pt1.hex()}")
        print(f"  Plaintext 2 (Hex): {pt2.hex()}")
        print(f"  Ciphertext 1 (Hex): {ct1.hex()}")
        print(f"  Ciphertext 2 (Hex): {ct2.hex()}")
        print(f"  --> מספר הביטים שהשתנו בפלט: {diff_bits} מתוך 128 (כ-{round((diff_bits/128)*100, 2)}%)\n")

if __name__ == "__main__":
    avalanche_effect_experiment()