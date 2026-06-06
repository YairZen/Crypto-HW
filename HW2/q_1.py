import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def aes_encrypt_decrypt_demo():
    # 1. הטקסט המקורי להצפנה כפי שנדרש בתרגיל
    raw_text = "Homework 2 for the Course Cryptology: Student 1 Full Name, ID and Student 2 Full Name, ID."
    plaintext_bytes = raw_text.encode('utf-8')

    print("--- תחילת הצפנת AES ---")
    print(f"טקסט מקורי: {raw_text}")
    print(f"אורך הטקסט המקורי בבתים: {len(plaintext_bytes)} bytes\n")

    # 2. יצירת מפתח אקראי בגודל 128 ביט (16 בתים) התקף לשני המצבים
    aes_key = os.urandom(16)
    print(f"מפתח הצפנה סימטרי (Hex): {aes_key.hex()}")

    # 3. שלב הריפוד (Padding) לפי תקן PKCS7 - חובה עבור ECB ו-CBC
    # מנגנון ה-PKCS7 מוסיף בתים שערכם כגודל הריפוד החסר כדי להביא את הקלט לכפולות של גודל הבלוק.
    # בלוק AES דורש בדיוק 16 בתים (128 ביט)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()
    print(f"אורך הטקסט לאחר ריפוד (כפולה של 16): {len(padded_plaintext)} bytes\n")

    # ==========================================
    # מצב פעולה א': AES במצב ECB
    # ==========================================
    print("--- 1. מצב פעולה: AES-ECB ---")
    cipher_ecb = Cipher(algorithms.AES(aes_key), modes.ECB())
    encryptor_ecb = cipher_ecb.encryptor()

    ciphertext_ecb = encryptor_ecb.update(padded_plaintext) + encryptor_ecb.finalize()
    print(f"הטקסט המוצפן ב-ECB (Hex): {ciphertext_ecb.hex()}")

    # פענוח ECB
    decryptor_ecb = cipher_ecb.decryptor()
    decrypted_padded_ecb = decryptor_ecb.update(ciphertext_ecb) + decryptor_ecb.finalize()

    # הסרת הריפוד
    unpadder_ecb = padding.PKCS7(128).unpadder()
    decrypted_text_ecb = unpadder_ecb.update(decrypted_padded_ecb) + unpadder_ecb.finalize()
    print(f"הטקסט המפונח מ-ECB: {decrypted_text_ecb.decode('utf-8')}\n")

    # ==========================================
    # מצב פעולה ב': AES במצב CBC
    # ==========================================
    print("--- 2. מצב פעולה: AES-CBC ---")
    # מצב CBC דורש וקטור אתחול (IV) אקראי בגודל בלוק (16 בתים)
    iv = os.urandom(16)
    print(f"וקטור אתחול IV (Hex): {iv.hex()}")

    cipher_cbc = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor_cbc = cipher_cbc.encryptor()

    ciphertext_cbc = encryptor_cbc.update(padded_plaintext) + encryptor_cbc.finalize()
    print(f"הטקסט המוצפן ב-CBC (Hex): {ciphertext_cbc.hex()}")

    # פענוח CBC
    decryptor_cbc = cipher_cbc.decryptor()
    decrypted_padded_cbc = decryptor_cbc.update(ciphertext_cbc) + decryptor_cbc.finalize()

    # הסרת הריפוד
    unpadder_cbc = padding.PKCS7(128).unpadder()
    decrypted_text_cbc = unpadder_cbc.update(decrypted_padded_cbc) + unpadder_cbc.finalize()
    print(f"הטקסט המפונח מ-CBC: {decrypted_text_cbc.decode('utf-8')}\n")

if __name__ == "__main__":
    aes_encrypt_decrypt_demo()