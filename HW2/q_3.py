import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def expand_key(x, bits=20):
    # פונקציית הרחבת המפתח המלאכותית שניתנה בהנחיות התרגיל
    bin_key = format(x, f'0{bits}b')  # המרת המספר למחרוזת בינארית באורך k ביטים
    repeated = (bin_key * 7)[:128]     # שכפול הרצף 7 פעמים וחיתוך ל-128 ביט
    return int(repeated, 2).to_bytes(16, 'big')  # המרה למערך של 16 בתים עבור AES

def run_brute_force_experiment(k, plaintext, target_ciphertext):
    print(f"--- מתחיל התקפת כוח גס עבור מפתח בגודל k = {k} ביטים ---")

    start_time = time.time()  # תחילת מדידת זמן
    key_checks = 0            # מונה בדיקות מפתחות
    key_found = None

    # הגדרת גודל מרחב החיפוש (כמות האפשרויות הכוללת: 2 בחזקת k)
    # פונקציית range(0, search_space) תרוץ אוטומטית מאפס ועד (search_space - 1)
    search_space = 2 ** k

    # לולאת כוח גס שעוברת על כל מרחב המפתח המצומצם
    for x in range(0, search_space):
        key_checks += 1

        # 1. יצירת מפתח מורחב בגודל 128 ביט מתוך ה-x הנוכחי
        candidate_key = expand_key(x, bits=k)

        # 2. ניסיון הצפנה עם המפתח המועמד (במצב ECB על בלוק בודד)
        cipher = Cipher(algorithms.AES(candidate_key), modes.ECB())
        encryptor = cipher.encryptor()
        candidate_ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # 3. בדיקה האם הגענו לטקסט המוצפן המבוקש
        if candidate_ciphertext == target_ciphertext:
            key_found = x
            break  # מצאנו את המפתח, עוצרים את הלולאה

    end_time = time.time()  # סיום מדידת זמן
    elapsed_time = end_time - start_time

    print(f"  מפתח מקורי שנמצא: {key_found} (ברשת הביטים: {bin(key_found) if key_found is not None else ''})")
    print(f"  מספר בדיקות מפתח שבוצעו: {key_checks}")
    print(f"  זמן ריצה כולל: {elapsed_time:.4f} שניות\n")

    return elapsed_time, key_checks

def main():
    # 1) הגדרת ערכי הבסיס לניסוי לפי הדוגמה בשאלה
    plaintext = b"Hello student!!!"
    key_sizes = [20, 22, 24]
    execution_times = []

    print("==================================================")
    print("סימולציית התקפת כוח גס (Brute-Force) על AES מוקטן")
    print("==================================================\n")

    # הרצת הניסוי לכל גודל מפתח k = 20, 22, 24
    for k in key_sizes:
        # בחירת מפתח מטרה - שימוש במספר קבוע בהתאם להנחיות המקוריות
        secret_x = (2 ** k) - 1
        real_key = expand_key(secret_x, bits=k)

        # יצירת הטקסט המוצפן של המטרה בעזרת המפתח שנבחר
        cipher = Cipher(algorithms.AES(real_key), modes.ECB())
        encryptor = cipher.encryptor()
        target_ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # 2) הרצת מתקפת הכוח הגס ומדידת המדדים
        elapsed_time, checks = run_brute_force_experiment(k, plaintext, target_ciphertext)
        execution_times.append(elapsed_time)

    # 3) --- שלב יצירת הגרף בעזרת matplotlib ---
    plt.figure(figsize=(8, 5))
    plt.plot(key_sizes, execution_times, marker='o', linestyle='-', color='b', linewidth=2, markersize=8)

    # הגדרות עיצוב לציר ה-X וה-Y כפי שנדרש בשאלה
    plt.title("AES Reduced Key Brute-Force Time Complexity", fontsize=14, fontweight='bold')
    plt.xlabel("Key Size (Bits)", fontsize=12)
    plt.ylabel("Brute-Force Time (Seconds)", fontsize=12)
    plt.xticks(key_sizes)  # נקודות עבור 20, 22 ו-24
    plt.grid(True, linestyle='--', alpha=0.6)

    # שמירת הגרף כקובץ תמונה לצורך הצגה ב-doc
    plt.savefig("brute_force_graph.png", dpi=300)
    print("הגרף נוצר בהצלחה ונשמר כקובץ תמונה בשם: 'brute_force_graph.png'")

    plt.show()

if __name__ == "__main__":
    main()