import Exercise1_1

final_results = []

def Iterative_Attack(ciphertext, plaintext, key1, key2):
    """
    Performs an Iterative Attack using the original function signature.
    Matches the exact plaintext length and content.
    """
    print(f"--- Starting Iterative Attack for {plaintext} ---")

    current_text = ciphertext
    iterations = 0
    success = False
    max_iterations = 30000

    while iterations < max_iterations:
        iterations += 1

        # Calling the original signature
        res_text, res_flag = Exercise1_1.NameCipher_encryption(current_text, key1, key2)
        current_text = res_text

        # If the original plaintext was odd, we compare current_text to plaintext + 'X'
        target = plaintext if len(plaintext) % 2 == 0 else plaintext + 'X'

        if current_text == target:
            success = True
            break

    print(f"--- Attack Summary ---")
    if success:
        result_msg = f"Success! Found {plaintext} after {iterations} iterations."
        print(result_msg)
        final_results.append(result_msg) # שמירה לסיכום הסופי
    else:
        result_msg = f"Attack failed for {plaintext}. Current state: {current_text}"
        print(result_msg)
        final_results.append(result_msg)

    return iterations

# --- Execution ---

# Example 1: YAIR
Iterative_Attack("EQQB", "YAIR", "road", "door")

print("\n" + "="*40 + "\n")

# Example 2: MATAN
Iterative_Attack("EYRCVJ", "MATAN", "road", "door")


print("\n" + "!" * 20)
print("FINAL RESULTS SUMMARY:")
for res in final_results:
    print(res)
print("!" * 20)