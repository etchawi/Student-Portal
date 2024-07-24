def caesar_decrypt(ciphertext, shift):
    decrypted_text = ''
    for char in ciphertext:
        if char.isalpha():  # Check if the character is a letter
            shifted = ord(char) - shift
            if shifted < ord('A'):
                shifted += 26
            decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text

ciphertext = "TEBKFKQEBZLROPBLCERJXKBSBKQP"

# Try all possible shifts from 1 to 25 and print the outputs
for shift in range(1, 26):
    plaintext = caesar_decrypt(ciphertext, shift)
    print(f"Shift {shift}: {plaintext}")
