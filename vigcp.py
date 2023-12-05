def encrypt(plaintext, key):
    ciphertext = ''
    key_len = len(key)
    plaintext_len = len(plaintext)

    for i in range(plaintext_len):
        plaintext_ord = ord(plaintext[i])
        key_ord = ord(key[i % key_len])
        encrypted_char = chr((plaintext_ord ^ key_ord) % 256)
        ciphertext += encrypted_char

    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ''
    key_len = len(key)
    ciphertext_len = len(ciphertext)

    for i in range(ciphertext_len):
        ciphertext_ord = ord(ciphertext[i])
        key_ord = ord(key[i % key_len])
        decrypted_char = chr((ciphertext_ord ^ key_ord) % 256)
        plaintext += decrypted_char

    return plaintext

# Function to convert a string to binary
def string_to_binary(s):
    return ''.join(format(ord(c), '08b') for c in s)

# Example usage
plaintext = input("Plaintext: ")
key = input("Key: ")

chiper_text = encrypt(plaintext, key)
plaint_text = decrypt(chiper_text, key)

# Display binary representation
print(f'Binary  plaintext: {string_to_binary(plaintext)}')
print(f'Binary  key: {string_to_binary(key)}')
print(f'Encrypted text: {chiper_text}')
print(f'Binary  ciphertext: {string_to_binary(chiper_text)}')
print(f'Dekripsi text (Plaintext): {plaint_text}')

