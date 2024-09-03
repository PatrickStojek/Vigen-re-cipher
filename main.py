def char_to_index(c):
    return ord(c.upper()) - ord('A')

def index_to_char(i):
    return chr(i + ord('A'))

def vigenere_encrypt(plaintext, keyword):
    plaintext = plaintext.upper()
    keyword = keyword.upper()
    ciphertext = []
    keyword_length = len(keyword)
    
    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            p = char_to_index(char)
            k = char_to_index(keyword[i % keyword_length])
            c = (p + k) % 26
            ciphertext.append(index_to_char(c))
        else:
            ciphertext.append(char)
    
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, keyword):
    ciphertext = ciphertext.upper()
    keyword = keyword.upper()
    plaintext = []
    keyword_length = len(keyword)
    
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            c = char_to_index(char)
            k = char_to_index(keyword[i % keyword_length])
            p = (c - k) % 26
            plaintext.append(index_to_char(p))
        else:
            plaintext.append(char)
    
    return ''.join(plaintext)

# Example usage
keyword = "KEY"
plaintext = "HELLO WORLD"
ciphertext = vigenere_encrypt(plaintext, keyword)
decrypted_text = vigenere_decrypt(ciphertext, keyword)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {decrypted_text}")
