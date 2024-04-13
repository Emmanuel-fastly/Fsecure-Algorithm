from fsecure import encrypt, decrypt


def Test_Fsecure():
    master_key = "Nei! var jhor du"  # Example master key
    message = "Hello, World!123"  # Example string (must be 16 characters)

    # Ensure the string is exactly 16 bytes
    if len(message) != 16:
        raise ValueError("Input string must be exactly 16 characters long.")

    # Convert master key to integer
    master_key = int.from_bytes(master_key.encode("utf-8"), byteorder="big")

    # Convert string to bytes, then to a single integer for encryption
    plaintext_bytes = message.encode("utf-8")
    plaintext = int.from_bytes(plaintext_bytes, byteorder="big")

    # Encrypt and decrypt
    ciphertext = encrypt(plaintext, master_key)
    decrypted_plaintext = decrypt(ciphertext, master_key)

    # Convert decrypted plaintext back to string
    decrypted_bytes = decrypted_plaintext.to_bytes(16, byteorder="big")
    decrypted_string = decrypted_bytes.decode("utf-8")

    print("Original string:", message)
    print("Encrypted:", hex(ciphertext))
    print("Decrypted string:", decrypted_string)

    assert message == decrypted_string
    print("Decryption successful!")


if __name__ == "__main__":
    Test_Fsecure()
