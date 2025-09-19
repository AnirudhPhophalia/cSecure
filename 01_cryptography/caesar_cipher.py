def caesar_encrypt(text, shift):
    result = ""
    
    for char in text:
        if char.isalpha():
            # Determine if uppercase or lowercase
            ascii_offset = ord('A') if char.isupper() else ord('a')
            # Shift character and wrap around using modulo
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def brute_force_caesar(encrypted_text):
    results = {}
    
    print("=== BRUTE FORCE ATTACK ===")
    print("Trying all possible shifts (0-25):\n")
    
    for shift in range(26):
        decrypted = caesar_decrypt(encrypted_text, shift)
        results[shift] = decrypted
        print(f"Shift {shift:2d}: {decrypted}")
    
    return results

def analyze_frequency(text):
    frequency = {}
    text = text.upper().replace(' ', '')
    
    for char in text:
        if char.isalpha():
            frequency[char] = frequency.get(char, 0) + 1
    
    # Sort by frequency (most common first)
    return dict(sorted(frequency.items(), key=lambda x: x[1], reverse=True))

def main():
    print("=== CAESAR CIPHER ===\n")
    
    # Basic encryption/decryption
    original_message = "Hello, World! This is a secret message."
    shift_key = 3
    
    print("1. BASIC ENCRYPTION/DECRYPTION")
    print(f"Original message: {original_message}")
    print(f"Shift key: {shift_key}")
    
    encrypted = caesar_encrypt(original_message, shift_key)
    print(f"Encrypted: {encrypted}")
    
    decrypted = caesar_decrypt(encrypted, shift_key)
    print(f"Decrypted: {decrypted}")
    print()
    
    # Brute force attack
    print("2. CRYPTANALYSIS - BRUTE FORCE ATTACK")
    secret_message = "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
    print(f"Intercepted message: {secret_message}")
    brute_force_caesar(secret_message)
    print()
    
    # Frequency analysis
    print("3. FREQUENCY ANALYSIS")
    test_text = "ATTACKATDAWN"
    frequencies = analyze_frequency(test_text)
    print(f"Text: {test_text}")
    print("Character frequencies:")
    for char, count in frequencies.items():
        print(f"  {char}: {count}")
    print()
    
    # Interactive mode
    print("4. INTERACTIVE MODE")
    while True:
        choice = input("\nChoose an option:\n1. Encrypt\n2. Decrypt\n3. Brute force\n4. Exit\nYour choice: ")
        
        if choice == '1':
            message = input("Enter message to encrypt: ")
            try:
                shift = int(input("Enter shift value (0-25): "))
                if 0 <= shift <= 25:
                    result = caesar_encrypt(message, shift)
                    print(f"Encrypted: {result}")
                else:
                    print("Shift must be between 0 and 25!")
            except ValueError:
                print("Please enter a valid number!")
                
        elif choice == '2':
            message = input("Enter message to decrypt: ")
            try:
                shift = int(input("Enter shift value (0-25): "))
                if 0 <= shift <= 25:
                    result = caesar_decrypt(message, shift)
                    print(f"Decrypted: {result}")
                else:
                    print("Shift must be between 0 and 25!")
            except ValueError:
                print("Please enter a valid number!")
                
        elif choice == '3':
            message = input("Enter encrypted message to break: ")
            brute_force_caesar(message)
            
        elif choice == '4':
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()