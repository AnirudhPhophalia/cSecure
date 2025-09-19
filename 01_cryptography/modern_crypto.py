import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def demonstrate_hashing():
    print("=== HASHING DEMONSTRATION ===")
    
    original_data = "This is sensitive data"
    print(f"Original data: {original_data}")
    
    # MD5 (weak)
    md5_hash = hashlib.md5(original_data.encode()).hexdigest()
    print(f"MD5 (WEAK):    {md5_hash}")
    
    # SHA-1 (deprecated)
    sha1_hash = hashlib.sha1(original_data.encode()).hexdigest()
    print(f"SHA-1 (WEAK):  {sha1_hash}")
    
    # SHA-256 (secure)
    sha256_hash = hashlib.sha256(original_data.encode()).hexdigest()
    print(f"SHA-256:       {sha256_hash}")
    
    # SHA-3 (latest)
    sha3_hash = hashlib.sha3_256(original_data.encode()).hexdigest()
    print(f"SHA3-256:      {sha3_hash}")
    
    # Demonstrate hash collision resistance
    print("\n--- Hash Collision Resistance ---")
    similar_data = "This is sensitive datA"  # Note the capital A
    print(f"Similar data:  {similar_data}")
    similar_hash = hashlib.sha256(similar_data.encode()).hexdigest()
    print(f"SHA-256:       {similar_hash}")
    print(f"Same hash?     {sha256_hash == similar_hash}")
    print()

def generate_key_from_password(password, salt=None):
    """Generate encryption key from password using PBKDF2"""
    if salt is None:
        salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Recommended minimum
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def symmetric_encryption_demo():
    print("=== SYMMETRIC ENCRYPTION (AES) ===")
    
    # Generate a random key
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    
    plaintext = "Secret message for symmetric encryption demo"
    print(f"Plaintext:  {plaintext}")
    print(f"Key:        {key.decode()}")
    
    # Encryption
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    print(f"Encrypted:  {ciphertext.decode()}")
    
    # Decryption
    decrypted = cipher_suite.decrypt(ciphertext)
    print(f"Decrypted:  {decrypted.decode()}")
    print()

def password_based_encryption_demo():
    print("=== PASSWORD-BASED ENCRYPTION ===")
    
    password = "MyStrongPassword123!"
    plaintext = "This message is encrypted with a password"
    
    print(f"Password:   {password}")
    print(f"Plaintext:  {plaintext}")
    
    # Generate key from password
    key, salt = generate_key_from_password(password)
    print(f"Salt:       {base64.b64encode(salt).decode()}")
    
    # Encrypt
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    print(f"Encrypted:  {ciphertext.decode()}")
    
    # Decrypt (simulate receiving encrypted data)
    # We need the same password and salt to derive the same key
    derived_key, _ = generate_key_from_password(password, salt)
    decrypt_suite = Fernet(derived_key)
    decrypted = decrypt_suite.decrypt(ciphertext)
    print(f"Decrypted:  {decrypted.decode()}")
    print()

def hash_comparison_attack():
    print("=== HASH ATTACK SIMULATION ===")
    
    # Simulated stored password hashes (no salt)
    stored_passwords = {
        "admin": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",  # "admin"
        "user1": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",  # "secret123"
        "user2": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # "password"
    }
    
    print("Stored password hashes (unsalted - VULNERABLE):")
    for user, hash_val in stored_passwords.items():
        print(f"{user}: {hash_val}")
    
    # Common passwords for dictionary attack
    common_passwords = ["admin", "password", "123456", "secret", "secret123", "letmein"]
    
    print("\n--- Dictionary Attack ---")
    print("Trying common passwords...")
    
    for password in common_passwords:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"Trying '{password}': {password_hash}")
        
        # Check if this hash matches any stored hash
        for user, stored_hash in stored_passwords.items():
            if password_hash == stored_hash:
                print(f"  *** CRACKED! User '{user}' has password '{password}' ***")
    
    print("\n--- Why Salting Helps ---")
    salt = secrets.token_hex(16)
    password = "password"
    salted_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    
    print(f"Password: {password}")
    print(f"Salt: {salt}")
    print(f"Salted hash: {salted_hash}")
    print("Even with the same password, different salts produce different hashes!")
    print()

def digital_signature_simulation():
    print("=== DIGITAL SIGNATURE SIMULATION ===")
    print("Note: This is a simplified demonstration, not actual cryptographic signatures")
    
    message = "This document needs to be signed"
    private_key = "super_secret_private_key_123"
    
    print(f"Message: {message}")
    print(f"Private key: {private_key}")
    
    # Create "signature" by hashing message with private key
    signature_data = message + private_key
    signature = hashlib.sha256(signature_data.encode()).hexdigest()
    
    print(f"Signature: {signature}")
    
    # Verification process
    print("\n--- Verification Process ---")
    received_message = "This document needs to be signed"
    received_signature = signature
    public_key = private_key  # In real crypto, these would be different!
    
    # Verify by recreating signature
    verify_data = received_message + public_key
    expected_signature = hashlib.sha256(verify_data.encode()).hexdigest()
    
    is_valid = received_signature == expected_signature
    print(f"Signature valid: {is_valid}")
    
    # Test with tampered message
    print("\n--- Testing Tampered Message ---")
    tampered_message = "This document needs to be signed!!!"
    tampered_data = tampered_message + public_key
    tampered_signature = hashlib.sha256(tampered_data.encode()).hexdigest()
    
    is_tampered_valid = received_signature == tampered_signature
    print(f"Tampered message: {tampered_message}")
    print(f"Signature still valid: {is_tampered_valid}")
    print()

def main():
    print("=== MODERN CRYPTOGRAPHY ===\n")

    try:
        demonstrate_hashing()
        symmetric_encryption_demo()
        password_based_encryption_demo()
        hash_comparison_attack()
        digital_signature_simulation()
        
        print("=== SECURITY BEST PRACTICES ===")
        print("1. Use strong hashing algorithms (SHA-256, SHA-3)")
        print("2. Always use salt for password hashing")
        print("3. Use key derivation functions (PBKDF2, scrypt, Argon2)")
        print("4. Never store passwords in plain text")
        print("5. Use authenticated encryption (AES-GCM)")
        print("6. Keep private keys secure and never share them")
        print("7. Use proper random number generation")
        
    except ImportError as e:
        print(f"Error: {e}")
        print("\nTo run this script, install the cryptography library:")
        print("pip install cryptography")

if __name__ == "__main__":
    main()