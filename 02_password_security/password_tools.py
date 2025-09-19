import random
import string
import hashlib
import time
import re
from itertools import product

class PasswordAnalyzer:
    def __init__(self):
        # Common weak passwords for demonstration
        self.common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "password1",
            "abc123", "Password1", "welcome123", "admin123", "root"
        ]
        
        # Common password patterns
        self.weak_patterns = [
            r'^[a-z]+$',           # Only lowercase
            r'^[A-Z]+$',           # Only uppercase  
            r'^\d+$',              # Only numbers
            r'^[a-zA-Z]+$',        # Only letters
            r'^.{1,6}$',           # Too short
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk)',  # Sequential letters
            r'(.)\1{2,}',          # Repeated characters (aaa, 111, etc.)
        ]

    def check_strength(self, password):
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 25
            feedback.append("Good length (12+ characters)")
        elif len(password) >= 8:
            score += 15
            feedback.append("Acceptable length (8+ characters)")
        else:
            feedback.append("Too short (use 12+ characters)")
        
        # Character variety checks
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        variety_count = sum([has_lower, has_upper, has_digit, has_special])
        
        if variety_count == 4:
            score += 25
            feedback.append("Excellent character variety")
        elif variety_count == 3:
            score += 20
            feedback.append("Good character variety")
        elif variety_count == 2:
            score += 10
            feedback.append("Basic character variety")
        else:
            feedback.append("Poor character variety")
        
        # Check against common passwords
        if password.lower() in [p.lower() for p in self.common_passwords]:
            feedback.append("This is a common password!")
        else:
            score += 20
            feedback.append("Not a common password")
        
        # Check for weak patterns
        weak_pattern_found = False
        for pattern in self.weak_patterns:
            if re.search(pattern, password):
                weak_pattern_found = True
                break
        
        if not weak_pattern_found:
            score += 15
            feedback.append("No obvious weak patterns")
        else:
            feedback.append("Contains weak patterns")

        # Entropy calculation (simplified)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        
        if charset_size > 0:
            entropy = len(password) * (charset_size.bit_length() - 1)
            if entropy >= 60:
                score += 15
                feedback.append(f"High entropy ({entropy} bits)")
            elif entropy >= 40:
                score += 10
                feedback.append(f"Moderate entropy ({entropy} bits)")
            else:
                feedback.append(f"Low entropy ({entropy} bits)")
        
        # Determine overall strength
        if score >= 85:
            strength = "VERY STRONG"
        elif score >= 70:
            strength = "STRONG"
        elif score >= 50:
            strength = "MODERATE"
        elif score >= 30:
            strength = "WEAK"
        else:
            strength = "VERY WEAK"
        
        return {
            'score': score,
            'strength': strength,
            'feedback': feedback
        }

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*(),.?\":{}|<>"
    
    def generate_secure_password(self, length=16, use_symbols=True):
        """Generate a cryptographically secure password"""
        charset = self.lowercase + self.uppercase + self.digits
        if use_symbols:
            charset += self.special_chars
        
        # Ensure at least one character from each category
        password = [
            random.choice(self.lowercase),
            random.choice(self.uppercase),
            random.choice(self.digits)
        ]
        
        if use_symbols:
            password.append(random.choice(self.special_chars))
        
        # Fill remaining length with random characters
        for _ in range(length - len(password)):
            password.append(random.choice(charset))
        
        # Shuffle to avoid predictable patterns
        random.shuffle(password)
        return ''.join(password)
    
    def generate_memorable_password(self, num_words=4):
        """Generate a memorable passphrase using word combinations"""
        # Simple word list for demonstration
        words = [
            "bhagya", "doctor", "tanay", "bewtra", "khag", "endra", "ram",
            "dr", "anushka", "ak", "verma", "ishw", "inder", "argh", "chirag", "utk", "vani", "vaani",
            "dhiren", "amish", "abhi", "rohin", "raghav", "naman",
            "jindal", "aarav", "arora", "vri", "shank", "dkash"
        ]
        
        selected_words = random.sample(words, num_words)
        
        # Add numbers and capitalize randomly
        for i in range(len(selected_words)):
            if random.choice([True, False]):
                selected_words[i] = selected_words[i].capitalize()
        
        # Insert random numbers
        passphrase = []
        for word in selected_words:
            passphrase.append(word)
            if random.choice([True, False]):
                passphrase.append(str(random.randint(0, 99)))
        
        return '-'.join(passphrase)

class PasswordCracker:
    def __init__(self):
        self.attempts = 0
        self.start_time = 0
    
    def dictionary_attack(self, target_hash, hash_algorithm='sha256'):
        print("=== DICTIONARY ATTACK SIMULATION ===")
        
        # Common passwords for attack
        dictionary = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "password1",
            "abc123", "Password1", "welcome123", "admin123", "root",
            "test", "guest", "user", "login", "pass", "secret"
        ]
        
        self.attempts = 0
        self.start_time = time.time()
        
        print(f"Target hash: {target_hash}")
        print(f"Dictionary size: {len(dictionary)} passwords")
        print("Attempting to crack...\n")
        
        for password in dictionary:
            self.attempts += 1
            
            # Hash the password attempt
            if hash_algorithm == 'md5':
                attempt_hash = hashlib.md5(password.encode()).hexdigest()
            else:
                attempt_hash = hashlib.sha256(password.encode()).hexdigest()
            
            print(f"Attempt {self.attempts}: '{password}' -> {attempt_hash}")
            
            if attempt_hash == target_hash:
                elapsed_time = time.time() - self.start_time
                print(f"\n*** PASSWORD CRACKED! ***")
                print(f"Password: '{password}'")
                print(f"Attempts: {self.attempts}")
                print(f"Time: {elapsed_time:.2f} seconds")
                return password
            
            # Small delay to make it visible
            time.sleep(0.1)
        
        print(f"\nPassword not found in dictionary after {self.attempts} attempts")
        return None
    
    def brute_force_attack(self, target_hash, max_length=4, charset="0123456789"):
        print("=== BRUTE FORCE ATTACK SIMULATION ===")
        print("Note: Limited to short passwords for demonstration purposes")
        
        self.attempts = 0
        self.start_time = time.time()
        
        print(f"Target hash: {target_hash}")
        print(f"Character set: {charset}")
        print(f"Max length: {max_length}")
        print("Attempting to crack...\n")
        
        for length in range(1, max_length + 1):
            print(f"Trying length {length}...")
            
            for attempt in product(charset, repeat=length):
                self.attempts += 1
                password = ''.join(attempt)
                
                attempt_hash = hashlib.sha256(password.encode()).hexdigest()
                
                if self.attempts % 100 == 0:  # Show progress every 100 attempts
                    print(f"  Attempt {self.attempts}: '{password}'")
                
                if attempt_hash == target_hash:
                    elapsed_time = time.time() - self.start_time
                    print(f"\n*** PASSWORD CRACKED! ***")
                    print(f"Password: '{password}'")
                    print(f"Attempts: {self.attempts}")
                    print(f"Time: {elapsed_time:.2f} seconds")
                    return password
                
                # Stop if too many attempts (for demo purposes)
                if self.attempts > 1000:
                    print(f"\nStopping after {self.attempts} attempts (demo limit)")
                    return None
        
        print(f"\nPassword not found after {self.attempts} attempts")
        return None

def main():
    """Main function demonstrating all password security concepts"""
    print("=== PASSWORD SECURITY LEARNING TOOL ===\n")
    
    analyzer = PasswordAnalyzer()
    generator = PasswordGenerator()
    cracker = PasswordCracker()
    
    # 1. Password Strength Analysis
    print("1. PASSWORD STRENGTH ANALYSIS")
    test_passwords = [
        "123456",
        "password",
        "Password123",
        "MyStr0ng!P@ssw0rd2024",
        "correct-horse-battery-staple"
    ]
    
    for pwd in test_passwords:
        print(f"\nAnalyzing: '{pwd}'")
        result = analyzer.check_strength(pwd)
        print(f"Strength: {result['strength']} (Score: {result['score']}/100)")
        for feedback in result['feedback']:
            print(f"  {feedback}")
    
    print("\n" + "="*50)
    
    # 2. Secure Password Generation
    print("\n2. SECURE PASSWORD GENERATION")
    
    print("\nGenerated secure passwords:")
    for i in range(3):
        secure_pwd = generator.generate_secure_password(16, True)
        print(f"Password {i+1}: {secure_pwd}")
        result = analyzer.check_strength(secure_pwd)
        print(f"  Strength: {result['strength']}")
    
    print("\nGenerated memorable passphrases:")
    for i in range(3):
        memorable_pwd = generator.generate_memorable_password(4)
        print(f"Passphrase {i+1}: {memorable_pwd}")
        result = analyzer.check_strength(memorable_pwd)
        print(f"  Strength: {result['strength']}")
    
    print("\n" + "="*50)
    
    # 3. Password Cracking Demonstration
    print("\n3. PASSWORD CRACKING DEMONSTRATION")
    
    # Create a weak password hash for demonstration
    weak_password = "admin"
    target_hash = hashlib.sha256(weak_password.encode()).hexdigest()
    
    print(f"Let's crack a weak password...")
    print(f"(The password is '{weak_password}' for this demo)")
    print()
    
    # Dictionary attack
    cracked = cracker.dictionary_attack(target_hash)
    
    print("\n" + "-"*30)
    
    # Brute force on numeric password
    numeric_password = "1234"
    numeric_hash = hashlib.sha256(numeric_password.encode()).hexdigest()
    
    print(f"\nNow let's try brute force on a numeric password...")
    print(f"(The password is '{numeric_password}' for this demo)")
    print()
    
    cracked_numeric = cracker.brute_force_attack(numeric_hash, 4, "0123456789")
    
    print("\n" + "="*50)
    
    # 4. Interactive Mode
    print("\n4. INTERACTIVE MODE")
    while True:
        print("\nChoose an option:")
        print("1. Analyze password strength")
        print("2. Generate secure password")
        print("3. Generate memorable passphrase") 
        print("4. Exit")
        
        choice = input("Your choice (1-4): ")
        
        if choice == '1':
            password = input("Enter password to analyze: ")
            result = analyzer.check_strength(password)
            print(f"\nStrength: {result['strength']} (Score: {result['score']}/100)")
            print("Feedback:")
            for feedback in result['feedback']:
                print(f"  {feedback}")
                
        elif choice == '2':
            length = input("Enter password length (default 16): ")
            try:
                length = int(length) if length else 16
                use_symbols = input("Use symbols? (y/n, default y): ").lower()
                use_symbols = use_symbols != 'n'
                
                password = generator.generate_secure_password(length, use_symbols)
                print(f"Generated password: {password}")
                
                result = analyzer.check_strength(password)
                print(f"Strength: {result['strength']}")
                
            except ValueError:
                print("Invalid length!")
                
        elif choice == '3':
            num_words = input("Number of words (default 4): ")
            try:
                num_words = int(num_words) if num_words else 4
                passphrase = generator.generate_memorable_password(num_words)
                print(f"Generated passphrase: {passphrase}")
                
                result = analyzer.check_strength(passphrase)
                print(f"Strength: {result['strength']}")
                
            except ValueError:
                print("Invalid number!")
                
        elif choice == '4':
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()