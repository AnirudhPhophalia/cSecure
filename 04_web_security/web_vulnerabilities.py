import sqlite3
import html
import re
import hashlib
import secrets
import urllib.parse

class VulnerableWebApp:
    def __init__(self):
        self.setup_database()
        self.sessions = {}
    
    def setup_database(self):
        """Create a simple database for demonstration"""
        self.conn = sqlite3.connect(':memory:')
        cursor = self.conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                email TEXT,
                role TEXT
            )
        ''')
        
        # Insert sample data
        sample_users = [
            ('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'admin@example.com', 'admin'),
            ('user1', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'user1@example.com', 'user'),
            ('user2', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', 'user2@example.com', 'user'),
        ]
        
        cursor.executemany('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', sample_users)
        
        # Create posts table for XSS demo
        cursor.execute('''
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY,
                title TEXT,
                content TEXT,
                author TEXT
            )
        ''')
        
        self.conn.commit()
        print("Database initialized with sample data:")
        print("Users: admin/password, user1/secret123, user2/hello")

class SQLInjectionDemo:
    
    def __init__(self, webapp):
        self.webapp = webapp
    
    def vulnerable_login(self, username, password):
        print("\n=== VULNERABLE LOGIN ATTEMPT ===")
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        # VULNERABLE: Direct string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.sha256(password.encode()).hexdigest()}'"
        print(f"SQL Query: {query}")
        
        try:
            cursor = self.webapp.conn.cursor()
            cursor.execute(query)
            result = cursor.fetchone()
            
            if result:
                print(f"✓ Login successful! Welcome {result[1]} (Role: {result[4]})")
                return True
            else:
                print("✗ Login failed!")
                return False
                
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            return False
    
    def secure_login(self, username, password):
        print("\n=== SECURE LOGIN ATTEMPT ===")
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        # SECURE: Parameterized query
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"SQL Query: {query}")
        print(f"Parameters: ['{username}', '{password_hash}']")
        
        try:
            cursor = self.webapp.conn.cursor()
            cursor.execute(query, (username, password_hash))
            result = cursor.fetchone()
            
            if result:
                print(f"✓ Login successful! Welcome {result[1]} (Role: {result[4]})")
                return True
            else:
                print("✗ Login failed!")
                return False
                
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")
            return False
    
    def demonstrate_sql_injection(self):
        """Show various SQL injection techniques"""
        print("\n" + "="*50)
        print("SQL INJECTION DEMONSTRATION")
        print("="*50)
        
        print("\n1. NORMAL LOGIN ATTEMPTS")
        print("-" * 30)
        
        # Normal login attempts
        self.vulnerable_login("admin", "password")
        self.vulnerable_login("admin", "wrongpassword")
        
        print("\n2. SQL INJECTION ATTACKS")
        print("-" * 30)
        
        # SQL Injection: Bypass authentication
        print("\nAttack 1: Authentication Bypass")
        self.vulnerable_login("admin' --", "anything")
        
        print("\nAttack 2: Union-based injection")
        self.vulnerable_login("admin' UNION SELECT 1,2,3,4,5 --", "anything")
        
        print("\nAttack 3: Always true condition")
        self.vulnerable_login("' OR '1'='1", "' OR '1'='1")
        
        print("\n3. SECURE LOGIN COMPARISON")
        print("-" * 30)
        
        print("\nSame attacks against secure function:")
        self.secure_login("admin' --", "anything")
        self.secure_login("' OR '1'='1", "' OR '1'='1")
        
        print("\nNormal login with secure function:")
        self.secure_login("admin", "password")

class XSSDemo:
    
    def __init__(self):
        self.posts = []
    
    def vulnerable_add_post(self, title, content, author):
        print("\n=== VULNERABLE POST SUBMISSION ===")
        print(f"Title: {title}")
        print(f"Content: {content}")
        print(f"Author: {author}")
        
        # VULNERABLE: Direct storage without sanitization
        post = {
            'id': len(self.posts) + 1,
            'title': title,
            'content': content,
            'author': author
        }
        
        self.posts.append(post)
        print("✓ Post added successfully!")
        return post['id']
    
    def secure_add_post(self, title, content, author):
        print("\n=== SECURE POST SUBMISSION ===")
        print(f"Original Title: {title}")
        print(f"Original Content: {content}")
        print(f"Original Author: {author}")
        
        # SECURE: HTML escape all user input
        sanitized_title = html.escape(title)
        sanitized_content = html.escape(content)
        sanitized_author = html.escape(author)
        
        print(f"Sanitized Title: {sanitized_title}")
        print(f"Sanitized Content: {sanitized_content}")
        print(f"Sanitized Author: {sanitized_author}")
        
        post = {
            'id': len(self.posts) + 1,
            'title': sanitized_title,
            'content': sanitized_content,
            'author': sanitized_author
        }
        
        self.posts.append(post)
        print("✓ Post added securely!")
        return post['id']
    
    def display_posts(self):
        print("\n=== BLOG POSTS DISPLAY ===")
        if not self.posts:
            print("No posts available.")
            return
        
        for post in self.posts:
            print(f"\n--- Post {post['id']} ---")
            print(f"Title: {post['title']}")
            print(f"Author: {post['author']}")
            print(f"Content: {post['content']}")
    
    def demonstrate_xss(self):
        print("\n" + "="*50)
        print("CROSS-SITE SCRIPTING (XSS) DEMONSTRATION")
        print("="*50)
        
        print("\n1. NORMAL POST SUBMISSION")
        print("-" * 30)
        self.vulnerable_add_post("Welcome Post", "Hello everyone!", "admin")
        
        print("\n2. XSS ATTACK ATTEMPTS")
        print("-" * 30)
        
        # Reflected XSS
        print("\nAttack 1: Basic Script Injection")
        self.vulnerable_add_post(
            "Malicious Post",
            "<script>alert('XSS Attack!');</script>",
            "attacker"
        )
        
        # Image XSS
        print("\nAttack 2: Image-based XSS")
        self.vulnerable_add_post(
            "Image Post",
            '<img src="x" onerror="alert(\'Image XSS\')">',
            "attacker"
        )
        
        # Event handler XSS
        print("\nAttack 3: Event Handler XSS")
        self.vulnerable_add_post(
            "Event Post",
            '<div onmouseover="alert(\'Event XSS\')">Hover me!</div>',
            "attacker"
        )
        
        print("\n3. SECURE POST SUBMISSION")
        print("-" * 30)
        
        print("\nSame attacks against secure function:")
        self.secure_add_post(
            "Malicious Post",
            "<script>alert('XSS Attack!');</script>",
            "attacker"
        )
        
        print("\n4. DISPLAYING POSTS")
        print("-" * 30)
        print("Note: In a real web app, the malicious scripts would execute in users' browsers!")
        self.display_posts()

class InputValidationDemo:
    
    def __init__(self):
        pass
    
    def validate_email(self, email):
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_password(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    def sanitize_filename(self, filename):
        """Sanitize filename to prevent directory traversal"""
        # Remove dangerous characters and path separators
        sanitized = re.sub(r'[<>:"/\\|?*]', '', filename)
        sanitized = sanitized.replace('..', '')
        sanitized = sanitized.strip('. ')
        
        return sanitized if sanitized else 'unnamed_file'
    
    def demonstrate_validation(self):
        """Demonstrate various input validation techniques"""
        print("\n" + "="*50)
        print("INPUT VALIDATION DEMONSTRATION")
        print("="*50)
        
        print("\n1. EMAIL VALIDATION")
        print("-" * 30)
        
        test_emails = [
            "user@example.com",
            "invalid.email",
            "user@domain",
            "user.name+tag@example.co.uk",
            "user@",
            "@domain.com"
        ]
        
        for email in test_emails:
            is_valid = self.validate_email(email)
            status = "✓ VALID" if is_valid else "✗ INVALID"
            print(f"{email:<30} {status}")
        
        print("\n2. PASSWORD VALIDATION")
        print("-" * 30)
        
        test_passwords = [
            "password",
            "Password123",
            "Pass123!",
            "VeryStrongP@ssw0rd",
            "123456",
            "Abc1!"
        ]
        
        for password in test_passwords:
            is_valid, message = self.validate_password(password)
            status = "✓ VALID" if is_valid else "✗ INVALID"
            print(f"{password:<20} {status} - {message}")
        
        print("\n3. FILENAME SANITIZATION")
        print("-" * 30)
        
        test_filenames = [
            "document.pdf",
            "../../../etc/passwd",
            "file<script>.txt",
            "normal_file_123.doc",
            "con.txt",  # Reserved name on Windows
            "file|with|pipes.txt"
        ]
        
        for filename in test_filenames:
            sanitized = self.sanitize_filename(filename)
            print(f"Original:  {filename}")
            print(f"Sanitized: {sanitized}")
            print()

def demonstrate_secure_practices():
    """Demonstrate secure coding practices"""
    print("\n" + "="*50)
    print("SECURE CODING PRACTICES")
    print("="*50)
    
    print("\n1. SECURE SESSION MANAGEMENT")
    print("-" * 30)
    
    # Generate secure session token
    session_token = secrets.token_urlsafe(32)
    print(f"Secure session token: {session_token}")
    
    print("\n2. SECURE PASSWORD HASHING")
    print("-" * 30)
    
    password = "user_password_123"
    
    # Bad: Plain text storage
    print(f"Plain text (BAD): {password}")
    
    # Bad: Simple MD5
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    print(f"MD5 hash (BAD): {md5_hash}")
    
    # Better: SHA-256 with salt
    salt = secrets.token_hex(16)
    sha256_salted = hashlib.sha256((password + salt).encode()).hexdigest()
    print(f"SHA-256 + salt (BETTER): {sha256_salted}")
    print(f"Salt: {salt}")
    
    print("\n3. SECURE URL PARAMETER HANDLING")
    print("-" * 30)
    
    # Demonstrate URL encoding
    user_input = "user input with spaces & special chars"
    encoded = urllib.parse.quote(user_input)
    print(f"Original: {user_input}")
    print(f"URL encoded: {encoded}")
    print(f"Decoded: {urllib.parse.unquote(encoded)}")
    
    print("\n4. CONTENT SECURITY POLICY (CSP) EXAMPLE")
    print("-" * 30)
    
    csp_header = "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    print(f"CSP Header: {csp_header}")
    print("This header helps prevent XSS attacks by controlling resource loading.")

def main():
    """Main function demonstrating all web security concepts"""
    print("=== WEB SECURITY===")
    
    # Initialize components
    webapp = VulnerableWebApp()
    sql_demo = SQLInjectionDemo(webapp)
    xss_demo = XSSDemo()
    validation_demo = InputValidationDemo()
    
    while True:
        print("\nChoose a demonstration:")
        print("1. SQL Injection")
        print("2. Cross-Site Scripting (XSS)")
        print("3. Input Validation")
        print("4. Secure Coding Practices")
        print("5. Run all demonstrations")
        print("6. Exit")
        
        choice = input("Your choice (1-6): ")
        
        if choice == '1':
            sql_demo.demonstrate_sql_injection()
        elif choice == '2':
            xss_demo.demonstrate_xss()
        elif choice == '3':
            validation_demo.demonstrate_validation()
        elif choice == '4':
            demonstrate_secure_practices()
        elif choice == '5':
            print("Running all demonstrations...")
            sql_demo.demonstrate_sql_injection()
            xss_demo.demonstrate_xss()
            validation_demo.demonstrate_validation()
            demonstrate_secure_practices()
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()