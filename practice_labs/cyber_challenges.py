import hashlib
import base64
import random
import string
import json
import os
from datetime import datetime, timedelta

class CTFChallenge:
    """Capture The Flag style cybersecurity challenges"""
    
    def __init__(self):
        self.challenges = {
            'crypto1': {
                'title': 'Basic Caesar Cipher',
                'description': 'Decrypt this message: "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"',
                'hint': 'The shift value is 3',
                'solution': 'The quick brown fox jumps over the lazy dog',
                'points': 10
            },
            'crypto2': {
                'title': 'Base64 Encoding',
                'description': 'Decode this Base64 string: "Q3liZXJTZWN1cml0eUlzRnVu"',
                'hint': 'Use Base64 decoding',
                'solution': 'CyberSecurityIsFun',
                'points': 15
            },
            'crypto3': {
                'title': 'Hash Identification',
                'description': 'What is the original word for this MD5 hash: "5d41402abc4b2a76b9719d911017c592"',
                'hint': 'It\'s a common English word',
                'solution': 'hello',
                'points': 20
            },
            'web1': {
                'title': 'Basic SQL Injection',
                'description': 'What SQL injection payload bypasses authentication with username "admin"?',
                'hint': 'Comment out the password check',
                'solution': "admin' --",
                'points': 25
            },
            'forensics1': {
                'title': 'Hidden Message',
                'description': 'Find the hidden message in this string: "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBoaWRkZW4gbWVzc2FnZQ=="',
                'hint': 'Decode from Base64',
                'solution': 'Hello World! This is a hidden message',
                'points': 15
            }
        }
        
        self.user_progress = {}
    
    def list_challenges(self):
        """List all available challenges"""
        print("=== CYBERSECURITY CTF CHALLENGES ===")
        print("Challenge ID | Title | Points")
        print("-" * 40)
        
        for challenge_id, challenge in self.challenges.items():
            print(f"{challenge_id:12} | {challenge['title']:20} | {challenge['points']:3} pts")
    
    def get_challenge(self, challenge_id):
        """Get challenge details"""
        if challenge_id not in self.challenges:
            print("Challenge not found!")
            return None
        
        challenge = self.challenges[challenge_id]
        print(f"\n=== {challenge['title']} ===")
        print(f"Description: {challenge['description']}")
        print(f"Points: {challenge['points']}")
        
        return challenge
    
    def submit_flag(self, challenge_id, answer, username="player"):
        """Submit an answer for a challenge"""
        if challenge_id not in self.challenges:
            print("Challenge not found!")
            return False
        
        challenge = self.challenges[challenge_id]
        
        if answer.strip().lower() == challenge['solution'].lower():
            print(f" Correct! You earned {challenge['points']} points!")
            
            # Track progress
            if username not in self.user_progress:
                self.user_progress[username] = {'solved': [], 'total_points': 0}
            
            if challenge_id not in self.user_progress[username]['solved']:
                self.user_progress[username]['solved'].append(challenge_id)
                self.user_progress[username]['total_points'] += challenge['points']
            
            return True
        else:
            print(" Incorrect answer. Try again!")
            return False
    
    def show_hint(self, challenge_id):
        """Show hint for a challenge"""
        if challenge_id not in self.challenges:
            print("Challenge not found!")
            return
        
        print(f"💡 Hint: {self.challenges[challenge_id]['hint']}")
    
    def show_progress(self, username="player"):
        """Show user's progress"""
        if username not in self.user_progress:
            print("No progress recorded yet!")
            return
        
        progress = self.user_progress[username]
        total_challenges = len(self.challenges)
        solved_count = len(progress['solved'])
        
        print(f"\n=== PROGRESS FOR {username.upper()} ===")
        print(f"Challenges solved: {solved_count}/{total_challenges}")
        print(f"Total points: {progress['total_points']}")
        print("Solved challenges:")
        
        for challenge_id in progress['solved']:
            challenge = self.challenges[challenge_id]
            print(f"  ✓ {challenge_id}: {challenge['title']} ({challenge['points']} pts)")

class VulnerabilityLab:
    
    def __init__(self):
        self.vulnerable_code_samples = {
            'sql_injection': {
                'title': 'SQL Injection Vulnerability',
                'code': '''
                    def login(username, password):
                        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                        result = execute_query(query)
                        return result is not None
                ''',
                'vulnerability': 'Direct string concatenation allows SQL injection',
                'fix': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))'
            },
            'xss': {
                'title': 'Cross-Site Scripting (XSS)',
                'code': '''
                    @app.route('/comment', methods=['POST'])
                    def add_comment():
                        comment = request.form['comment']
                        return f"<div>User said: {comment}</div>"
                ''',
                'vulnerability': 'User input is directly inserted into HTML without sanitization',
                'fix': 'Escape HTML: html.escape(comment) or use template engines with auto-escaping'
            },
            'path_traversal': {
                'title': 'Path Traversal Vulnerability',
                'code': '''
                    @app.route('/file/<filename>')
                    def get_file(filename):
                        return send_from_directory('/uploads/', filename)
                ''',
                'vulnerability': 'No validation allows access to files outside intended directory',
                'fix': 'Validate filename: secure_filename(filename) and check if file exists in allowed directory'
            }
        }
    
    def show_vulnerable_code(self, vuln_type):
        """Display vulnerable code sample"""
        if vuln_type not in self.vulnerable_code_samples:
            print("Vulnerability type not found!")
            return
        
        sample = self.vulnerable_code_samples[vuln_type]
        print(f"\n=== {sample['title']} ===")
        print("Vulnerable Code:")
        print(sample['code'])
        print(f"\nVulnerability: {sample['vulnerability']}")
        print(f"Fix: {sample['fix']}")
    
    def list_vulnerabilities(self):
        """List all vulnerability samples"""
        print("=== VULNERABILITY LAB ===")
        print("Available vulnerability samples:")
        
        for vuln_type, sample in self.vulnerable_code_samples.items():
            print(f"- {vuln_type}: {sample['title']}")
    
    def vulnerability_quiz(self):
        print("\n=== VULNERABILITY IDENTIFICATION QUIZ ===")
        
        questions = [
            {
                'code': "password = input('Enter password: ')\nif password == 'admin123': login_success()",
                'question': "What security issue does this code have?",
                'answer': "hardcoded password",
                'explanation': "The password is hardcoded in the source code, making it visible to anyone who can read the code."
            },
            {
                'code': "user_input = input('Enter data: ')\nos.system(f'echo {user_input}')",
                'question': "What type of vulnerability is this?",
                'answer': "command injection",
                'explanation': "User input is directly passed to os.system() without validation, allowing command injection attacks."
            },
            {
                'code': "def hash_password(password):\n    return hashlib.md5(password.encode()).hexdigest()",
                'question': "What's wrong with this password hashing?",
                'answer': "weak hashing",
                'explanation': "MD5 is cryptographically broken and unsuitable for password hashing. Use bcrypt, scrypt, or Argon2 instead."
            }
        ]
        
        score = 0
        for i, q in enumerate(questions, 1):
            print(f"\nQuestion {i}:")
            print(f"Code: {q['code']}")
            print(f"Question: {q['question']}")
            
            answer = input("Your answer: ").strip().lower()
            
            if q['answer'].lower() in answer:
                print("✓ Correct!")
                print(f"Explanation: {q['explanation']}")
                score += 1
            else:
                print("✗ Incorrect.")
                print(f"Correct answer: {q['answer']}")
                print(f"Explanation: {q['explanation']}")
        
        print(f"\nQuiz completed! Score: {score}/{len(questions)}")

class ForensicsLab:
    
    def __init__(self):
        self.case_files = self._generate_mock_data()
    
    def _generate_mock_data(self):
        """Generate mock forensics data"""
        return {
            'web_logs': [
                '192.168.1.100 - - [20/Sep/2025:10:15:23] "GET /admin.php HTTP/1.1" 200 1234',
                '192.168.1.100 - - [20/Sep/2025:10:15:24] "POST /login.php HTTP/1.1" 302 0',
                '10.0.0.50 - - [20/Sep/2025:10:16:15] "GET /admin.php?id=1\' OR 1=1-- HTTP/1.1" 200 5678',
                '10.0.0.50 - - [20/Sep/2025:10:16:16] "GET /users.php HTTP/1.1" 200 9999',
                '172.16.0.25 - - [20/Sep/2025:10:17:30] "GET /upload.php HTTP/1.1" 200 1111',
                '172.16.0.25 - - [20/Sep/2025:10:17:31] "POST /upload.php HTTP/1.1" 200 0'
            ],
            'network_connections': [
                'TCP 192.168.1.100:1234 -> 8.8.8.8:53 ESTABLISHED',
                'TCP 192.168.1.100:5555 -> 198.51.100.50:443 ESTABLISHED',
                'TCP 10.0.0.50:6666 -> 203.0.113.75:80 TIME_WAIT',
                'UDP 172.16.0.25:7777 -> 192.0.2.100:53 ESTABLISHED'
            ],
            'file_hashes': {
                'suspicious.exe': 'a1b2c3d4e5f6789012345678901234567890abcd',
                'document.pdf': 'f1e2d3c4b5a6987654321098765432109876fedc',
                'system32.dll': '123456789abcdef0123456789abcdef012345678'
            }
        }
    
    def analyze_web_logs(self):
        """Analyze web server logs for suspicious activity"""
        print("=== WEB LOG ANALYSIS ===")
        print("Analyzing web server logs for suspicious patterns...\n")
        
        suspicious_patterns = [
            (r"'.*OR.*1=1", "SQL Injection attempt"),
            (r"<script", "XSS attempt"), 
            (r"\.\.\/", "Path traversal attempt"),
            (r"union.*select", "SQL Union injection"),
        ]
        
        for log_entry in self.case_files['web_logs']:
            print(f"Log: {log_entry}")
            
            # Check for suspicious patterns
            for pattern, attack_type in suspicious_patterns:
                import re
                if re.search(pattern, log_entry, re.IGNORECASE):
                    print(f" ALERT: {attack_type} detected!")
            
            # Extract IP and analyze
            ip = log_entry.split()[0]
            if ip.startswith('10.0.0.') or ip.startswith('172.16.'):
                print(f" Note: Internal IP address {ip}")
            
            print()
    
    def analyze_network_traffic(self):
        print("=== NETWORK TRAFFIC ANALYSIS ===")
        print("Analyzing network connections...\n")
        
        for connection in self.case_files['network_connections']:
            print(f"Connection: {connection}")
            
            # Check for suspicious ports
            if ':5555' in connection or ':6666' in connection or ':7777' in connection:
                print(" ALERT: Non-standard port detected!")
            
            # Check for external connections
            if '198.51.100' in connection or '203.0.113' in connection:
                print(" Note: External connection detected")
            
            print()
    
    def hash_analysis(self):
        print("=== FILE HASH ANALYSIS ===")
        print("Checking file hashes against known threats...\n")
        
        # Mock malware hash database
        known_malware_hashes = {
            'a1b2c3d4e5f6789012345678901234567890abcd': 'TrojanHorse.Win32.Generic',
            '123456789abcdef0123456789abcdef012345678': 'Backdoor.Win32.Agent'
        }
        
        for filename, file_hash in self.case_files['file_hashes'].items():
            print(f"File: {filename}")
            print(f"Hash: {file_hash}")
            
            if file_hash in known_malware_hashes:
                print(f" MALWARE DETECTED: {known_malware_hashes[file_hash]}")
            else:
                print(" Hash not found in malware database")
            
            print()
    
    def timeline_analysis(self):
        """Create timeline of events"""
        print("=== TIMELINE ANALYSIS ===")
        print("Reconstructing sequence of events...\n")
        
        events = [
            ("2025-09-20 10:15:23", "Normal admin login from 192.168.1.100"),
            ("2025-09-20 10:16:15", "SQL injection attempt from 10.0.0.50"),
            ("2025-09-20 10:16:16", "Unauthorized access to users.php"),
            ("2025-09-20 10:17:30", "File upload attempt from 172.16.0.25"),
            ("2025-09-20 10:17:31", "Successful file upload"),
        ]
        
        for timestamp, event in events:
            print(f"{timestamp}: {event}")
        
        print("\nAnalysis:")
        print("- Attack timeline spans 2 minutes")
        print("- Multiple IP addresses involved")
        print("- Escalation from injection to file upload")
        print("- Potential coordinated attack")

class IncidentResponseLab:
    """Incident response scenario simulations"""
    
    def __init__(self):
        self.scenarios = {
            'malware_outbreak': {
                'title': 'Malware Outbreak Response',
                'description': 'Multiple workstations showing suspicious activity',
                'initial_indicators': [
                    'Slow network performance',
                    'Unusual outbound network traffic',
                    'Files being encrypted randomly',
                    'Unknown processes running'
                ],
                'response_steps': [
                    'Isolate affected systems',
                    'Preserve evidence',
                    'Analyze malware samples',
                    'Implement containment',
                    'Eradicate threat',
                    'Recover systems',
                    'Lessons learned'
                ]
            },
            'data_breach': {
                'title': 'Data Breach Investigation',
                'description': 'Unauthorized access to customer database detected',
                'initial_indicators': [
                    'Failed login alerts',
                    'Unusual database queries',
                    'Large data downloads',
                    'Modified user accounts'
                ],
                'response_steps': [
                    'Confirm breach scope',
                    'Secure compromised accounts',
                    'Preserve log evidence',
                    'Notify stakeholders',
                    'Forensic analysis',
                    'Regulatory reporting',
                    'Implement safeguards'
                ]
            }
        }
    
    def start_scenario(self, scenario_name):
        """Start an incident response scenario"""
        if scenario_name not in self.scenarios:
            print("Scenario not found!")
            return
        
        scenario = self.scenarios[scenario_name]
        print(f"\n=== {scenario['title']} ===")
        print(f"Scenario: {scenario['description']}")
        print("\nInitial Indicators:")
        
        for indicator in scenario['initial_indicators']:
            print(f"- {indicator}")
        
        print(f"\nRecommended Response Steps:")
        for i, step in enumerate(scenario['response_steps'], 1):
            print(f"{i}. {step}")
        
        # Interactive response
        print("\nWhat would you do first?")
        for i, step in enumerate(scenario['response_steps'][:3], 1):
            print(f"{i}. {step}")
        
        choice = input("Enter your choice (1-3): ")
        
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= 3:
                chosen_step = scenario['response_steps'][choice_num - 1]
                print(f"\nYou chose: {chosen_step}")
                
                if choice_num == 1:
                    print("✓ Good choice! This helps prevent further damage.")
                elif choice_num == 2:
                    print("✓ Important step for investigation and legal requirements.")
                elif choice_num == 3:
                    print("✓ Critical for understanding the threat.")
            else:
                print("Invalid choice!")
        except ValueError:
            print("Please enter a number!")

def main():
    """Main function for cybersecurity practice labs"""
    print("=== CYBERSECURITY PRACTICE LABS ===")
    print("Hands-on exercises and challenges for learning cybersecurity")
    
    # Initialize components
    ctf = CTFChallenge()
    vuln_lab = VulnerabilityLab()
    forensics = ForensicsLab()
    incident_response = IncidentResponseLab()
    
    while True:
        print("\nChoose a practice area:")
        print("1. CTF Challenges")
        print("2. Vulnerability Assessment Lab")
        print("3. Digital Forensics Lab")
        print("4. Incident Response Scenarios")
        print("5. Exit")
        
        choice = input("Your choice (1-5): ")
        
        if choice == '1':
            print("\nCTF Challenge Menu:")
            print("a. List challenges")
            print("b. Attempt challenge")
            print("c. Show progress")
            
            sub_choice = input("Your choice (a-c): ")
            
            if sub_choice == 'a':
                ctf.list_challenges()
            elif sub_choice == 'b':
                challenge_id = input("Enter challenge ID: ")
                challenge = ctf.get_challenge(challenge_id)
                if challenge:
                    print("\nCommands: 'hint' for hint, 'quit' to exit")
                    while True:
                        answer = input("Enter your answer: ")
                        if answer.lower() == 'quit':
                            break
                        elif answer.lower() == 'hint':
                            ctf.show_hint(challenge_id)
                        else:
                            if ctf.submit_flag(challenge_id, answer):
                                break
            elif sub_choice == 'c':
                ctf.show_progress()
        
        elif choice == '2':
            print("\nVulnerability Lab Menu:")
            print("a. List vulnerabilities")
            print("b. View vulnerable code")
            print("c. Take vulnerability quiz")
            
            sub_choice = input("Your choice (a-c): ")
            
            if sub_choice == 'a':
                vuln_lab.list_vulnerabilities()
            elif sub_choice == 'b':
                vuln_type = input("Enter vulnerability type: ")
                vuln_lab.show_vulnerable_code(vuln_type)
            elif sub_choice == 'c':
                vuln_lab.vulnerability_quiz()
        
        elif choice == '3':
            print("\nForensics Lab Menu:")
            print("a. Analyze web logs")
            print("b. Analyze network traffic")
            print("c. Hash analysis")
            print("d. Timeline analysis")
            
            sub_choice = input("Your choice (a-d): ")
            
            if sub_choice == 'a':
                forensics.analyze_web_logs()
            elif sub_choice == 'b':
                forensics.analyze_network_traffic()
            elif sub_choice == 'c':
                forensics.hash_analysis()
            elif sub_choice == 'd':
                forensics.timeline_analysis()
        
        elif choice == '4':
            print("\nIncident Response Scenarios:")
            print("a. Malware outbreak")
            print("b. Data breach")
            
            sub_choice = input("Your choice (a-b): ")
            
            if sub_choice == 'a':
                incident_response.start_scenario('malware_outbreak')
            elif sub_choice == 'b':
                incident_response.start_scenario('data_breach')
        
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()