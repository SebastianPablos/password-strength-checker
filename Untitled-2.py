import re
import math
import bcrypt

# List of common passwords to check against
COMMON_PASSWORDS = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]

def check_password_strength(password):
    # Initialize feedback list
    feedback = []

    # Check length
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    else:
        feedback.append("Password length is good.")

    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        feedback.append("Password should contain at least one uppercase letter.")
    else:
        feedback.append("Password contains uppercase letters.")

    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        feedback.append("Password should contain at least one lowercase letter.")
    else:
        feedback.append("Password contains lowercase letters.")

    # Check for digits
    if not re.search(r'[0-9]', password):
        feedback.append("Password should contain at least one digit.")
    else:
        feedback.append("Password contains digits.")

    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        feedback.append("Password should contain at least one special character.")
    else:
        feedback.append("Password contains special characters.")

    # Check against common passwords
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("Password is too common and easily guessable.")
    else:
        feedback.append("Password is not a common password.")

    # Calculate entropy (measure of password randomness)
    char_pool_size = 0
    if re.search(r'[a-z]', password):
        char_pool_size += 26  # lowercase letters
    if re.search(r'[A-Z]', password):
        char_pool_size += 26  # uppercase letters
    if re.search(r'[0-9]', password):
        char_pool_size += 10  # digits
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        char_pool_size += 32  # special characters (approximate)

    entropy = len(password) * math.log2(char_pool_size) if char_pool_size > 0 else 0
    feedback.append(f"Password entropy: {entropy:.2f} bits (higher is better).")

    # Determine strength based on feedback
    strength = "Very Strong"
    if len(password) < 8 or password.lower() in COMMON_PASSWORDS or entropy < 50:
        strength = "Very Weak"
    elif entropy < 70:
        strength = "Weak"
    elif entropy < 90:
        strength = "Moderate"
    elif entropy < 120:
        strength = "Strong"

    return strength, feedback

def hash_password(password):
    # Generate a salt and hash the password using bcrypt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

def main():
    password = input("Enter your password: ")
    strength, feedback = check_password_strength(password)
    print("\nPassword Strength Analysis:")
    for item in feedback:
        print(f"- {item}")
    print(f"\nOverall Password Strength: {strength}")

    # Hash the password for secure storage
    hashed_password = hash_password(password)
    print(f"\nHashed Password (for secure storage): {hashed_password}")

if __name__ == "__main__":
    main()