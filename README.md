Password Strength Checker and Hasher

This Python script checks the strength of a password based on various criteria (length, complexity, entropy, etc.) and securely hashes it using the bcrypt library. It is designed to help users create strong passwords and store them securely.
Features

    Password Strength Analysis:

        Checks password length.

        Verifies the presence of uppercase letters, lowercase letters, digits, and special characters.

        Compares the password against a list of common passwords.

        Calculates password entropy (a measure of randomness and complexity).

        Provides an overall strength rating (Very Weak, Weak, Moderate, Strong, Very Strong).

    Secure Password Hashing:

        Uses the bcrypt library to securely hash passwords for storage.

        Generates a unique salt for each password.

Requirements

    Python 3.x

    bcrypt library

To install the required library, run:
bash


pip install bcrypt

Usage

    Clone the repository or download the script:
    bash
    Copy

    git clone https://github.com/SebastianPablos/password-strength-checker
    

    Run the script:
    bash
    Copy

    python password_strength_checker.py

    Enter a password when prompted. The script will analyze the password and display:

        Feedback on the password's strength.

        The overall strength rating.

        A securely hashed version of the password.

Example Output
Copy

Enter your password: MySecurePassword123!

Password Strength Analysis:
- Password length is good.
- Password contains uppercase letters.
- Password contains lowercase letters.
- Password contains digits.
- Password contains special characters.
- Password is not a common password.
- Password entropy: 96.00 bits (higher is better).

Overall Password Strength: Strong

Hashed Password (for secure storage): $2b$12$5l8z7Xy9V8e6Q1w2E3r4tOe1Z2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q

How It Works
Password Strength Checker

    The script evaluates the password based on:

        Length: Minimum 8 characters.

        Complexity: Presence of uppercase, lowercase, digits, and special characters.

        Common Passwords: Checks against a list of easily guessable passwords.

        Entropy: Measures the randomness of the password using the formula:
        Copy

        Entropy = Length * log2(Character Pool Size)

        The character pool size depends on the types of characters used in the password.

Password Hasher

    The script uses the bcrypt library to hash the password securely. Bcrypt is a widely used hashing algorithm designed for password storage. It automatically generates a unique salt for each password, making it resistant to rainbow table attacks.

Contributing

Contributions are welcome! If you'd like to improve this project, please:

    Fork the repository.

    Create a new branch for your feature or bugfix.

    Submit a pull request.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

    Inspired by the need for better password security practices.

    Uses the bcrypt library for secure password hashing.

Contact

For questions or feedback, please open an issue on GitHub or contact Sebastian at sebastianpablosc@gmail.com
