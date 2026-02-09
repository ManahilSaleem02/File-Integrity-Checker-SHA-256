# File-Integrity-Checker-SHA-256:
A lightweight command-line tool that verifies file integrity by generating and comparing cryptographic hash values (SHA-256). The tool helps detect unauthorized or accidental file modifications by ensuring that a file’s contents remain unchanged over time. Commonly used in cybersecurity, digital forensics, and system monitoring to maintain data integrity.

# Features / Functionality:
  1. Generate SHA-256 hash for any file
  2. Save hash to a separate .hash file for future verification
  3. Verify if a file has been modified since the hash was generated
  4. Simple command-line interface (CLI)
  5. Lightweight and easy to use

# How to Run:

  1. Clone the repository:    "git clone https://github.com/ManahilSaleem02/File-Integrity-Checker-SHA-256.git"  then "cd File-Integrity-Checker"

  2. Run the Python program and generate hash for a file:  "python file_checker.py generate <filename>"

  3. Verify a file against its hash:  "python file_checker.py verify <filename>"


# Example Usage:
1. cloning the repository:
<img width="880" height="129" alt="me" src="https://github.com/user-attachments/assets/372b1279-5230-401e-b600-0528ebcdd077" />
     2. Creating a test file and saving its hash:
<img width="880" height="129" alt="2" src="https://github.com/user-attachments/assets/e5f948fe-0bea-4aa2-8644-f43801fdbd1d" />
     3. Modifying the file and then checking the file integrity:
<img width="850" height="129" alt="3" src="https://github.com/user-attachments/assets/bf1e1d58-905d-4596-be41-5f169d22bd85" />


