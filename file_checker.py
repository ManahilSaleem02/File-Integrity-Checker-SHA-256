#!/usr/bin/env python3
"""
File Integrity Checker using SHA-256
A lightweight command-line tool for verifying file integrity through cryptographic hashing.
"""

import hashlib
import sys
import os
from pathlib import Path


def calculate_sha256(filepath):
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        filepath (str): Path to the file to hash
        
    Returns:
        str: Hexadecimal SHA-256 hash
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        PermissionError: If the file cannot be read
    """
    sha256_hash = hashlib.sha256()
    
    try:
        with open(filepath, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: File '{filepath}' not found.")
    except PermissionError:
        raise PermissionError(f"Error: Permission denied to read '{filepath}'.")
    except Exception as e:
        raise Exception(f"Error reading file '{filepath}': {str(e)}")


def generate_hash(filepath):
    """
    Generate SHA-256 hash for a file and save it to a .hash file.
    
    Args:
        filepath (str): Path to the file to hash
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check if file exists
        if not os.path.exists(filepath):
            print(f"❌ Error: File '{filepath}' not found.")
            return False
        
        # Calculate hash
        print(f"🔐 Generating SHA-256 hash for '{filepath}'...")
        file_hash = calculate_sha256(filepath)
        
        # Create hash filename
        hash_filepath = f"{filepath}.hash"
        
        # Save hash to file
        with open(hash_filepath, "w") as hash_file:
            hash_file.write(file_hash)
        
        print(f"✅ Hash generated successfully!")
        print(f"📄 Hash: {file_hash}")
        print(f"💾 Hash saved as: {hash_filepath}")
        return True
        
    except Exception as e:
        print(f"❌ {str(e)}")
        return False


def verify_hash(filepath):
    """
    Verify if a file has been modified by comparing its current hash
    with the stored hash.
    
    Args:
        filepath (str): Path to the file to verify
        
    Returns:
        bool: True if file is intact, False if modified or error
    """
    try:
        # Check if original file exists
        if not os.path.exists(filepath):
            print(f"❌ Error: File '{filepath}' not found.")
            return False
        
        # Check if hash file exists
        hash_filepath = f"{filepath}.hash"
        if not os.path.exists(hash_filepath):
            print(f"❌ Error: Hash file '{hash_filepath}' not found.")
            print(f"💡 Tip: Generate a hash first using: python file_checker.py generate {filepath}")
            return False
        
        # Read stored hash
        with open(hash_filepath, "r") as hash_file:
            stored_hash = hash_file.read().strip()
        
        # Calculate current hash
        print(f"🔍 Verifying '{filepath}'...")
        current_hash = calculate_sha256(filepath)
        
        # Compare hashes
        if current_hash == stored_hash:
            print(f"✅ File intact - No modifications detected")
            print(f"📄 Hash: {current_hash}")
            return True
        else:
            print(f"⚠️  File has been modified!")
            print(f"📄 Original hash:  {stored_hash}")
            print(f"📄 Current hash:   {current_hash}")
            return False
            
    except Exception as e:
        print(f"❌ {str(e)}")
        return False


def print_usage():
    """Print usage instructions."""
    print("=" * 70)
    print("File Integrity Checker - SHA-256")
    print("=" * 70)
    print("\nUsage:")
    print("  python file_checker.py generate <filename>")
    print("  python file_checker.py verify <filename>")
    print("\nCommands:")
    print("  generate  - Generate SHA-256 hash for a file and save it")
    print("  verify    - Verify file integrity against saved hash")
    print("\nExamples:")
    print("  python file_checker.py generate sample.txt")
    print("  python file_checker.py verify sample.txt")
    print("=" * 70)


def main():
    """Main function to handle command-line arguments."""
    
    # Check if correct number of arguments provided
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    filepath = sys.argv[2]
    
    # Execute appropriate command
    if command == "generate":
        success = generate_hash(filepath)
        sys.exit(0 if success else 1)
        
    elif command == "verify":
        success = verify_hash(filepath)
        sys.exit(0 if success else 1)
        
    else:
        print(f"❌ Error: Unknown command '{command}'")
        print("\n")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
