#!/usr/bin/env python3
import argparse

def parse_key(key_str):
    """
    Parse a key provided as a comma-separated list of byte values.
    Example input: "0xCA,0xFE,0xBA,0xBE"
    Returns a list of integers.
    """
    parts = key_str.split(',')
    key = []
    for part in parts:
        part = part.strip()
        # If the part starts with '0x' or '0X', interpret it as hexadecimal.
        if part.lower().startswith("0x"):
            key.append(int(part, 16))
        else:
            key.append(int(part))
    return key

def rc4(key, data):
    """
    RC4 encryption/decryption function.
    Since RC4 is symmetric, this function works for both encryption and decryption.
    
    :param key: List of integers representing key bytes.
    :param data: Data to encrypt/decrypt (bytes)
    :return: Encrypted/decrypted data (bytes)
    """
    # Key Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    key_length = len(key)
    
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-Random Generation Algorithm (PRGA)
    i = 0
    j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return result

def main():
    parser = argparse.ArgumentParser(description="RC4 file encryption/decryption script with byte-formatted key")
    parser.add_argument("input", help="Path to the input file")
    parser.add_argument("output", help="Path for the output file")
    parser.add_argument("key", help="Encryption key in byte format, e.g. '0xCA,0xFE,0xBA,0xBE'")
    
    args = parser.parse_args()
    
    # Parse the key from the provided string into a list of integers
    key_bytes = parse_key(args.key)
    
    # Read the input file as binary data
    try:
        with open(args.input, "rb") as infile:
            data = infile.read()
    except FileNotFoundError:
        print(f"Error: File {args.input} not found.")
        return
    
    # Encrypt (or decrypt) the data using RC4
    result = rc4(key_bytes, data)
    
    # Write the result to the output file
    with open(args.output, "wb") as outfile:
        outfile.write(result)
    
    print(f"Operation complete. Output saved to: {args.output}")

if __name__ == "__main__":
    main()