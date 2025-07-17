import sys

def byte_difference_percentage(hex1: str, hex2: str) -> float:
    # Ensure both hex strings are the same length (16 bytes => 32 hex characters)
    if len(hex1) != len(hex2) or len(hex1) != 32:
        raise ValueError("Both hex strings must be 32 characters long (16 bytes).")

    # Convert hex strings to byte arrays
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)

    # Count differing bytes
    differing_bytes = sum(1 for b1, b2 in zip(bytes1, bytes2) if b1 != b2)

    # Calculate percentage of differing bytes
    total_bytes = len(bytes1)
    diff_percentage = (1-(differing_bytes / total_bytes)) * 100

    return diff_percentage

# Encryption key
encryption_key = '1122334455667788ff00eeddccbbaa99'

source_keys = []
with open('guess_key_'+sys.argv[1]+'.txt','r') as file:
    source_keys = [line.rstrip() for line in file]

percentage_diff = byte_difference_percentage(encryption_key, source_keys[0])
print(f"Accuracy: {percentage_diff:.2f}%")
