import os
import hashlib

def find_hidden_files(directory):
    """Find hidden files in the selected directory."""
    hidden_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith('.') or file.startswith('$'):
                hidden_files.append(os.path.join(root, file))
    return hidden_files

def calculate_file_hashes(directory):
    """Calculate MD5, SHA1, and SHA256 hashes for files in the directory."""
    file_hashes = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                    md5_hash = hashlib.md5(file_data).hexdigest()
                    sha1_hash = hashlib.sha1(file_data).hexdigest()
                    sha256_hash = hashlib.sha256(file_data).hexdigest()

                    file_hashes.append({
                        "file": file_path,
                        "md5": md5_hash,
                        "sha1": sha1_hash,
                        "sha256": sha256_hash
                    })
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
    return file_hashes
