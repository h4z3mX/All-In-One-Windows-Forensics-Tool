import os
from datetime import datetime

def list_files(directory):
    """
    Recursively list files in a mounted directory.
    :param directory: Path to the mounted directory.
    :return: List of file information dictionaries.
    """
    file_list = []
    try:
        for root, dirs, files in os.walk(directory):
            for name in files:
                path = os.path.join(root, name)
                stat = os.stat(path)
                file_info = {
                    "name": name,
                    "type": "File",
                    "modified": datetime.utcfromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    "accessed": datetime.utcfromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                    "created": datetime.utcfromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                }
                file_list.append(file_info)
    except Exception as e:
        print(f"Error listing files: {e}")
    return file_list
