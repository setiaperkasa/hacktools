import os
import stat

def check_folder_permissions(directory):
    issues = []
    for root, dirs, _ in os.walk(directory):
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            mode = os.stat(dir_path).st_mode
            if mode != 0o100644:
                issues.append(f"{dir_path} - Incorrect folder permissions (not 644)")
    return issues
