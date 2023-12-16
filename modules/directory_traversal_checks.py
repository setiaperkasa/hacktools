import re

def is_vulnerable_to_traversal(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()
        patterns = [
            r"\$_(GET|POST|REQUEST|FILES)\[['\"]?[a-zA-Z0-9_]+['\"]?\][ ]*\.[ ]*['\"]?/",
            r"fopen\([ ]*\$_(GET|POST|REQUEST|FILES)",
            r"include\([ ]*\$_(GET|POST|REQUEST|FILES)",
            r"require\([ ]*\$_(GET|POST|REQUEST|FILES)"
        ]
        for pattern in patterns:
            if re.search(pattern, content):
                return True
    return False
