import os

def check_host_header_vuln(directory, file_extensions):
    potential_vulns = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(file_extensions):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_number, line in enumerate(f, 1):
                        if 'Host' in line and is_suspicious(line):
                            potential_vulns.append(f"{file_path}: Line {line_number}")

    return potential_vulns

def is_suspicious(line):
    # Basic checks for known patterns (can be expanded)
    patterns = ['request.headers[\'Host\']', '$_SERVER[\'HTTP_HOST\']']
    for pattern in patterns:
        if pattern in line:
            return True
    return False
