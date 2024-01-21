import re

def contains_suspicious_php_code(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            suspicious_functions = [r'\bexec\b', r'\bshell_exec\b', r'\bbase64_decode\b', r'\beval\b', r'\bsystem\b', r'\bpassthru\b']
            for func in suspicious_functions:
                if re.search(func + r'\s*\(', content):
                    return f"PHP Function: {func}"
            return False
    except:
        return False

def contains_web_shell_signatures(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            web_shell_signatures = [
                r'\br57shell\b', r'\bbase64_decode\b', r'\bphp_uname\b', r'\bphpinfo\b', r'\bpassthru\b', r'\bshell_exec\b', r'\bexec\b', 
                r'\bpopen\b', r'\beval\b', r'\bsystem\b', r'\bassert\b', r'\bstr_rot13\b', r'\bgzinflate\b', r'\bgzuncompress\b', 
                r'\burldecode\b', r'\bcmd\b', r'\bproc_open\b', r'\bproc_close\b'
            ]
            for signature in web_shell_signatures:
                if re.search(signature, content):
                    return f"Web Shell Signature: {signature}"
            return False
    except:
        return False

def contains_sensitive_information(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            sensitive_keywords = ['phpinfo', 'adminer', 'phpmyadmin']  # Tambahkan kata kunci lain jika diperlukan
            for keyword in sensitive_keywords:
                if keyword in content:
                    return f"Server Information Leak: {keyword}"
            return False
    except:
        return False
