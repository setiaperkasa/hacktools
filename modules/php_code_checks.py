import re

def contains_suspicious_php_code(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            suspicious_functions = ['exec', 'shell_exec', 'base64_decode', 'eval', 'system', 'passthru']
            for func in suspicious_functions:
                if func + '(' in content:
                    return True
            return False
    except:
        return False

def contains_web_shell_signatures(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            web_shell_signatures = [
                "r57shell", "base64_decode", "php_uname", "phpinfo", "passthru", "shell_exec", "exec", "popen", "eval",
                "system", "assert", "str_rot13", "gzinflate", "gzuncompress", "urldecode", "cmd", "proc_open", "proc_close"
            ]
            for signature in web_shell_signatures:
                if signature in content:
                    return True
            return False
    except:
        return False
