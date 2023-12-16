import re

#Pengecekan Query SQL dan Input Pengguna    
def check_php_code(file_path):
    issues = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line_number, line in enumerate(file, 1):
            if re.search(r"\$_(POST|GET)\['[^']+'\]", line):
                issues.append(f"Line {line_number}: Direct usage of POST/GET found, potential SQL Injection vulnerability")
            if re.search(r"mysql_query\(", line):
                issues.append(f"Line {line_number}: Found 'mysql_query', consider using prepared statements")
            if re.search(r"mysqli_query\(", line) and not re.search(r"bind_param", line, re.MULTILINE):
                issues.append(f"Line {line_number}: Found 'mysqli_query' without 'bind_param', consider using binding parameters")
    return issues
 