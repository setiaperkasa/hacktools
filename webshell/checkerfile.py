import os
import tkinter as tk
from tkinter import filedialog, Listbox
from PIL import Image
import PyPDF2
import re
import stat

#Pengecekan Gambar
def is_valid_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except:
        return False

def is_fake_pdf(file_path):
    try:
        with open(file_path, 'rb') as file:
            PyPDF2.PdfReader(file)
        return False
    except:
        return True

#Pengecekan PDF
def contains_php_code(file_path):
    try:
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page in reader.pages:
                text = page.extract_text()
                if text and "<?php" in text:
                    return True
        return False
    except:
        return False

#Pengecekan Binari File
def contains_php_code_in_binary(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            return b'<?php' in content
    except:
        return False

#Pengecekan Coding PHP mencurigakan
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

#Pengecekan WebShell PHP
def contains_web_shell_signatures(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            web_shell_signatures = [
                "r57shell", "base64_decode", "php_uname", "phpinfo",
                "passthru", "shell_exec", "exec", "popen", "eval",
                "system", "assert", "str_rot13", "gzinflate", "gzuncompress",
                "urldecode", "cmd", "proc_open", "proc_close"
            ]
            for signature in web_shell_signatures:
                if signature in content:
                    return True
            return False
    except:
        return False

#Pengecekan Directory Traversal
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
 
#Pengecekan Hak Akses Folder
def check_folder_permissions(directory):
    issues = []
    for root, dirs, _ in os.walk(directory):
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            mode = os.stat(dir_path).st_mode
            if mode != 0o100644:  
                issues.append(f"{dir_path} - Incorrect folder permissions (not 644)")
    return issues

#Pengecekan Upload Code
def check_php_upload_vulnerabilities(file_path):
    issues = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()

        # Periksa penggunaan $_FILES (indikasi kode unggah file)
        if re.search(r"\$_FILES\[", content):
            # Periksa Validasi Jenis MIME
            if not re.search(r"mime_content_type\(", content) and not re.search(r"finfo_", content):
                issues.append("Missing MIME type validation.")

            # Periksa Pemeriksaan Ekstensi File
            if not re.search(r"\.php", content, re.IGNORECASE):
                issues.append("Missing file extension check for .php (or other extensions).")

            # Periksa Batas Ukuran File
            if not re.search(r"size", content):
                issues.append("Missing file size limit check.")

            # Periksa Jalur Penyimpanan Aman
            if re.search(r"move_uploaded_file\(\s*\$_FILES", content) and not re.search(r"/var/www/", content):
                issues.append("Potential insecure storage path for uploaded files.")

            # Periksa Penanganan Kesalahan
            if not re.search(r"if\s*\(\s*!move_uploaded_file", content):
                issues.append("Missing or insufficient error handling in file upload.")
    
    return issues
    
def scan_directory(directory):
    suspicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            file_ext = os.path.splitext(full_path)[1].lower()
            # Pengecekan gambar, PDF, doc, dan lainnya
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
                if not is_valid_image(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")

            elif file_ext == '.pdf':
                if is_fake_pdf(full_path) or contains_php_code(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")

            elif file_ext in ['.doc', '.docx', '.xls', '.xlsx']:
                if contains_php_code_in_binary(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")
            
            elif file_ext == '.php':
                if contains_suspicious_php_code(full_path) or contains_web_shell_signatures(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")
                    
            # Pengecekan khusus untuk file PHP
            if file_ext == '.php':
                # Pengecekan kode PHP, traversal, dan upload vulnerabilities
                    php_issues = check_php_code(full_path)
                    if php_issues:
                        suspicious_files.extend([full_path + " - " + issue for issue in php_issues])
                    if is_vulnerable_to_traversal(full_path):
                        suspicious_files.append(full_path + " (Potential Directory Traversal)")
                    upload_issues = check_php_upload_vulnerabilities(full_path)
                    if upload_issues:
                        suspicious_files.extend([full_path + " - " + issue for issue in upload_issues])
    
    # Pengecekan hak akses folder
    permission_issues = check_folder_permissions(directory)
    suspicious_files.extend(permission_issues)
    return suspicious_files

def on_scan():
    directory = filedialog.askdirectory()
    print(f"Selected directory: {directory}")
    if directory:
        suspicious_files = scan_directory(directory)
        listbox.delete(0, tk.END)
        for file in suspicious_files:
            listbox.insert(tk.END, file)
        if not suspicious_files:
            listbox.insert(tk.END, "No suspicious files found.")

root = tk.Tk()
root.title("File Scanner by UPIL")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

scan_button = tk.Button(frame, text="Scan Directory", command=on_scan)
scan_button.pack(side=tk.LEFT)

scrollbar = tk.Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox = Listbox(root, width=100, height=20, yscrollcommand=scrollbar.set)
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar.config(command=listbox.yview)

root.mainloop()
