import os
import tkinter as tk
from tkinter import filedialog, Listbox
from PIL import Image
import PyPDF2

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

def contains_php_code_in_binary(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            return b'<?php' in content
    except:
        return False

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

def scan_directory(directory):
    suspicious_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            file_ext = os.path.splitext(full_path)[1].lower()
            
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

listbox = Listbox(root, width=100, height=20)
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

root.mainloop()
