import subprocess
import json
import sys

def install_packages(package_list):
    for package in package_list:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import tkinter
    from PIL import Image
    import PyPDF2
except ImportError as e:
    print("Required packages not found. Installing...")
    with open("requirements.txt", "r") as f:
        packages = f.read().splitlines()
    install_packages(packages)
    
import tkinter as tk
from tkinter import filedialog, Listbox, ttk
from modules import image_checks, pdf_checks, php_code_checks, directory_checks, directory_traversal_checks, php_query_checks, php_upload_checks, file_checks
import os
from modules.image_checks import is_valid_image, get_metadata, analyze_metadata
from modules.php_code_checks import contains_suspicious_php_code, contains_web_shell_signatures
from modules.php_query_checks import check_php_code
from modules.directory_traversal_checks import is_vulnerable_to_traversal
from modules.php_upload_checks import check_php_upload_vulnerabilities
from modules.pdf_checks import is_fake_pdf, contains_php_code
from modules.file_checks import contains_php_code_in_binary
from modules.directory_checks import check_folder_permissions

def update_progress(step, total_steps):
    progress['value'] = (step / total_steps) * 100
    root.update_idletasks()
    
def scan_directory(directory, tk_root, progress):
    suspicious_files = []
    total_files = sum([len(files) for _, _, files in os.walk(directory)])
    processed_files = 0
    for root, dirs, files in os.walk(directory):
        total_files = sum([len(files) for r, d, files in os.walk(directory)])
        processed_files = 0
        for file in files:
            full_path = os.path.join(root, file)
            file_ext = os.path.splitext(full_path)[1].lower()
            # Pengecekan gambar, PDF, doc, dan lainnya
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
                if not is_valid_image(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")
                else:
                    try:
                        metadata = get_metadata(full_path)
                        is_suspicious, reason = analyze_metadata(metadata)
                        if is_suspicious:
                            suspicious_files.append(full_path + " - " + reason)
                    except Exception as e:
                        print(f"Error analyzing {full_path}: {e}")
                        
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
                        
            processed_files += 1
            update_progress(processed_files, total_files)
            
    # Pengecekan hak akses folder
    permission_issues = check_folder_permissions(directory)
    suspicious_files.extend(permission_issues)
    return suspicious_files

def on_scan():
    directory = filedialog.askdirectory()
    print(f"Selected directory: {directory}")
    if directory:
        suspicious_files = scan_directory(directory, root, progress)
        listbox.delete(0, tk.END)
        for file in suspicious_files:
            listbox.insert(tk.END, file)
        if not suspicious_files:
            listbox.insert(tk.END, "No suspicious files found.")
        progress['value'] = 0

if __name__ == "__main__":
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

    progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=100, mode='determinate')
    progress.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    root.mainloop()

