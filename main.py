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
    
from PIL import Image
from PIL.ExifTags import TAGS    
import tkinter as tk
from tkinter import filedialog, Listbox, ttk, simpledialog, messagebox
import os
from modules.image_checks import (is_valid_image, get_metadata, analyze_metadata, check_gif_extra_data, check_bmp_extra_data)
from modules.php_code_checks import contains_suspicious_php_code, contains_web_shell_signatures, contains_sensitive_information
from modules.php_query_checks import check_php_code
from modules.directory_traversal_checks import is_vulnerable_to_traversal
from modules.php_upload_checks import check_php_upload_vulnerabilities
from modules.pdf_checks import is_fake_pdf, contains_php_code
from modules.file_checks import contains_php_code_in_binary
from modules.directory_checks import check_folder_permissions
from modules.host_header_vuln_checks import check_host_header_vuln

global progress_label, progress_bar

def show_progress_dialog(total_files):
    progress_dialog = tk.Toplevel(root)
    progress_dialog.title("Progress")
    progress_dialog.geometry("300x100")

    global progress_label, progress_bar

    progress_label = tk.Label(progress_dialog, text="0/0")
    progress_label.pack()

    progress_bar = ttk.Progressbar(progress_dialog, orient=tk.HORIZONTAL, length=280, mode='determinate')
    progress_bar.pack(pady=(20, 10))

    finish_button = tk.Button(progress_dialog, text="Selesai", command=progress_dialog.destroy)

    return progress_dialog, finish_button, progress_bar, progress_label

    
def update_progress(processed_files, total_files):
    global progress_label, progress_bar
    progress_percentage = (processed_files / max(1, total_files)) * 100
    progress_bar['value'] = progress_percentage
    progress_label.config(text=f"{processed_files}/{total_files}")
    root.update_idletasks()
    

    
def scan_directory(directory, progress_dialog, finish_button, progress_bar, progress_label):
    suspicious_files = []
    total_files = sum([len(files) for _, _, files in os.walk(directory)])
    processed_files = 0
    for root, dirs, files in os.walk(directory):
        total_files = sum([len(files) for r, d, files in os.walk(directory)])
        processed_files = 0
        for file in files:
            processed_files += 1
            full_path = os.path.join(root, file)
            file_ext = os.path.splitext(full_path)[1].lower()
            # Pengecekan gambar, PDF, doc, dan lainnya
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                if not is_valid_image(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")
                    continue  
                else:
                    # Periksa data tambahan dalam file GIF dan BMP
                    if file_ext == '.gif':
                        extra_data_found, message = check_gif_extra_data(full_path)
                    elif file_ext == '.bmp':
                        extra_data_found, message = check_bmp_extra_data(full_path)
                    else:
                        extra_data_found, message = False, ""

                    if extra_data_found:
                        suspicious_files.append(full_path + " - " + message)
                    else:
                        try:
                            metadata = get_metadata(full_path)
                            is_suspicious, reason = analyze_metadata(metadata)
                            if is_suspicious:
                                suspicious_files.append(full_path + " - " + reason)
                        except Exception as e:
                            suspicious_files.append(full_path + " - Error: " + str(e))

                        
            elif file_ext == '.pdf':
                if is_fake_pdf(full_path) or contains_php_code(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")

            elif file_ext in ['.doc', '.docx', '.xls', '.xlsx']:
                if contains_php_code_in_binary(full_path):
                    suspicious_files.append(full_path + " (Suspicious)")
            
            elif file_ext == '.php':
                suspicious_message = []

                suspicious_php_code_message = contains_suspicious_php_code(full_path)
                if suspicious_php_code_message:
                    suspicious_message.append(suspicious_php_code_message)

                web_shell_signature_message = contains_web_shell_signatures(full_path)
                if web_shell_signature_message:
                    suspicious_message.append(web_shell_signature_message)

                sensitive_info_message = contains_sensitive_information(full_path)
                if sensitive_info_message:
                    suspicious_message.append(sensitive_info_message)

                if suspicious_message:
                    suspicious_files.append(full_path + " (Suspicious - " + ", ".join(suspicious_message) + ")")
                    
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
            
            #Pengecekan Host Header            
            if file_ext in ['.php', '.py', '.js', '.html']:
                host_header_issues = check_host_header_vuln(full_path, ['.php', '.py', '.js', '.html'])
                for issue in host_header_issues:
                    suspicious_files.append(issue + " (Potential Host Header Attack)")
                    
            update_progress(processed_files, total_files)
    
    progress_bar['value'] = 100
    progress_label.config(text=f"{total_files}/{total_files}")
    finish_button.pack()
    progress_dialog.update()
    
    # Pengecekan hak akses folder
    permission_issues = check_folder_permissions(directory)
    suspicious_files.extend(permission_issues)
    return suspicious_files

def on_scan():
    directory = filedialog.askdirectory()
    print(f"Selected directory: {directory}")
    if directory:
        progress_dialog, finish_button, progress_bar, progress_label = show_progress_dialog(total_files)
        suspicious_files = scan_directory(directory, progress_dialog, finish_button, progress_bar, progress_label)
        listbox.delete(0, tk.END)
        for file in suspicious_files:
            listbox.insert(tk.END, file)
        if not suspicious_files:
            listbox.insert(tk.END, "No suspicious files found.")
        progress['value'] = 0

def export_log(suspicious_files):
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if filename:
        with open(filename, "w") as f:
            for file in suspicious_files:
                f.write(file + "\n")
        messagebox.showinfo("Export Log", f"Log berhasil diekspor ke {filename}")
        
def build_menu(root):
    # Membuat menu bar
    menubar = tk.Menu(root)

    # Membuat menu dropdown
    scan_menu = tk.Menu(menubar, tearoff=0)
    scan_menu.add_command(label="Scan Directory", command=on_scan)
    scan_menu.add_command(label="Export Hasil", command=lambda: export_log(listbox.get(0, tk.END)))
    scan_menu.add_separator()
    scan_menu.add_command(label="Exit", command=root.quit)

    settings_menu = tk.Menu(menubar, tearoff=0)
    settings_menu.add_command(label="Pengaturan")
    settings_menu.add_command(label="About", command=check_for_updates)

    # Menambahkan menu dropdown ke menu bar
    menubar.add_cascade(label="Scan", menu=scan_menu)
    menubar.add_cascade(label="Settings", menu=settings_menu)

    # Menampilkan menu bar
    root.config(menu=menubar)
    
def check_for_updates():
    # Implementasi kode untuk memeriksa pembaruan
    messagebox.showinfo(title="About", message="File Scanner (Beta) Creator : Upil")

    
if __name__ == "__main__":
    root = tk.Tk()        
    root.title("File Scanner")
    root.geometry("400x300")
    
    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)

    scrollbar = tk.Scrollbar(root)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    listbox = Listbox(root, width=100, height=20, yscrollcommand=scrollbar.set)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar.config(command=listbox.yview)
    
    total_files = 0
    
    progress_label = tk.Label(root, text="", width=10)
    progress_label.pack()
    
    progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=100, mode='determinate')
    
    build_menu(root)
    
    root.mainloop()
