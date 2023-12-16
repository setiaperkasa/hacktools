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
