import subprocess
import json
from PIL import Image
from PIL.ExifTags import TAGS
import os
import re
import io

#Pengecekan Gambar
def is_valid_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except:
        return False

def safe_float_conversion(number_str):
    try:
        return float(number_str)
    except ValueError:
        print(f"Warning: Could not convert '{number_str}' to float. Using 0.0 instead.")
        return 0.0

        
def get_metadata(image_path):
    try:
        with Image.open(image_path) as image:
            image.verify()  # Verify that it's an image

            if image.format == 'JPEG':
                exif_data = image._getexif()

                if not exif_data:
                    return {}

                metadata = {}
                for tag, value in exif_data.items():
                    decoded = TAGS.get(tag, tag)
                    metadata[decoded] = value

                return metadata

            elif image.format == 'GIF':
                return {
                    "Size": image.size,
                    "Frame count": getattr(image, "n_frames", 1)
                }

            else:
                return {}  # Empty dictionary for non-JPEG/non-GIF images

    except Exception as e:
        raise RuntimeError(f"Error processing file {image_path}: {str(e)}")


# Fungsi untuk menganalisis metadata
def analyze_metadata(metadata):
    suspicious_patterns = [r'<script.*?>.*?</script>', r'eval\s*\(.*\)', r'base64_decode\s*\(.*\)', r'[A-Za-z0-9+/=]{50,}']
    for tag, value in metadata.items():
        if isinstance(value, str):
            for pattern in suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return True, f"Suspicious content found in {tag}: {value}"
    return False, "No suspicious metadata found."

def safe_float_conversion(number_str):
    try:
        return float(number_str)
    except ValueError:
        print(f"Warning: '{number_str}' is not a valid float. Using 0.0 instead.")
        return 0.0

suspicious_patterns = [r'<script.*?>.*?</script>', r'eval\s*\(.*\)', r'base64_decode\s*\(.*\)', r'[A-Za-z0-9+/=]{50,}']
        
# Fungsi untuk memeriksa data tambahan pada file GIF
def check_gif_extra_data(file_path):
    try:
        injection_patterns = [
            b'\x2f\x2f\x2f\x2f\x2f',        # Pattern 1
            b'\xFF\x2A\x2F\x3D\x31\x3B',    # Pattern 2
            b'\x2A\x2F\x3D\x31\x3B'         # Pattern 3
        ]

        with open(file_path, 'rb') as file:
            content = file.read()

        for pattern in injection_patterns:
            if pattern in content:
                return True, f"Suspicious injection pattern found in GIF data: {pattern}"

        if len(content) > 13:
            post_header_data = content[13:]
            if any(b > 127 for b in post_header_data):
                return True, "Non-ASCII characters in GIF data (Chances are no suspicious code in GIF file)"
                
        return False, "No suspicious code in GIF file"

    except Exception as e:
        print(f"Error processing GIF file {file_path}: {str(e)}")
        return False, None



# Fungsi untuk memeriksa data tambahan pada file BMP
def check_bmp_extra_data(file_path):
    try:
        with open(file_path, 'rb') as file:
            file.seek(2)
            bmp_size = int.from_bytes(file.read(4), byteorder='little')
            file.seek(bmp_size, os.SEEK_SET)
            extra_data = file.read()
            return bool(extra_data), "Extra data in BMP file" if extra_data else "No extra data in BMP file"

    except Exception as e:
        print(f"Error processing BMP file: {str(e)}")
        return False, None


