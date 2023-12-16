import subprocess
import json
from PIL import Image
from PIL.ExifTags import TAGS
import os
import re

#Pengecekan Gambar
def is_valid_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except:
        return False
        
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
            else:
                return {}  # Return an empty dictionary for non-JPEG images
    except Exception as e:
        raise RuntimeError(f"Error processing file {image_path}: {str(e)}")


def analyze_metadata(metadata):
    # Define patterns that might indicate suspicious content
    suspicious_patterns = [
        r'<script.*?>.*?</script>',  # JavaScript or HTML scripts
        r'eval\s*\(.*\)',            # Usage of 'eval' function
        r'base64_decode\s*\(.*\)',   # Base64 decoding functions
        r'[A-Za-z0-9+/=]{50,}',      # Long Base64-like strings (change length as needed)
        # Add more patterns as needed
    ]

    for tag, value in metadata.items():
        if isinstance(value, str):  # Check only string type metadata
            for pattern in suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return True, f"Suspicious content found in {tag}: {value}"
    
    return False, "No suspicious metadata found."
