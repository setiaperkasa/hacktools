import re

#Pengecekan Binari File
def contains_php_code_in_binary(file_path):
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            return b'<?php' in content
    except:
        return False
