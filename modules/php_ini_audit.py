import os

def find_php_ini(web_server_root):
    # Tambahkan logika untuk menemukan php.ini berdasarkan direktori root server web
    # Ini adalah fungsi pengganti dan memerlukan implementasi yang tepat
    # Lokasi umum: /etc/php/, /usr/local/lib/, root server web, dll.
    return "/path/to/php.ini"

def parse_php_ini(file_path):
    config = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.strip() and not line.startswith(';'):
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    return config

def audit_php_config(config):
    # Tentukan aturan audit Anda di sini
    # Misalnya, periksa safe_mode, expose_php, dll.
    issues = []
    if config.get('safe_mode', 'Off').lower() != 'on':
        issues.append('safe_mode is not enabled')
    if config.get('expose_php', 'On').lower() != 'off':
        issues.append('expose_php should be turned off')
    if config.get('allow_url_fopen', 'On').lower() == 'on':
        issues.append('allow_url_fopen should be turned off for security reasons')
    if config.get('display_errors', 'Off').lower() != 'off':
        issues.append('display_errors should be turned off for security reasons')
    if config.get('error_reporting', '').lower() != 'e_all':
        issues.append('error_reporting should be set to E_ALL')
    # Tambahkan lebih banyak aturan sesuai kebutuhan
    return issues

def main(web_server_root):
    php_ini_path = find_php_ini(web_server_root)
    if os.path.exists(php_ini_path):
        config = parse_php_ini(php_ini_path)
        issues = audit_php_config(config)
        if issues:
            print("PHP Configuration Issues Found:")
            for issue in issues:
                print(f"- {issue}")
        else:
            print("No issues found in PHP configuration.")
    else:
        print(f"php.ini file not found in {web_server_root}")

if __name__ == "__main__":
    WEB_SERVER_ROOT = '/var/www/'  # Contoh jalur, sesuaikan seperlunya
    main(WEB_SERVER_ROOT)
