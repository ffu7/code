import requests
from bs4 import BeautifulSoup
import re

def check_backup_files(url):
    extensions = [".bak", ".zip", ".tgz", ".sql"]

    for extension in extensions:
        if extension in url.lower():
          print("Backup Files: Possible backup file found.")
          return extension

def check_for_leakage(content, sensitive_keywords):
    try:
        for keyword in sensitive_keywords:
            if keyword.lower().strip() in content.decode('utf-8').lower():
                return True, keyword
        return False, None
    except Exception as e:
        print(f"Error: {e}")



def check_file(line):
    pattern = r'\.pdf$|\.jpg$|\.jpeg$|\.png$|\.gif$'
    if re.search(pattern, line):
        return True
    else:
        return False
       
def main(folder_name,url):
    file = open(folder_name+'/sensitive_data.txt', 'a')
    payloads_file_path = "payloads/sensitive_payloads.txt"
    backup=check_backup_files(url)
    if backup:
        file.write(f"Possible backup file found at {url} data: {backup}\n")

    with open(payloads_file_path, "r") as payloads_file:
        sensitive_keywords = payloads_file.readlines()
    page_content = requests.get(url)
    pattern = r'(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
    #pattern = r'([a-zA-Z0-9-]+)\.([a-zA-Z0-9]+)\((.*?)\)'

    if page_content.status_code == 200:

        for line in page_content.iter_lines():
            try:
                if not check_file(line.decode('utf-8')):
                    try:
                        leakage_detected, keyword = check_for_leakage(line, sensitive_keywords)
                    except Exception as e:
                        print(f"Error: {e}")
                    if leakage_detected:
                        print(f"Potential information leakage detected! Keyword {keyword} found.")
                        file.write(f"Potential information leakage detected! Keyword : {keyword} found. At {url} : {line}:\n")
                    try:
                        matches = re.findall(pattern, line.decode('utf-8'))
                    except Exception as e:
                        print(f"Error: {e}")
                    if matches:
                        print("AWS access key ID:")
                        for match in matches:
                            print(match)
                            file.write(f"Possible AWS key ID file found at {url} : {line.decode('utf-8')} found : {match}\n")

            except Exception as e:
                print(f"Error: {e}")

    file.close()
