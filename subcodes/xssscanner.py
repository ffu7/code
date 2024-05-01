import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import urllib3
from pprint import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

vulnerabilities = []  

def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = payload
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value
    print(f"[*] Payload sending to  {target_url} ")
    print(f"[*] Data: {data}")
    if form_details["method"] == "post":
        print(requests.post(target_url, data=data))
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)
        print(requests.get(target_url, params=data))

def scan_xss(url, payload):
        forms = get_all_forms(url)
        print(f"[*] {url} at {len(forms)} a form found.")
        is_vulnerable = False
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, payload).content.decode()
            if payload in content:
                print(f"XSS Found at : {url} ")
                is_vulnerable = True
                vulnerabilities.append({
                    "url": url,
                    "form_details": form_details,
                    "payload": payload,
                })
                break

        if not is_vulnerable:
            print("no xss found")
        return is_vulnerable

def scan_url_with_payloads(folder_name,url, payloads):
    url = url.strip()
    print(f"Tested URL: {url}")
    file = open(folder_name+'/XSS_found.txt', 'a')
    for payload in payloads:
        payload = payload.strip()
        is_vulnerable = scan_xss(url, payload)
        if is_vulnerable:
            print("Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"URL: {vuln['url']}")
                print("Form Details:")
                pprint(vuln["form_details"])
                print(f"Loaded Payload: {vuln['payload']}")
                file.write(f"URL: {vuln['url']}\n")
                file.write(f"Form Details:{vuln['form_details']}\n")
                file.write(f"Loaded Payload: {vuln['payload']}\n")
                file.write("----------------------------\n")
            break

    print("Test completed for given URLS .")
    #file.close()
def main(folder_name,url):
   
    payloads_file_path = "payloads/xss_payloads.txt"
    with open(payloads_file_path, "r") as payloads_file:
        payloads = payloads_file.readlines()

    scan_url_with_payloads(folder_name,url, payloads)

