import requests
from urllib.parse import urlparse

def getSubdomains(folder_name,target_url):
    print('# keywrod based Subdomain finder')
    domain_name = urlparse(target_url.strip()).netloc
    domainLower = domain_name.lower()
    if domainLower.startswith('www.'):
        domainLower = domainLower.replace('www.', '')

    subdomains = set()
 
    payloads_file_path = "payloads/sub_domain_payloads.txt"
    with open(payloads_file_path, "r") as payloads_file:
        subs = payloads_file.readlines()    

    for sub in subs:
        sub = sub.strip()
        suburl = sub + "." + domainLower
        print("Testing : "+suburl)
        try:
            response = requests.get("http://" + suburl,timeout=1)
            if response.status_code == 200:
                 subdomains.add(suburl)
            else:
                pass
        except:
            pass
        try:
            response = requests.get("https://" + suburl,timeout=1)
            if response.status_code == 200:
                 subdomains.add(suburl)
            else:
                pass
        except:
            pass
           
    if subdomains:
        print('- {} Subdomains found, Results have been saved'.format(len(subdomains)))
        file = open(folder_name+'/subdomains.txt', 'a')
        for domain in subdomains:
            file.write(domain+'\n')
            print(domain)
        file.close()
    else:
        print('- No subdomains found')
