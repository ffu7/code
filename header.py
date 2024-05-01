import requests

def hedaersCheck(folder_name,url):
    #domain = url.split("//")[-1].split("/")[0].split('?')[0]
    file = open(folder_name+"/Headers.txt", 'a')
            
    #  kontrol et ???
    def getServer(url):
        try:
            req = requests.get(url, verify=False).headers
            print("- Server: " + req['Server'])
            file.write("- Server: " + req['Server'])
           
        except:
            pass


    def httpMethods(url):
        
        try:
            #supported_methods = get_supported_methods(url)
            response = requests.options(url)
            if response.status_code == 200:
                allowed_methods = response.headers.get('Allow')
                print('-HTTP methods: ' + allowed_methods+'\n')
                file.write('-HTTP methods: ' + allowed_methods+'\n')
            else:
                print("Failed to retrieve supported methods.")

        except:
            pass

    def checkCSP(url):
        try:
            req = requests.get(url, verify=False).headers
            if 'Content-Security-Policy' in req:
                pass
            else:
                print("- Content Security Policy (CSP) not implemented")
                file.write('- Content-Security-Policy header missing (Potential XSS vulnerability)'+'\n')
        except:
            pass

    def checkClickjacking(url):
        try:
            req = requests.get(url, verify=False).headers
            if 'X-Frame-Options' in req:
                pass
            else:
                print("- Clickjacking: X-Frame-Options header missing")
                file.write('- X-Frame-Options header missing (Clickjacking vulnerability)'+'\n')
        except:
            pass

    def checkMissingXSSProtection(url):
        try:
            req = requests.get(url, verify=False).headers
            if 'X-XSS-Protection' in req:
                pass
            else:
                print("- X-XSS-Protection header missing")
                file.write('- X-XSS-Protection header missing (Potential XSS vulnerability)'+'\n')
        except:
            pass

    def checkCORS(url):
        try:
            req = requests.get(url, headers={"Origin":"https://noweb.com"}, verify=False).headers
            if req['Access-Control-Allow-Origin'] == "https://noweb.com":
                print("- Cross-origin Resource Sharing (CORS) misconfiguration")
                file.write('- Cross-origin Resource Sharing (CORS) misconfiguration'+'\n')
        except:
            pass

    def hostHeaderAttack(url):
        try:
            req = requests.get(url, headers={'Host': 'noweb.com'}, verify=False, allow_redirects=False).headers
            if "noweb.com" in req['Location']:
                print("- Vulnerable to Host header attack{}".format(url))
                file.write("- Vulnerable to Host header attack\n")
        except:
            pass


    def check_headers_vulnerabilities(url):
      try:
        response = requests.get(url)
        headers = response.headers
        
        if 'Server' in headers:
            print(f"[-] Server header found: {headers['Server']} (May reveal server details)")
            file.write(f"- Server header found: {headers['Server']} (May reveal server details)"+'\n')

        if 'Strict-Transport-Security' not in headers:
            print(f"-Strict-Transport-Security header missing (HTTP to HTTPS downgrade vulnerability)")
            file.write('- Strict-Transport-Security header missing (HTTP to HTTPS downgrade vulnerability)'+'\n')
        if 'X-Content-Type-Options' not in headers:
            print(f"- X-Content-Type-Options header missing (MIME sniffing vulnerability)")
            file.write('- X-Content-Type-Options header missing (MIME sniffing vulnerability)'+'\n')
      except requests.exceptions.RequestException as e:
        print(f"[!] An error occurred: {e}")


    getServer(url)
    httpMethods(url)
    checkCSP(url)
    checkClickjacking(url)
    checkMissingXSSProtection(url)
    checkCORS(url)
    hostHeaderAttack(url)
    check_headers_vulnerabilities(url)
    file.close()