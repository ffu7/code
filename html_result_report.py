import requests, socket, os
from datetime import date

def file_has_data(file_path):
    try:
        with open(file_path, 'r') as file:
            first_line = file.readline()
            return bool(first_line)  
    except FileNotFoundError:
        return False


def generate(folder_name,domain, url):
    today = date.today()
    #picture_path = "../ffusubcodes/ffu.jpg"
    background_color = "Orange"
    # Open the HTML report file in write mode
    with open(folder_name+"/report.html", "w") as f:
        # Write the HTML header
        f.write("<html>\n")
        f.write("<head>\n")
        f.write("<title>Web Vulnerability Report</title>\n")
        f.write("</head>\n")
        f.write("<body style='background-color: {}' opacity: 0.3;>\n".format(background_color))
        """
        f.write(f"<img src='{picture_path}' alt='Picture' width='50' height='50'>")
        f.write("<h1>"+domain+"\n Web Vulnerability Report \n"+format(today)+"</h1>\n")
       """
        f.write("<div style='display: inline-block;'>")
        #f.write(f"<img src='{picture_path}' alt='FUU' width='50' height='50'>"+ )
        f.write('<h1><b><span style="color: red;">Web Vulnerability Report </h1></b></span><h2>Tested Domain :'  + domain + " / Test Date     : "+ format(today) + "</h2>")
        try:
            response = requests.head(url, allow_redirects=True)
            server_header = response.headers.get('Server')
            if server_header:
                f.write("<h2>Server Info : {} </h2>\n".format(server_header))
        except requests.RequestException as e:
            print(f"Error: {e}")
        

        f.write("</div>")
        # Loop through each findings
        if file_has_data(folder_name+"/shodan.txt"):
            with open(folder_name+"/shodan.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Information found on shodan.io</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/ports.txt"):
            with open(folder_name+"/ports.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Open Ports</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/Headers.txt"):
            with open(folder_name+"/Headers.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Header security related vulnerabailities</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/metafiles.txt"):
            with open(folder_name+"/metafiles.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Meta Files found on the server</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/admin_entry_points.txt"):
            with open(folder_name+"/admin_entry_points.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible Admin login pages</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/sqli_DB_found.txt"):
            with open(folder_name+"/sqli_DB_found.txt", "r") as txt_file:
                content = txt_file.read()
                if len(content) >30:
                    f.write(f"<h2>Possible data base name found</h2>\n")
                    f.write("<pre>\n")
                    f.write(content)
                    f.write("</pre>\n")
        if file_has_data(folder_name+"/command_injection_found.txt"):
            with open(folder_name+"/command_injection_found.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible command injection found</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/directorylisting.txt"):
            with open(folder_name+"/directorylisting.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible directorylisting vulnerabailities</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/sensitive_data.txt"):
            with open(folder_name+"/sensitive_data.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible sensitive data</h2>\n")
                f.write("<pre>\n")
                content=content.replace('<!--', '&lt;!--')
                f.write(content)
                f.write("</pre>\n")
                
        if file_has_data(folder_name+"/logs_data.txt"):
            with open(folder_name+"/logs_data.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible logs files found</h2>\n")
                f.write("<pre>\n")
                content=content.replace('<!--', '&lt;!--')
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/sqli_found.txt"):
            with open(folder_name+"/sqli_found.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible sql injection vulnerabailities</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/XSS_found.txt"):
            with open(folder_name+"/XSS_found.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible XSS related vulnerabailities</h2>\n")
                f.write("<pre>\n")
                content=content.replace('<script', '&lt;script')
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/idor_found.txt"):
            with open(folder_name+"/idor_found.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Possible IDOR vulnerabailities</h2>\n")
                f.write("<pre>\n")
                content=content.replace('<script', '&lt;script')
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/non_main_domain_urls.txt"):
            with open(folder_name+"/non_main_domain_urls.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>non main domain related urls</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
        if file_has_data(folder_name+"/subdomains.txt"):        
            with open(folder_name+"/subdomains.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>subdomains related to main domain </h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
                
                
        # kaldirilacak ??????????
        if file_has_data(folder_name+"/form_urls.txt"):        
            with open(folder_name+"/form_urls.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>URLs containing forms</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
           
        if file_has_data(folder_name+"/urls.txt"):    
            with open(folder_name+"/urls.txt", "r") as txt_file:
                content = txt_file.read()
                f.write(f"<h2>Found urls</h2>\n")
                f.write("<pre>\n")
                f.write(content)
                f.write("</pre>\n")
    
        f.write("</body>\n")
        f.write("</html>\n")


#https://htmlcolorcodes.com/
#<h1 style="background-color:Orange;">Orange</h1>

