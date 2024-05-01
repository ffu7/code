import requests,re
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse,urlencode


#url = 'http://ffu.com/user_info.php'

def extract_base_url(url):
    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    print(base_url)
    return base_url

def remove_parameters_from_url(url):
    parsed_url = urlparse(url)
    parsed_url = parsed_url._replace(query='')
    clean_url = urlunparse(parsed_url)
    return clean_url
    
def replace_query_params(url, new_value):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    for param in query_params:
        query_params[param] = new_value
    new_query_string = urlencode(query_params, doseq=True)
    new_url = parsed_url._replace(query=new_query_string).geturl()
    return new_url

def url_has_parameters(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if query_params:
        return True
    else:
        return False   
def main(folder_name,url):
    file = open(folder_name+'/idor_found.txt', 'a')
    parameters = ["id", "userid", "user_id","username", "user", "query","create", "delete", "edit", "retrieve", "get", "put"]
    user_ids = [1, 2, 4, 6, 8, 9,500] # hedef siteye gore farkli idler eklenmelidir
    base_url=remove_parameters_from_url(url)    
    
    if url_has_parameters(url):
        for user_id in user_ids:
            try:
                new_url = replace_query_params(url, user_id)
                response = requests.get(new_url)
                if response.status_code == 200 and  "User Information" in response.text:
                    file.write(f"Possbile IDOR at URL : {new_url} \n")
            except requests.RequestException:
                pass
    else:
        parameters = ["id", "userid", "user_id","username", "user", "query","create", "delete", "edit", "retrieve", "get", "put"]
        for parameter in parameters:
            for user_id in user_ids:
                try:
                    test_url=base_url + "?" +parameter+"="+ str(user_id)
                    response = requests.get(test_url)
                    if response.status_code == 200 and  "User Information" in response.text:
                        file.write(f"URL : {base_url} /  Paramter : {parameter} /User ID: {user_id}\n")

                except requests.RequestException:
                    pass
    file.close()
