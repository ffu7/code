import requests

def getSubdomains(folder_name,domain):
    print('# Subdomain scanner')
    domainLower = domain.lower()
    if domainLower.startswith('www.'):
        domainLower = domainLower.replace('www.', '')

    # Get subdomains from CRT.SH site.
    req = requests.get('https://crt.sh/?q={}'.format(domainLower)).text.splitlines()
    subdomains = set()
    for line in req:
        if '<BR>' in line:
            subdomain = line.replace('<TD>', '').replace('<BR>', ' ').replace('</TD>', '').split()
            try:
                for i in range(0, 5):
                    if subdomain[i] not in subdomains:
                        if '*.' in subdomain[i]:
                            pass
                        else:
                            if domainLower in subdomain[i]:
                                subdomains.add(subdomain[i])
            except:
                pass

    # Get subdomains from hackertarget.com
    req = requests.get('https://api.hackertarget.com/hostsearch/?q={}'.format(domainLower)).text.splitlines()
    for subdomain in req:
        subdomain = subdomain.replace(',' , ' ').split()
        if subdomain[0] in subdomains:
            pass
        else:
            subdomains.add(subdomain[0])

           
    if len(subdomains) > 1:
        print('- {} Subdomains found, Results have been saved'.format(len(subdomains)))
        file = open(folder_name+'/subdomains.txt', 'a')
        for domain in subdomains:
            file.write(domain+'\n')
        file.close()
    else:
        print('- No subdomains found')
