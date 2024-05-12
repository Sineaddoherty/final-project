import subprocess
import requests

def get_firewall(url, Waf):
    if Waf:
        command = f' {url}'
        try:
             #-- REQUESTS INFORMATION FROM URL  
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
             #-- print out error with issue with url 
        except subprocess.CalledProcessError as error:
            output = f"Error: {error}"
            return output

    else:
        response = requests.get(url)
        response = response.headers
        #-- different firewall that can be etected
        server_waf = ['waf', 'cloudflare', 'akamaigHost', 'naxsi']
        
        if response.get('server') and response.get('server') in server_waf:
            #-- print firewalls of URL 
            result = '[-] Firewall detected : ', response.get('server'),
        else:
            #-- no firewall found of URL
            result = '[+] No firewall detected'

        return result
