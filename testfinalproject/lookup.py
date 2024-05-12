import socket
from ipwhois import IPWhois


def whois(webpage):
       #-- using Socket to get acess to URL
    ip = socket.gethostbyname(webpage)
     #-- using API
    object = IPWhois(ip)
    results = object.lookup_whois()
    return results
