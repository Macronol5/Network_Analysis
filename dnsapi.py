import socket

def getdnsname(IP):
    try:
        domain_name = socket.gethostbyaddr(IP)[0]
        dns_name = domain_name
    except socket.herror as error:
        dns_name = error
    return dns_name

# print(getdnsname("40.99.34.226"))