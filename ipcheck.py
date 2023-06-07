
def is_private_ip(ip):
    
    if ":" in ip:
        # IPv6 address
        if ip.startswith("fc") or ip.startswith("fd"):
            return True
        return False
    else:
        # IPv4 address
        ip = ip.split(".")
        if ip[0] == "10":
            return True
        elif ip[0] == "172" and 16 <= int(ip[1]) <= 31:
            return True
        elif ip[0] == "192" and ip[1] == "168":
            return True
        return False


