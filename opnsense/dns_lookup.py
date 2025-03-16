import socket

def reverse_dns_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


ip = input("Enter an IP address to lookup: ")
dns_name = reverse_dns_lookup(ip)
print(f"{ip} -> {dns_name if dns_name else 'No DNS name found'}")
