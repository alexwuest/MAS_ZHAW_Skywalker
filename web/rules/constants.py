DNS_CONFIG = {
    "local": {
        "ip": "192.168.5.1",
        "label": "local (192.168.5.1)",
    },
    "cloudflare": {
        "ip": "1.1.1.1",
        "label": "Cloudflare (1.1.1.1)",
    },
    "google": {
        "ip": "8.8.8.8",
        "label": "Google (8.8.8.8)",
    },
    "quad9": {
        "ip": "9.9.9.9",
        "label": "Quad9 (9.9.9.9)",
    },
}

def get_dns_choices():
    return [(key, value["label"]) for key, value in DNS_CONFIG.items()]