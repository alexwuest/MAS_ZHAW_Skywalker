# rules/ip_enrichment.py
from queue import Queue
import time
from collections import defaultdict
from . import config

ip_enrichment_queue = Queue()
_last_enriched = defaultdict(float)
IP_LOOKUP_COOLDOWN = 360  # seconds

def enqueue_ip(dst_ip, src_ip):
    now = time.time()
    if now - _last_enriched[dst_ip] > IP_LOOKUP_COOLDOWN:
        _last_enriched[dst_ip] = now
        ip_enrichment_queue.put((dst_ip, src_ip))
        if config.DEBUG_ALL:
            print(f"IP queued for enrichment: {dst_ip} (src: {src_ip})", flush=True)
