import subprocess
import re
import os
import time

from django.db import IntegrityError

from collections import deque
from threading import Thread

from .models import DNSRecord
from . import config

ssh_key_path = os.path.expanduser("~/.ssh/opnsense_key")

# Buffers to track queries with timestamps
query_buffer = {}

# Cleanup queue to drop stale queries after timeout
cleanup_queue = deque()

timeout_seconds = 5

# Query line: IP src > dst: <txid>+ <type>? <domain>
query_re = re.compile(
    r'(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(?P<src_ip>[\d.]+)\.(?P<src_port>\d+)\s+>\s+(?P<dst_ip>[\d.]+)\.53: (?P<txid>\d+)\+ (?P<qtype>A|AAAA|PTR|HTTPS)\? (?P<domain>[^\s]+)',
    re.IGNORECASE
)

answer_re = re.compile(
    r'(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(?P<dst_ip>[\d.]+)\.53\s+>\s+(?P<src_ip>[\d.]+)\.(?P<src_port>\d+):\s+(?P<txid>\d+)\s+[^\s]*\s+(?P<rest>.*)',
    re.IGNORECASE
)



def dns_capture_worker():
    print("🔁 DNS capture worker running...")

    ssh_cmd = [
        "ssh",
        "-i", ssh_key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        config.SSH_PARSER_ADDRESS,
        "tcpdump -i igc1 port 53 -n -l"
    ]

    proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    # Start cleanup thread
    Thread(target=clean_expired_queries, daemon=True).start()

    for line in proc.stdout:
        line = line.strip()
        if config.DEBUG_DNS:
            print(f"📦 {line}", flush=True)

        query = query_re.search(line)
        if query:
            txid = query.group("txid")
            query_data = {
                "timestamp": query.group("ts"),
                "source_ip": query.group("src_ip"),
                "query_type": query.group("qtype"),
                "domain": query.group("domain"),
                "raw_line": line,
                "added_at": time.time(),
            }
            query_buffer[(txid, query.group("src_port"))] = query_data
            cleanup_queue.append((txid, query.group("src_port"), time.time()))
            if config.DEBUG_DNS:
                print(f"DNS SSH Parser - Buffered query: {query_data}", flush=True)
            continue

        answer = answer_re.search(line)
        if answer:
            txid = answer.group("txid")
            dst_ip = answer.group("dst_ip")
            key = (txid, answer.group("src_port"))

            if key in query_buffer:
                query_data = query_buffer.pop(key)
                rest = answer.group("rest")

                if config.DEBUG_DNS:
                    print(f"DNS SSH Parser - Answer rest: {rest}", flush=True)

                resolved_ips = [
                    m.group("rip")
                    for m in re.finditer(r'(?:A|AAAA|PTR) (?P<rip>[\da-fA-F:.]+|[\w.-]+)', rest)
                ]

                for rip in resolved_ips:
                    source_ip = query_data["source_ip"]
                    domain = query_data["domain"]
                    query_type = query_data["query_type"]
                    raw_line = query_data["raw_line"]

                    record = DNSRecord.objects.filter(
                        source_ip=source_ip,
                        resolved_ip=rip,
                        query_type=query_type,
                        domain=domain
                    ).first()

                    if record:
                        try:
                            record.save()  # auto_now updates timestamp
                            #if config.DEBUG_DNS:
                            print(f"🕓 DNS SSH Parser - Updated existing record: {domain} -> {rip}", flush=True)
                        except Exception as e:
                            print(f"❌ DNS SSH Parser - Failed to update record: {e}", flush=True)
                    else:
                        try:
                            DNSRecord.objects.create(
                                source_ip=source_ip,
                                domain=domain,
                                query_type=query_type,
                                resolved_ip=rip,
                                raw_line=raw_line
                            )
                            if config.DEBUG_DNS:
                                print(f"✅ DNS SSH Parser - Stored new DNS: {domain} -> {rip}", flush=True)
                        except Exception as e:
                            print(f"❌ DNS SSH Parser - Failed to store DNS: {e}", flush=True)

            else:
                print(f"⚠️ DNS SSH Parser - No match found for txid {txid} from {dst_ip}", flush=True)

def clean_expired_queries():
    while True:
        now = time.time()
        while cleanup_queue and (now - cleanup_queue[0][2]) > timeout_seconds:
            txid, src_port, _ = cleanup_queue.popleft()
            removed = query_buffer.pop((txid, src_port), None)
            if removed:
                print(f"⏱️ Removed stale query: {removed['domain']}", flush=True)
        time.sleep(1)
