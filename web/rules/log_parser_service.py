import time
import threading
import os
from .ip_enrichment import ip_enrichment_queue
from .api_logs_parser import parse_logs
from .api_firewall_sync import recheck_metadata_seen
from . import config, api_firewall_sync
from .ssh_dns_parser import dns_capture_worker


_log_parser_started = False
_log_parser_lock = threading.Lock()

# TODO Add other functions to classes as well. Better implementation see below!

def start_log_parser():
    global _log_parser_started
    with _log_parser_lock:
        if not _log_parser_started and os.environ.get("RUN_MAIN") == "true":
            _log_parser_started = True
            
            # Start the log parser thread
            threading.Thread(target=parse_logs, daemon=True).start()
            print("✅ Log parser thread started.")

            # Start the IP enrichment worker thread
            threading.Thread(target=enrich_ip_worker, daemon=True).start()
            print("✅ IP enrichment worker thread started.")

            # Start IP queue monitor thread
            threading.Thread(target=print_queue_status, daemon=True).start()
            print("✅ IP queue monitor thread started.")

            # Start recheck MetaDataSeen thread
            threading.Thread(target=recheck_metadata_seen, daemon=True).start()
            print("✅ Recheck MetaDataSeen thread started.")

            # Start the firewall rule verifier thread
            FirewallRuleVerifier().start()
            print("✅ Firewall rule verifier thread started.")

            # Start DNS parser thread
            threading.Thread(target=dns_capture_worker, daemon=True).start()
            print("✅ DNS capture worker thread started.")


def enrich_ip_worker():
    from .api_logs_parser import enrich_ip

    print("🔁 IP enrichment worker running...", flush=True)

    while True:
        dst_ip, src_ip, timestamp = ip_enrichment_queue.get()
        try:
            if config.DEBUG_ALL:
                print(f"🔄 Enriching IP from queue: {dst_ip} (src: {src_ip}, (timestamp {timestamp}))", flush=True)
            enrich_ip(dst_ip, src_ip, timestamp)
        except Exception as e:
            print(f"❌ Failed to enrich {dst_ip}: {e}", flush=True)
        finally:
            ip_enrichment_queue.task_done()


def print_queue_status():
    import time
    while True:
        try:
            qsize = ip_enrichment_queue.qsize()
            print(40*"*")
            print(f"📊 IP Queue size: {qsize}", flush=True)
            queue_list = list(ip_enrichment_queue.queue)
            print(f"🧾 Top queued IPs: {[item[0] for item in queue_list[:5]]}", flush=True)
            print(40*"*")
        except Exception as e:
            print(f"⚠️ Error printing queue: {e}", flush=True)
        time.sleep(60)


class FirewallRuleVerifier(threading.Thread):
    def __init__(self, interval_seconds=60):
        super().__init__(daemon=True)
        self.interval = interval_seconds
        self._stop_event = threading.Event()

    def run(self):
        print("🔁 FirewallRuleVerifier thread started. Running every", self.interval, "seconds", flush=True)
        while not self._stop_event.is_set():
            try:
                print("🛡️ Verifying firewall rules against OPNsense...", flush=True)
                api_firewall_sync.db_opnsense_sync()
            except Exception as e:
                print(f"❌ FirewallRuleVerifier error: {e}", flush=True)
            time.sleep(self.interval)

    def stop(self):
        self._stop_event.set()