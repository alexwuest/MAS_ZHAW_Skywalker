import threading
import os
from .ip_enrichment import ip_enrichment_queue
from .api_logs_parser import parse_logs
from . import config

_log_parser_started = False
_log_parser_lock = threading.Lock()

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


def enrich_ip_worker():
    from .api_logs_parser import enrich_ip

    print("🔁 IP enrichment worker running...", flush=True)

    while True:
        dst_ip, src_ip = ip_enrichment_queue.get()
        try:
            if config.DEBUG:
                print(f"Enriching IP from queue: {dst_ip} (src: {src_ip})", flush=True)
            enrich_ip(dst_ip, src_ip)
        except Exception as e:
            print(f"❌ Failed to enrich {dst_ip}: {e}", flush=True)
        finally:
            ip_enrichment_queue.task_done()
