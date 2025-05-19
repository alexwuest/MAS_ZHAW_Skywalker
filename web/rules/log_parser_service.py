import os
import threading
from .api_logs_parser import parse_logs

_log_parser_started = False
_log_parser_lock = threading.Lock()

def start_log_parser():
    global _log_parser_started
    with _log_parser_lock:
        if not _log_parser_started and os.environ.get("RUN_MAIN") == "true":
            _log_parser_started = True
            thread = threading.Thread(target=parse_logs, daemon=True)
            thread.start()
            print("✅ Log parser thread started.")
