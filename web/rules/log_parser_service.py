import threading
from .api_logs_parser import parse_logs

def start_log_parser():
    thread = threading.Thread(target=parse_logs, daemon=True)
    thread.start()
    print("✅ Log parser thread started.")
