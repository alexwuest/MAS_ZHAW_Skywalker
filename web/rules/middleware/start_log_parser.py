import threading
from rules.api_logs_parser import parse_logs

parser_started = False

class StartLogParserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        global parser_started
        if not parser_started:
            threading.Thread(target=parse_logs, daemon=True).start()
            parser_started = True
            print("✅ Middleware - Log parser thread started...")

        return self.get_response(request)
