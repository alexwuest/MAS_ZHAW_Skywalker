from django.apps import AppConfig
import sys

class RulesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'rules'

    def ready(self):
        if any(cmd in sys.argv for cmd in ['runserver', 'gunicorn', 'daphne', 'uvicorn']):
            try:
                from .api_logs_parser import start_log_parser
                start_log_parser()
                print("✅ Background log parser started.")
            except Exception as e:
                print(f"⚠️ Failed to start log parser: {e}")
