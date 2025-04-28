import os
from django.apps import AppConfig

class RulesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'rules'

    def ready(self):
        if os.environ.get('RUN_MAIN') == 'true':
            from .log_parser_service import start_log_parser
            start_log_parser()
