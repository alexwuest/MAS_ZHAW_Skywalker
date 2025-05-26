import os
from pathlib import Path
from dotenv import load_dotenv

# Import environment variables
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
OPNSENSE_IP = os.getenv("OPNSENSE_IP")

# Import certificate
CERT_PATH = BASE_DIR / "certificate_crt.pem"

IP_TABLE = {}
DEBUG = True                # Debugging will log to console
DEBUG_ALL = False            # A pain for the console :-)

API_USAGE = 0               # 0 low, 1 medium, 2 high