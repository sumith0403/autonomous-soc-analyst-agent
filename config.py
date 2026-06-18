import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# Wazuh
WAZUH_URL = os.getenv("WAZUH_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

# Severity thresholds
SEVERITY_CRITICAL = 15
SEVERITY_HIGH = 10
SEVERITY_MEDIUM = 5
SEVERITY_LOW = 0

# ChromaDB path
CHROMA_DB_PATH = "./storage/chroma_db"
PLAYBOOKS_PATH = "./playbooks"