import os
import sys
import json

def api_check():
    if not os.environ.get("FD_API_KEY"):
        error = {
            "status": "error",
            "error": "Missing FD_API_KEY environment variable. Please set it before running this command."
        }
        print(json.dumps(error))
        sys.exit(1) 