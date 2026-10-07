"""
Shadow.Guard - Cloud Risk Scoring & Rogue Cloud Resource Detector
Server entrypoint redirecting to frontend/server.py.
"""
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from frontend.server import app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "7860"))
    uvicorn.run(app, host="0.0.0.0", port=port)
