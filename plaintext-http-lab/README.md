# Plaintext HTTP Credential Detector + Dashboard

## Run (Ubuntu / WSL2 / Mac)
    python3 -m venv .venv-linux && source .venv-linux/bin/activate
    pip install -r requirements.txt
    python detector.py

## Run (Windows PowerShell, uses the included .venv)
    .\.venv\Scripts\Activate.ps1
    python detector.py

Open  http://localhost:5000/dashboard   (page auto-refreshes every 5 s)

## Trigger a real detection (second terminal)
    python attack.py
    # or
    curl -X POST -d "password=Fake123&api_key=FAKE-KEY" http://localhost:5000/login

Note: do not run server.py at the same time - it also uses port 5000.
