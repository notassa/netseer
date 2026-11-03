#!/usr/bin/env bash
# Start NetSeer from the repo venv with the 'suricata' group (needed to read the Suricata rules).
cd ~/FYP2_netseer && exec sg suricata -c ".venv/bin/uvicorn netseer.src.api.main:app --host 0.0.0.0 --port 8000"
