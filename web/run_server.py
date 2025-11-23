#!/usr/bin/env python3
"""Run a tiny static HTTP server for the UI and start the websocket server.

Usage: python3 web/run_server.py
"""
import http.server
import socketserver
import os
import threading

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / 'web'

def start_http(bind='0.0.0.0', port=8000):
    os.chdir(str(STATIC_DIR))
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer((bind, port), handler)

    thr = threading.Thread(target=httpd.serve_forever, daemon=True)
    thr.start()
    print(f"HTTP UI serving at http://{bind}:{port}/")
    return httpd, thr

if __name__ == '__main__':
    from packet_sniffer.websocket_server import start as start_ws

    start_ws()  # WS on 0.0.0.0:8765
    httpd, thr = start_http()
    try:
        thr.join()
    except KeyboardInterrupt:
        httpd.shutdown()
        print('shutting down')
