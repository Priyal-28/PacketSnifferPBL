Packet Sniffer — Web UI
=======================

This file describes how to run the experimental Web UI that ships in
the `web/` folder. The UI connects to the sniffer via a WebSocket and
shows a live, filterable view of captured frames.

Quick steps
-----------
1. Install dependencies:

```bash
pip3 install -r requirements.txt
```

2. Start the static HTTP + WebSocket server (serves UI on port 8000):

```bash
PYTHONPATH=. python3 web/run_server.py
```

3. Start the sniffer (requires root):

```bash
PYTHONPATH=. sudo python3 packet_sniffer/sniffer.py --data
```

4. Open your browser at http://localhost:8000/

What you'll see
---------------
- Live frame list on the left. Each item is clickable; when clicked, the
  details JSON for that frame appears in the right-hand panel.
- Filter checkboxes at the top let you select which protocols to display.

Troubleshooting
---------------
- If the sniffer exits immediately with a permission error, make sure you run
  it with `sudo` because raw sockets need elevated privileges.
- If the browser shows no frames, ensure `web/run_server.py` is running and
  the sniffer is started with `PYTHONPATH=.` so the local package imports are found.
- If you see "ModuleNotFoundError: No module named 'websockets'", install
  dependencies (`pip3 install websockets` or `pip3 install -r requirements.txt`).

Notes
-----
- This UI is intentionally minimal and for development/demo only. It is not
  hardened for production use. Consider using tls/wss and authentication if
  exposing it beyond localhost.
