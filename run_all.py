#!/usr/bin/env python3
"""Launcher: start HTTP UI + WebSocket server and (optionally) the sniffer.

Usage: python3 run_all.py [--no-sniffer] [--data] [--http-port PORT]
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-sniffer', action='store_true', help='Start UI only')
    parser.add_argument('--data', action='store_true', help='Start sniffer with --data')
    parser.add_argument('--http-port', type=int, default=8000, help='HTTP port for UI')
    parser.add_argument('--ws-port', type=int, default=8765, help='WebSocket port (unused here)')
    args = parser.parse_args()

    # Start web runner (it will start WS and HTTP)
    print('Starting UI (HTTP + WebSocket)...')
    # Use PYTHONPATH so local package imports work
    env = dict(**{
        'PYTHONPATH': str(Path('.').resolve())
    }, **dict(**{k: v for k, v in sys.environ.items()}))

    ui_proc = subprocess.Popen([sys.executable, 'web/run_server.py'], env=env)
    time.sleep(0.5)
    print('UI launched (PID=%s). HTTP: http://localhost:%s' % (ui_proc.pid, args.http_port))

    sniffer_proc = None
    if not args.no_sniffer:
        # Confirm with user
        print('About to start the packet sniffer. This requires root privileges.')
        resp = input('Proceed and run sniffer with sudo? [y/N]: ').strip().lower()
        if resp == 'y':
            cmd = ['sudo', sys.executable, 'packet_sniffer/sniffer.py']
            if args.data:
                cmd.append('--data')
            print('Starting sniffer...')
            sniffer_proc = subprocess.Popen(cmd, env=env)
            print('Sniffer launched (PID=%s)' % sniffer_proc.pid)
        else:
            print('Skipping sniffer start.')

    try:
        # Wait until terminated by user
        while True:
            time.sleep(1)
            # if sniffer proc ended, report
            if sniffer_proc is not None and sniffer_proc.poll() is not None:
                print('Sniffer terminated with code', sniffer_proc.returncode)
                sniffer_proc = None
    except KeyboardInterrupt:
        print('Stopping services...')
        if sniffer_proc is not None:
            sniffer_proc.terminate()
        ui_proc.terminate()

if __name__ == '__main__':
    main()
