import argparse
import os

from core import PacketSniffer
from output import OutputToScreen
from output import OutputToWeb


parser = argparse.ArgumentParser(description="Network packet sniffer")
parser.add_argument(
    "-i", "--interface",
    type=str,
    default=None,
    help="Interface from which Ethernet frames will be captured (monitors "
         "all available interfaces by default)."
)
parser.add_argument(
    "-d", "--data",
    action="store_true",
    help="Output packet data during capture."
)
_args = parser.parse_args()

if os.getuid() != 0:
    raise SystemExit("Error: Permission denied. This application requires "
                     "administrator privileges to run.")

OutputToScreen(
    subject=(sniffer := PacketSniffer()),
    display_data=_args.data
)

# Also broadcast to any connected web UI clients. This import is optional
# and will silently fail if websockets/server isn't available.
try:
    OutputToWeb(subject=sniffer, display_data=_args.data)
except Exception:
    pass

try:
    for _ in sniffer.listen(_args.interface):
        '''Iterate through the frames yielded by the listener in an 
        infinite cycle while feeding them to all registered observers 
        for further processing/output'''
        pass
except KeyboardInterrupt:
    raise SystemExit("[!] Aborting packet capture...")
