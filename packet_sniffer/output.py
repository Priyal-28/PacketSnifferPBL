#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import time
from abc import ABC, abstractmethod
from typing import Any


class Output(ABC):
    """Interface for the implementation of all classes responsible for
    further processing/output of the information gathered by the
    PacketSniffer class."""

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass


i = " " * 4  # Basic indentation level


class OutputToScreen(Output):
    def __init__(self, subject, *, display_data: bool):
        """Output data from a decoded frame to screen.

        :param subject: Instance of PacketSniffer to be observed.
        :param display_data: Boolean specifying the output of captured
            data.
        """
        super().__init__(subject)
        self._frame = None
        self._display_data = display_data
        self._initialize()

    @staticmethod
    def _initialize() -> None:
        print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
              "data. Press Ctrl-C to abort...\n")

    def update(self, frame) -> None:
        self._frame = frame
        self._display_output_header()
        self._display_protocol_info()
        self._display_packet_contents()

    def _display_output_header(self) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime())
        print(f"[>] Frame #{self._frame.packet_num} at {local_time}:")

    def _display_protocol_info(self) -> None:
        """Iterate through a protocol queue and call the appropriate
        display protocol method."""
        for proto in self._frame.protocol_queue:
            try:
                getattr(self, f"_display_{proto.lower()}_data")()
            except AttributeError:
                print(f"{'':>4}[+] Unknown Protocol")

    def _display_ethernet_data(self) -> None:
        ethernet = self._frame.ethernet
        interface = "all" if self._frame.interface is None \
            else self._frame.interface
        frame_length: int = self._frame.frame_length
        epoch_time: float = self._frame.epoch_time
        print(f"{i}[+] Ethernet {ethernet.src:.>23} -> {ethernet.dst}")
        print(f"{2 * i}  Interface: {interface}")
        print(f"{2 * i}  Frame Length: {frame_length}")
        print(f"{2 * i}  Epoch Time: {epoch_time}")

    def _display_ipv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        print(f"{i}[+] IPv4 {ipv4.src:.>27} -> {ipv4.dst: <15}")
        print(f"{2 * i}  DSCP: {ipv4.dscp}")
        print(f"{2 * i}  Total Length: {ipv4.len}")
        print(f"{2 * i}  ID: {ipv4.id}")
        print(f"{2 * i}  Flags: {ipv4.flags_str}")
        print(f"{2 * i}  TTL: {ipv4.ttl}")
        print(f"{2 * i}  Protocol: {ipv4.encapsulated_proto}")
        print(f"{2 * i}  Header Checksum: {ipv4.chksum_hex_str}")

    def _display_ipv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        print(f"{i}[+] IPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")
        print(f"{2 * i}  Traffic Class: {ipv6.tclass_hex_str}")
        print(f"{2 * i}  Flow Label: {ipv6.flabel_txt_str}")
        print(f"{2 * i}  Payload Length: {ipv6.payload_len}")
        print(f"{2 * i}  Next Header: {ipv6.encapsulated_proto}")
        print(f"{2 * i}  Hop Limit: {ipv6.hop_limit}")

    def _display_arp_data(self) -> None:
        arp = self._frame.arp
        if arp.oper == 1:  # ARP Request
            print(f"{i}[+] ARP Who has {arp.tpa:.>18} ? -> Tell {arp.spa}")
        else:              # ARP Reply
            print(f"{i}[+] ARP {arp.spa:.>28} -> Is at {arp.sha}")
        print(f"{2 * i}  Hardware Type: {arp.htype}")
        print(f"{2 * i}  Protocol Type: {arp.ptype_str} "
              f"({arp.ptype_hex_str})")
        print(f"{2 * i}  Hardware Length: {arp.hlen}")
        print(f"{2 * i}  Protocol Length: {arp.plen}")
        print(f"{2 * i}  Operation: {arp.oper} ({arp.oper_str})")
        print(f"{2 * i}  Sender Hardware Address: {arp.sha}")
        print(f"{2 * i}  Sender Protocol Address: {arp.spa}")
        print(f"{2 * i}  Target Hardware Address: {arp.tha}")
        print(f"{2 * i}  Target Protocol Address: {arp.tpa}")

    def _display_tcp_data(self) -> None:
        tcp = self._frame.tcp
        print(f"{i}[+] TCP {tcp.sport:.>28} -> {tcp.dport: <15}")
        print(f"{2 * i}  Sequence Number: {tcp.seq}")
        print(f"{2 * i}  ACK Number: {tcp.ack}")
        print(f"{2 * i}  Flags: {tcp.flags_hex_str} > {tcp.flags_str}")
        print(f"{2 * i}  Window Size: {tcp.window}")
        print(f"{2 * i}  Checksum: {tcp.chksum_hex_str}")
        print(f"{2 * i}  Urgent Pointer: {tcp.urg}")

    def _display_udp_data(self) -> None:
        udp = self._frame.udp
        print(f"{i}[+] UDP {udp.sport:.>28} -> {udp.dport}")
        print(f"{2 * i}  Header Length: {udp.len}")
        print(f"{2 * i}  Header Checksum: {udp.chksum}")

    def _display_icmpv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        icmpv4 = self._frame.icmpv4
        print(f"{i}[+] ICMPv4 {ipv4.src:.>27} -> {ipv4.dst: <15}")
        print(f"{2 * i}  ICMP Type: {icmpv4.type} ({icmpv4.type_str})")
        print(f"{2 * i}  Header Checksum: {icmpv4.chksum_hex_str}")

    def _display_icmpv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        icmpv6 = self._frame.icmpv6
        print(f"{i}[+] ICMPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")
        print(f"{2 * i}  Control Message Type: {icmpv6.type} "
              f"({icmpv6.type_str})")
        print(f"{2 * i}  Control Message Subtype: {icmpv6.code}")
        print(f"{2 * i}  Header Checksum: {icmpv6.chksum_hex_str}")

    def _display_packet_contents(self) -> None:
        if self._display_data is True:
            print(f"{i}[+] DATA:")
            data = (self._frame.data.decode(errors="ignore").
                    replace("\n", f"\n{i * 2}"))
            print(f"{i}{data}")


class OutputToWeb(Output):
    """Adapter that broadcasts a JSON-serializable summary of the frame
    to connected WebSocket clients using the websocket_server.broadcast()
    function. This keeps the console output intact and simply provides a
    machine-friendly view for the UI.
    """
    def __init__(self, subject, *, display_data: bool = False):
        try:
            # Import locally to avoid requiring the package unless used.
            from .websocket_server import broadcast
        except Exception:
            broadcast = None  # type: ignore
        self._broadcast = broadcast
        self._display_data = display_data
        super().__init__(subject)

    def update(self, frame: Any) -> None:
        if self._broadcast is None:
            return
        # Base payload
        payload = {
            'packet_num': getattr(frame, 'packet_num', None),
            'protocol_queue': getattr(frame, 'protocol_queue', []),
            'frame_length': getattr(frame, 'frame_length', None),
            'epoch_time': getattr(frame, 'epoch_time', None),
        }

        # Helper to safely extract attributes
        def _safe(obj, *attrs):
            try:
                for a in attrs:
                    obj = getattr(obj, a)
                return obj
            except Exception:
                return None

        # Ethernet
        if hasattr(frame, 'ethernet'):
            payload['ethernet'] = {
                'src': _safe(frame.ethernet, 'src'),
                'dst': _safe(frame.ethernet, 'dst'),
                'type': _safe(frame.ethernet, 'ptype_str') or _safe(frame.ethernet, 'ptype_hex_str')
            }

        # IPv4
        if hasattr(frame, 'ipv4'):
            ipv4 = frame.ipv4
            payload['ipv4'] = {
                'src': _safe(ipv4, 'src'),
                'dst': _safe(ipv4, 'dst'),
                'len': _safe(ipv4, 'len'),
                'ttl': _safe(ipv4, 'ttl'),
                'proto': _safe(ipv4, 'encapsulated_proto')
            }

        # IPv6
        if hasattr(frame, 'ipv6'):
            ipv6 = frame.ipv6
            payload['ipv6'] = {
                'src': _safe(ipv6, 'src'),
                'dst': _safe(ipv6, 'dst'),
                'payload_len': _safe(ipv6, 'payload_len'),
                'next_header': _safe(ipv6, 'encapsulated_proto')
            }

        # ARP
        if hasattr(frame, 'arp'):
            arp = frame.arp
            payload['arp'] = {
                'spa': _safe(arp, 'spa'),
                'tpa': _safe(arp, 'tpa'),
                'sha': _safe(arp, 'sha'),
                'tha': _safe(arp, 'tha'),
                'oper': _safe(arp, 'oper')
            }

        # TCP
        if hasattr(frame, 'tcp'):
            tcp = frame.tcp
            payload['tcp'] = {
                'sport': _safe(tcp, 'sport'),
                'dport': _safe(tcp, 'dport'),
                'seq': _safe(tcp, 'seq'),
                'ack': _safe(tcp, 'ack'),
                'flags': _safe(tcp, 'flags_str')
            }

        # UDP
        if hasattr(frame, 'udp'):
            udp = frame.udp
            payload['udp'] = {
                'sport': _safe(udp, 'sport'),
                'dport': _safe(udp, 'dport'),
                'len': _safe(udp, 'len')
            }

        # ICMP
        if hasattr(frame, 'icmpv4'):
            icmp = frame.icmpv4
            payload['icmpv4'] = {
                'type': _safe(icmp, 'type'),
                'code': _safe(icmp, 'code')
            }
        if hasattr(frame, 'icmpv6'):
            icmp6 = frame.icmpv6
            payload['icmpv6'] = {
                'type': _safe(icmp6, 'type'),
                'code': _safe(icmp6, 'code')
            }
        if self._display_data:
            try:
                payload['data'] = frame.data.decode(errors='ignore')
            except Exception:
                payload['data'] = None
        # Non-blocking broadcast
        try:
            self._broadcast(payload)
        except Exception:
            pass


class OutputToFile(Output):
    """Append detailed JSON lines to a file for persistent logging."""
    def __init__(self, subject, *, path: str = 'sniffer_log.jsonl', display_data: bool = False):
        self.path = path
        self._display_data = display_data
        super().__init__(subject)

    def update(self, frame: Any) -> None:
        # Reuse OutputToWeb's payload creation logic by building a dict here
        payload = {
            'packet_num': getattr(frame, 'packet_num', None),
            'protocol_queue': getattr(frame, 'protocol_queue', []),
            'frame_length': getattr(frame, 'frame_length', None),
            'epoch_time': getattr(frame, 'epoch_time', None),
        }
        try:
            payload['data'] = frame.data.decode(errors='ignore') if self._display_data else None
        except Exception:
            payload['data'] = None

        import json
        try:
            with open(self.path, 'a', encoding='utf8') as f:
                f.write(json.dumps(payload, default=str) + '\n')
        except Exception:
            # Do not raise from update
            pass
