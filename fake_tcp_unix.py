"""
fake_tcp_unix.py — Linux/macOS backend using Scapy.

Original technique by @patterniha (https://github.com/patterniha/SNI-Spoofing)
This file is the Unix counterpart of the original fake_tcp.py (WinDivert/Windows).

Requirements:
  pip install scapy
  Run with: sudo python main.py
"""

import sys
import threading
import socket

try:
    from scapy.all import conf, sniff, get_if_list, IP, TCP, Raw, send
    conf.verb = 0
except ImportError:
    sys.exit(
        "[ERROR] scapy is not installed.\n"
        "  Run: pip install scapy\n"
        "  Then: sudo python main.py"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  FakeInjectiveConnection — identical interface to original fake_tcp.py
# ══════════════════════════════════════════════════════════════════════════════

from dataclasses import dataclass, field

@dataclass
class FakeInjectiveConnection:
    sock:          socket.socket
    src_ip:        str
    dst_ip:        str
    src_port:      int
    dst_port:      int
    fake_data:     bytes
    bypass_method: str
    peer_sock:     socket.socket

    syn_seq:       int  = field(default=0,     init=False)
    syn_ack_seq:   int  = field(default=0,     init=False)
    syn_sent:      bool = field(default=False, init=False)
    fake_sent:     bool = field(default=False, init=False)
    monitor:       bool = field(default=True,  init=False)
    t2a_event:     threading.Event = field(default_factory=threading.Event, init=False)
    t2a_msg:       str  = field(default="",    init=False)

    @property
    def id(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    def notify(self, msg: str):
        self.t2a_msg = msg
        self.t2a_event.set()


# ══════════════════════════════════════════════════════════════════════════════
#  FakeTcpInjector — Scapy-based, same interface as original
# ══════════════════════════════════════════════════════════════════════════════

class FakeTcpInjector:
    """
    Drop-in replacement for the WinDivert-based FakeTcpInjector.
    Accepts the same (w_filter, connections) arguments so main.py
    does not need to change.
    """

    def __init__(self, w_filter: str, connections: dict):
        # w_filter is ignored on Unix — Scapy uses BPF "tcp" directly
        self.connections = connections
        self._lock       = threading.Lock()

    # --- find connection by packet direction ---
    def _find_conn(self, src_ip, dst_ip, sport, dport):
        c = self.connections.get((src_ip, dst_ip, sport, dport))
        if c:
            return c, 'out'
        c = self.connections.get((dst_ip, src_ip, dport, sport))
        if c:
            return c, 'in'
        return None, None

    # --- process each captured packet ---
    def _process_packet(self, pkt):
        try:
            if IP not in pkt or TCP not in pkt:
                return
            if not self.connections:
                return

            ip  = pkt[IP]
            tcp = pkt[TCP]
            f   = int(tcp.flags)

            syn     = bool(f & 0x02)
            ack     = bool(f & 0x10)
            fin     = bool(f & 0x01)
            rst     = bool(f & 0x04)
            payload = bytes(tcp.payload) if tcp.payload else b""

            conn, direction = self._find_conn(ip.src, ip.dst, tcp.sport, tcp.dport)
            if not conn or not conn.monitor:
                return

            if direction == 'out':
                # Step 1: SYN — record seq number
                if syn and not ack and not rst and not fin:
                    conn.syn_seq  = tcp.seq
                    conn.syn_sent = True
                    return

                # Step 2: 3rd handshake ACK (no payload) -> inject fake packet
                if (conn.syn_sent
                        and not conn.fake_sent
                        and ack
                        and not syn and not fin and not rst
                        and len(payload) == 0):
                    self._inject_fake(conn)
                    conn.fake_sent = True
                    return

            elif direction == 'in':
                # SYN-ACK — record seq number
                if syn and ack and not rst and not fin:
                    conn.syn_ack_seq = tcp.seq
                    return

                # Unexpected close before inject
                if (rst or fin) and not conn.fake_sent:
                    conn.notify("unexpected_close")
                    return

                # Server ACK after fake inject -> success
                if conn.fake_sent and ack and not syn:
                    conn.notify("fake_data_ack_recv")
                    return

        except Exception:
            pass

    # --- inject fake ClientHello using wrong_seq technique by @patterniha ---
    def _inject_fake(self, conn: FakeInjectiveConnection):
        """
        wrong_seq bypass:
          seq = syn_seq + 1 - len(fake_data)
          Puts the packet BEFORE the server's receive window.
          Server silently drops it; stateful DPI sees the SNI and whitelists the flow.
        """
        fake_seq = (conn.syn_seq + 1 - len(conn.fake_data)) & 0xFFFFFFFF

        pkt = (
            IP(src=conn.src_ip, dst=conn.dst_ip) /
            TCP(
                sport=conn.src_port,
                dport=conn.dst_port,
                flags='A',
                seq=fake_seq,
                ack=conn.syn_ack_seq + 1,
            ) /
            Raw(load=conn.fake_data)
        )
        send(pkt, verbose=False)
        print(f"[FakeTCP] injected fake ClientHello -> {conn.dst_ip}:{conn.dst_port}")

    # --- sniff one interface ---
    def _sniff_iface(self, iface: str):
        try:
            sniff(
                iface=iface,
                filter="tcp",
                prn=self._process_packet,
                store=False,
            )
        except Exception:
            pass  # interface not sniffable -> skip

    # --- entry point (called in a daemon thread by main.py) ---
    def run(self):
        import platform
        OS = platform.system()
        print(f"[FakeTCP] Starting on {OS} (Scapy backend)...")

        try:
            ifaces = get_if_list()
        except Exception:
            ifaces = []

        if not ifaces:
            sys.exit("[FakeTCP] No network interfaces found. Run as root/sudo.")

        print(f"[FakeTCP] Sniffing {len(ifaces)} interface(s)...")

        threads = [
            threading.Thread(target=self._sniff_iface, args=(iface,), daemon=True)
            for iface in ifaces
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
