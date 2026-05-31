"""
fake_tcp_unix.py — Linux / macOS / Android backend using Scapy.

Original technique by @patterniha (https://github.com/patterniha/SNI-Spoofing)

Requirements:
  pip install scapy
  Linux/macOS: sudo python main.py
  Android (Termux): run as root (tsu / su -c)
"""

import sys
import threading
import socket
import platform

OS     = platform.system()
IS_ANDROID = hasattr(platform, 'android_ver') or 'ANDROID_ROOT' in __import__('os').environ

try:
    from scapy.all import conf, sniff, get_if_list, IP, TCP, Raw, send
    conf.verb = 0
    # on Android/Termux, L3 socket works better than L2
    if IS_ANDROID:
        conf.L3socket = __import__('scapy.supersocket', fromlist=['L3RawSocket']).L3RawSocket
except ImportError:
    sys.exit(
        "[ERROR] scapy is not installed.\n"
        "  Run: pip install scapy\n"
        "  Android: pkg install python && pip install scapy"
    )

from dataclasses import dataclass, field


# ══════════════════════════════════════════════════════════════════════════════
#  FakeInjectiveConnection — identical interface to original fake_tcp.py
# ══════════════════════════════════════════════════════════════════════════════

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
#  FakeTcpInjector
# ══════════════════════════════════════════════════════════════════════════════

class FakeTcpInjector:
    """
    Drop-in replacement for WinDivert-based FakeTcpInjector.
    Accepts same (w_filter, connections) arguments as original.
    """

    def __init__(self, w_filter: str, connections: dict):
        self.connections = connections
        self._lock       = threading.Lock()

    def _find_conn(self, src_ip, dst_ip, sport, dport):
        c = self.connections.get((src_ip, dst_ip, sport, dport))
        if c:
            return c, 'out'
        c = self.connections.get((dst_ip, src_ip, dport, sport))
        if c:
            return c, 'in'
        return None, None

    def _process_packet(self, pkt):
        try:
            if IP not in pkt or TCP not in pkt:
                return
            if not self.connections:
                return

            ip      = pkt[IP]
            tcp     = pkt[TCP]
            f       = int(tcp.flags)
            syn     = bool(f & 0x02)
            ack     = bool(f & 0x10)
            fin     = bool(f & 0x01)
            rst     = bool(f & 0x04)
            payload = bytes(tcp.payload) if tcp.payload else b""

            conn, direction = self._find_conn(ip.src, ip.dst, tcp.sport, tcp.dport)
            if not conn or not conn.monitor:
                return

            if direction == 'out':
                if syn and not ack and not rst and not fin:
                    conn.syn_seq  = tcp.seq
                    conn.syn_sent = True
                    return
                if (conn.syn_sent and not conn.fake_sent
                        and ack and not syn and not fin and not rst
                        and len(payload) == 0):
                    self._inject_fake(conn)
                    conn.fake_sent = True
                    return

            elif direction == 'in':
                if syn and ack and not rst and not fin:
                    conn.syn_ack_seq = tcp.seq
                    return
                if (rst or fin) and not conn.fake_sent:
                    conn.notify("unexpected_close")
                    return
                if conn.fake_sent and ack and not syn:
                    conn.notify("fake_data_ack_recv")
                    return

        except Exception:
            pass

    def _inject_fake(self, conn: FakeInjectiveConnection):
        """wrong_seq bypass — original technique by @patterniha"""
        fake_seq = (conn.syn_seq + 1 - len(conn.fake_data)) & 0xFFFFFFFF
        pkt = (
            IP(src=conn.src_ip, dst=conn.dst_ip) /
            TCP(sport=conn.src_port, dport=conn.dst_port,
                flags='A', seq=fake_seq, ack=conn.syn_ack_seq + 1) /
            Raw(load=conn.fake_data)
        )
        send(pkt, verbose=False)
        print(f"[FakeTCP] injected fake ClientHello -> {conn.dst_ip}:{conn.dst_port}")

    def _sniff_iface(self, iface: str):
        try:
            sniff(iface=iface, filter="tcp",
                  prn=self._process_packet, store=False)
        except Exception:
            pass

    def _get_interfaces(self) -> list[str]:
        """
        Get sniffable interfaces.
        Android/Termux: manually add common interface names
        since get_if_list() may return nothing.
        """
        try:
            ifaces = get_if_list()
        except Exception:
            ifaces = []

        if IS_ANDROID or not ifaces:
            # common Android interface names
            android_ifaces = ['wlan0', 'rmnet0', 'rmnet_data0',
                              'rmnet_data1', 'lo', 'tun0', 'ccmni0']
            import os
            # also scan /sys/class/net which works on Android
            try:
                sys_ifaces = os.listdir('/sys/class/net')
                android_ifaces = list(set(android_ifaces + sys_ifaces))
            except Exception:
                pass
            # merge with whatever scapy found
            ifaces = list(set(ifaces + android_ifaces))

        return [i for i in ifaces if i]  # filter empty strings

    def run(self):
        label = f"{OS}{'(Android)' if IS_ANDROID else ''}"
        print(f"[FakeTCP] Starting on {label} (Scapy backend)...")

        # check root on Android
        if IS_ANDROID:
            import os
            if os.geteuid() != 0:
                sys.exit(
                    "[ERROR] Android: root is required.\n"
                    "  Run: su -c 'python main.py'\n"
                    "  Or use Termux with tsu: tsu -c 'python main.py'"
                )

        ifaces = self._get_interfaces()
        if not ifaces:
            sys.exit(
                f"[FakeTCP] No interfaces found on {label}.\n"
                "  Linux/macOS: run with sudo\n"
                "  Android: run as root with su"
            )

        print(f"[FakeTCP] Sniffing {len(ifaces)} interface(s): {ifaces}")

        threads = [
            threading.Thread(target=self._sniff_iface, args=(iface,), daemon=True)
            for iface in ifaces
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
