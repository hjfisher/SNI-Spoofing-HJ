import asyncio
import os
import socket
import sys
import traceback
import threading
import time
import json
import random
import itertools

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


config_path = os.path.join(get_exe_dir(), 'config.json')
with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST           = config["LISTEN_HOST"]
LISTEN_PORT           = config["LISTEN_PORT"]
CONNECT_PORT          = config["CONNECT_PORT"]
HEALTH_CHECK_INTERVAL = config.get("HEALTH_CHECK_INTERVAL", 30)
HEALTH_CHECK_TIMEOUT  = config.get("HEALTH_CHECK_TIMEOUT",  3)
PROBE_COUNT           = config.get("PROBE_COUNT", 5)
ACTIVE_SLOTS          = config.get("ACTIVE_SLOTS", 3)
LOSS_THRESHOLD        = config.get("LOSS_THRESHOLD", 0.20)
DEAD_THRESHOLD        = config.get("DEAD_THRESHOLD", 0.80)

# ── بارگذاری IP و SNI به صورت جداگانه ────────────────────────────────────────
ALL_IPS  = config["CONNECT_IPS"]
ALL_SNIS = [s.encode() for s in config["FAKE_SNIS"]]

# تمام combination های ممکن — برنامه خودش اینا رو داینامیک کشف می‌کنه
ALL_COMBINATIONS = list(itertools.product(ALL_IPS, ALL_SNIS))
print(f"[*] {len(ALL_IPS)} IPs × {len(ALL_SNIS)} SNIs"
      f" = {len(ALL_COMBINATIONS)} possible combinations")

INTERFACE_IPV4 = get_default_interface_ipv4(ALL_IPS[0])
DATA_MODE      = "tls"
BYPASS_METHOD  = "wrong_seq"

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


# ══════════════════════════════════════════════════════════════════════════════
#  PairStats — آمار هر combination (IP, SNI)
# ══════════════════════════════════════════════════════════════════════════════

class PairStats:
    MIN_PROBES = 3

    def __init__(self, ip: str, sni: bytes):
        self.ip  = ip
        self.sni = sni

        self.probes_sent: int = 0
        self.probes_recv: int = 0
        self.real_packets_sent: int = 0
        self.real_packets_lost: int = 0

        self.active_connections: int = 0
        self.total_connections:  int = 0
        self.alive:         bool = True
        self.probed:        bool = False   # آیا حداقل یه بار تست شده؟
        self.in_active_pool:bool = False

        self.lock = threading.Lock()

    @property
    def probe_loss_rate(self) -> float:
        if self.probes_sent < self.MIN_PROBES:
            return 0.0
        return (self.probes_sent - self.probes_recv) / self.probes_sent

    @property
    def real_loss_rate(self) -> float:
        if self.real_packets_sent == 0:
            return 0.0
        return self.real_packets_lost / self.real_packets_sent

    @property
    def combined_loss_rate(self) -> float:
        if self.real_packets_sent > 10:
            return 0.7 * self.real_loss_rate + 0.3 * self.probe_loss_rate
        return self.probe_loss_rate

    @property
    def score(self) -> float:
        if not self.alive:
            return float('inf')
        if not self.probed:
            return 0.5   # ناشناخته — شانس تست گرفتن داره
        return self.combined_loss_rate

    @property
    def is_stable(self) -> bool:
        return self.alive and self.probed and self.combined_loss_rate < LOSS_THRESHOLD

    def record_probe(self, success: bool):
        with self.lock:
            self.probes_sent += 1
            self.probed = True
            if success:
                self.probes_recv += 1
            if self.probes_sent >= self.MIN_PROBES:
                loss = (self.probes_sent - self.probes_recv) / self.probes_sent
                if loss >= DEAD_THRESHOLD:
                    self.alive = False
                elif self.probes_recv > 0:
                    self.alive = True

    def record_real_packet(self, lost: bool):
        with self.lock:
            self.real_packets_sent += 1
            if lost:
                self.real_packets_lost += 1


# ══════════════════════════════════════════════════════════════════════════════
#  CombinationExplorer — کشف داینامیک combination های خوب
# ══════════════════════════════════════════════════════════════════════════════

class CombinationExplorer:
    """
    به جای تست همه combination ها یکجا (که می‌تونه خیلی زیاد باشه)،
    این کلاس به صورت داینامیک و تصادفی combination ها رو کشف می‌کنه:

    - ابتدا یه subset تصادفی از همه combination ها رو probe می‌کنه
    - در هر دوره بعدی:
        * combination های خوب رو مجدداً verify می‌کنه
        * یه batch تصادفی جدید از combination های ناشناخته رو probe می‌کنه
    - این باعث می‌شه همیشه دنبال گزینه‌های بهتر بگرده
      بدون اینکه همه رو یکجا تست کنه
    """
    INITIAL_SAMPLE  = 20   # چند تا در اول تست می‌شه
    EXPLORE_BATCH   = 10   # در هر دوره چند تای جدید کشف می‌شه
    VERIFY_TOP      = 15   # چند تا از بهترین‌ها در هر دوره verify می‌شن

    def __init__(self, combinations: list[tuple[str, bytes]],
                 port: int, timeout: float, probe_count: int):
        self.port        = port
        self.timeout     = timeout
        self.probe_count = probe_count

        # map از (ip, sni) به PairStats
        self.stats: dict[tuple, PairStats] = {}
        for ip, sni in combinations:
            self.stats[(ip, sni)] = PairStats(ip, sni)

        # combination های هنوز تست‌نشده (shuffled)
        self._unexplored = list(combinations)
        random.shuffle(self._unexplored)

        self._lock = threading.Lock()

    def all_stats(self) -> list[PairStats]:
        return list(self.stats.values())

    def known_stats(self) -> list[PairStats]:
        """فقط اونایی که حداقل یه بار probe شدن"""
        return [ps for ps in self.stats.values() if ps.probed]

    # ── probe یک pair ─────────────────────────────────────────────────────
    def _probe_one(self, ps: PairStats):
        count = self.probe_count + random.randint(-1, 1)
        count = max(2, count)
        for _ in range(count):
            try:
                sock = socket.create_connection(
                    (ps.ip, self.port), timeout=self.timeout)
                sock.close()
                ps.record_probe(success=True)
            except Exception:
                ps.record_probe(success=False)
            time.sleep(random.uniform(0.05, 0.2))

    def _run_probes_parallel(self, pairs: list[PairStats]):
        random.shuffle(pairs)
        threads = [threading.Thread(target=self._probe_one, args=(ps,), daemon=True)
                   for ps in pairs]
        for t in threads:
            t.start()
            time.sleep(random.uniform(0, 0.03))
        for t in threads:
            t.join()

    # ── مرحله اول: probe اولیه ───────────────────────────────────────────
    def initial_explore(self):
        """یه subset تصادفی از combination های ناشناخته رو تست می‌کنه"""
        with self._lock:
            batch_keys = self._unexplored[:self.INITIAL_SAMPLE]
            self._unexplored = self._unexplored[self.INITIAL_SAMPLE:]
        batch = [self.stats[k] for k in batch_keys]
        print(f"[Explorer] Initial probe: {len(batch)} combinations...")
        self._run_probes_parallel(batch)

    # ── دوره‌های بعدی: verify + explore ──────────────────────────────────
    def periodic_explore(self):
        """
        ۱. بهترین‌های شناخته‌شده رو verify کن
        ۲. یه batch جدید از ناشناخته‌ها رو کشف کن
        """
        # verify بهترین‌های فعلی
        known = sorted(self.known_stats(), key=lambda x: x.score)
        to_verify = known[:self.VERIFY_TOP]
        if to_verify:
            print(f"[Explorer] Verifying top {len(to_verify)} known pairs...")
            self._run_probes_parallel(to_verify)

        # کشف batch جدید از ناشناخته‌ها
        with self._lock:
            batch_keys = self._unexplored[:self.EXPLORE_BATCH]
            self._unexplored = self._unexplored[self.EXPLORE_BATCH:]
            remaining = len(self._unexplored)

        if batch_keys:
            batch = [self.stats[k] for k in batch_keys]
            print(f"[Explorer] Exploring {len(batch)} new combinations"
                  f"  ({remaining} remaining unexplored)")
            self._run_probes_parallel(batch)
        else:
            # همه کشف شدن — از اول shuffle کن و دوباره شروع کن
            print("[Explorer] All combinations explored — reshuffling for next cycle")
            with self._lock:
                all_keys = list(self.stats.keys())
                random.shuffle(all_keys)
                self._unexplored = all_keys

    def print_summary(self):
        known   = self.known_stats()
        stable  = [ps for ps in known if ps.is_stable]
        weak    = [ps for ps in known if ps.alive and not ps.is_stable]
        dead    = [ps for ps in known if not ps.alive]
        unknown = len(self.stats) - len(known)

        print(f"\n{'═'*65}")
        print(f"[Explorer] known={len(known)}  stable={len(stable)}"
              f"  weak={len(weak)}  dead={len(dead)}  unexplored={unknown}")
        print(f"{'─'*65}")
        for ps in sorted(stable, key=lambda x: x.score)[:8]:
            marker = "●" if ps.in_active_pool else " "
            print(f" {marker} {ps.ip:<20} {ps.sni.decode():<25}"
                  f" loss={ps.combined_loss_rate*100:4.1f}%"
                  f" active={ps.active_connections}")
        print(f"{'═'*65}")


# ══════════════════════════════════════════════════════════════════════════════
#  ActivePool
# ══════════════════════════════════════════════════════════════════════════════

class ActivePool:
    def __init__(self, explorer: CombinationExplorer, slots: int):
        self.explorer = explorer
        self.slots    = slots
        self._pool:     list[PairStats] = []
        self._draining: list[PairStats] = []
        self._lock = threading.Lock()

    def initialize(self):
        with self._lock:
            candidates = [ps for ps in self.explorer.known_stats() if ps.is_stable]
            if not candidates:
                candidates = [ps for ps in self.explorer.known_stats() if ps.alive]
            if not candidates:
                candidates = self.explorer.known_stats()
            random.shuffle(candidates)
            self._pool = candidates[:self.slots]
            for ps in self._pool:
                ps.in_active_pool = True
        self._print_pool("INIT")

    def refresh(self):
        with self._lock:
            # آزاد کردن draining‌های خالی
            self._draining = [ps for ps in self._draining
                              if ps.active_connections > 0]
            for ps in [p for p in self._draining if p.active_connections == 0]:
                ps.in_active_pool = False

            # حذف ضعیف‌ها
            weak = [ps for ps in self._pool if not ps.is_stable]
            for ps in weak:
                self._pool.remove(ps)
                self._draining.append(ps)

            # پر کردن جاهای خالی از بهترین‌های شناخته‌شده
            in_use = set(id(ps) for ps in self._pool + self._draining)
            candidates = [
                ps for ps in self.explorer.known_stats()
                if ps.is_stable and id(ps) not in in_use
            ]
            if not candidates:
                candidates = [
                    ps for ps in self.explorer.known_stats()
                    if ps.alive and id(ps) not in in_use
                ]

            needed = self.slots - len(self._pool)
            if needed > 0 and candidates:
                weights = [1.0 / (ps.combined_loss_rate + 0.01) for ps in candidates]
                chosen = []
                tc, tw = candidates[:], weights[:]
                for _ in range(min(needed, len(tc))):
                    pick = random.choices(tc, weights=tw, k=1)[0]
                    idx  = tc.index(pick)
                    chosen.append(pick)
                    tc.pop(idx); tw.pop(idx)
                for ps in chosen:
                    ps.in_active_pool = True
                    self._pool.append(ps)

        self._print_pool("REFRESH")

    def pick(self) -> PairStats:
        with self._lock:
            pool = self._pool if self._pool else self.explorer.known_stats()
            if not pool:
                pool = self.explorer.all_stats()
            weights = [1.0 / (ps.combined_loss_rate + 0.01) for ps in pool]
            return random.choices(pool, weights=weights, k=1)[0]

    def report_failure(self, ps: PairStats):
        ps.record_probe(success=False)
        if not ps.is_stable:
            self.refresh()

    def _print_pool(self, reason: str):
        print(f"\n[Pool/{reason}] active={len(self._pool)}"
              f"  draining={len(self._draining)}")
        for ps in self._pool:
            print(f"  ● {ps.ip:<18} {ps.sni.decode():<25}"
                  f" loss={ps.combined_loss_rate*100:4.1f}%"
                  f" conns={ps.active_connections}")
        for ps in self._draining:
            print(f"  ↓ {ps.ip:<18} draining... conns={ps.active_connections}")


# ══════════════════════════════════════════════════════════════════════════════
#  ConnectionManager
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:

    def __init__(self, combinations, port, interval, timeout, probe_count, slots):
        self.explorer = CombinationExplorer(combinations, port, timeout, probe_count)
        self.pool     = ActivePool(self.explorer, slots)
        self.interval = interval

    def run_health_loop(self):
        # probe اولیه
        self.explorer.initial_explore()
        self.pool.initialize()
        self.explorer.print_summary()

        while True:
            jitter = random.uniform(-5, 5)
            time.sleep(max(10, self.interval + jitter))
            self.explorer.periodic_explore()
            self.pool.refresh()
            self.explorer.print_summary()

    def pick_pair(self) -> PairStats:
        return self.pool.pick()

    def report_failure(self, ps: PairStats):
        self.pool.report_failure(ps)


# ══════════════════════════════════════════════════════════════════════════════
#  relay و handle
# ══════════════════════════════════════════════════════════════════════════════

async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket,
                          peer_task: asyncio.Task, first_prefix_data: bytes,
                          pair_stats: PairStats):
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    raise ValueError("eof")
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                pair_stats.record_real_packet(lost=False)
                sent_len = await loop.sock_sendall(sock_2, data)
                if sent_len != len(data):
                    pair_stats.record_real_packet(lost=True)
                    raise ValueError("incomplete send")
            except Exception:
                sock_1.close()
                sock_2.close()
                peer_task.cancel()
                return
    except Exception:
        traceback.print_exc()
        sys.exit("relay main loop error!")


async def handle(incoming_sock: socket.socket, addr, manager: ConnectionManager):
    try:
        loop = asyncio.get_running_loop()

        pair = manager.pick_pair()
        connect_ip = pair.ip
        fake_sni   = pair.sni

        with pair.lock:
            pair.active_connections += 1
            pair.total_connections  += 1

        print(f"[+] {addr[0]}:{addr[1]} → {connect_ip}"
              f"  sni={fake_sni.decode()}"
              f"  loss={pair.combined_loss_rate*100:.1f}%"
              f"  active={pair.active_connections}")

        def _release(lost=False):
            with pair.lock:
                pair.active_connections = max(0, pair.active_connections - 1)
            if lost:
                pair.record_real_packet(lost=True)
                manager.report_failure(pair)

        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), fake_sni, os.urandom(32)
            )
        else:
            sys.exit("impossible mode!")

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)

        src_port = outgoing_sock.getsockname()[1]

        fake_injective_conn = FakeInjectiveConnection(
            outgoing_sock, INTERFACE_IPV4, connect_ip, src_port, CONNECT_PORT,
            fake_data, BYPASS_METHOD, incoming_sock
        )
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn

        try:
            await loop.sock_connect(outgoing_sock, (connect_ip, CONNECT_PORT))
        except Exception:
            _release(lost=True)
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            outgoing_sock.close()
            incoming_sock.close()
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                    sys.exit("impossible t2a msg!")
            except Exception:
                _release(lost=True)
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        del fake_injective_connections[fake_injective_conn.id]

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock,
                            asyncio.current_task(), b"", pair))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"", pair)

        _release(lost=False)

    except Exception:
        traceback.print_exc()
        sys.exit("handle should not raise exception")


async def main(manager: ConnectionManager):
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
    mother_sock.listen()

    loop = asyncio.get_running_loop()
    print(f"[*] Listening on {LISTEN_HOST}:{LISTEN_PORT}"
          f"  |  active_slots={ACTIVE_SLOTS}")
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET,  socket.SO_KEEPALIVE,  1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT,   3)
        asyncio.create_task(handle(incoming_sock, addr, manager))


if __name__ == "__main__":
    print("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424")
    print("@patterniha\n")

    manager = ConnectionManager(
        ALL_COMBINATIONS, CONNECT_PORT,
        HEALTH_CHECK_INTERVAL, HEALTH_CHECK_TIMEOUT,
        PROBE_COUNT, ACTIVE_SLOTS
    )
    threading.Thread(target=manager.run_health_loop, daemon=True).start()

    all_ips = list(dict.fromkeys(ALL_IPS))
    ip_conditions = " or ".join(
        f"(ip.SrcAddr == {ip} and ip.DstAddr == {INTERFACE_IPV4}) or "
        f"(ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {ip})"
        for ip in all_ips
    )
    w_filter = f"tcp and ({ip_conditions})"

    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, daemon=True).start()

    asyncio.run(main(manager))
