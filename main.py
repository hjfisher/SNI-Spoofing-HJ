import asyncio
import os
import socket
import sys
import traceback
import threading
import time
import json
import random
from collections import deque

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
# تعداد pairهایی که همزمان active نگه داشته می‌شن
ACTIVE_SLOTS          = config.get("ACTIVE_SLOTS", 3)
# آستانه loss برای جابجایی بدون قطع session
LOSS_THRESHOLD        = config.get("LOSS_THRESHOLD", 0.20)
DEAD_THRESHOLD        = config.get("DEAD_THRESHOLD", 0.80)

if "CONNECT_PAIRS" in config:
    ALL_PAIRS = [(p["ip"], p["sni"].encode()) for p in config["CONNECT_PAIRS"]]
else:
    raw_ips  = config.get("CONNECT_IPS", config.get("CONNECT_IP"))
    raw_snis = config.get("FAKE_SNIS",   config.get("FAKE_SNI"))
    ips  = raw_ips  if isinstance(raw_ips,  list) else [raw_ips]
    snis = raw_snis if isinstance(raw_snis, list) else [raw_snis]
    ALL_PAIRS = [(ip, sni.encode()) for ip in ips for sni in snis]

INTERFACE_IPV4 = get_default_interface_ipv4(ALL_PAIRS[0][0])
DATA_MODE      = "tls"
BYPASS_METHOD  = "wrong_seq"

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


# ══════════════════════════════════════════════════════════════════════════════
#  PairStats
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
        self.alive: bool = True
        self.in_active_pool: bool = False   # آیا الان در pool فعال هست؟

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
        return self.combined_loss_rate

    @property
    def is_stable(self) -> bool:
        return self.alive and self.combined_loss_rate < LOSS_THRESHOLD

    def record_probe(self, success: bool):
        with self.lock:
            self.probes_sent += 1
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
#  ActivePool — مدیریت ACTIVE_SLOTS تا اتصال همزمان
# ══════════════════════════════════════════════════════════════════════════════

class ActivePool:
    """
    همیشه ACTIVE_SLOTS تا pair را گرم نگه می‌دارد.
    قوانین:
    - انتخاب اولیه: تصادفی از بین stable‌ها (نه خطی)
    - جابجایی: فقط وقتی یه pair از LOSS_THRESHOLD رد شد
    - جابجایی graceful: pair قدیمی تا بسته شدن کانکشن‌های فعلی‌اش
      در pool می‌ماند (draining)، pair جدید بلافاصله کانکشن‌های
      جدید را می‌گیرد
    """

    def __init__(self, all_stats: list[PairStats], slots: int):
        self.all_stats  = all_stats
        self.slots      = slots
        self._pool: list[PairStats]      = []   # pairهای فعال
        self._draining: list[PairStats]  = []   # در حال drain (graceful exit)
        self._lock = threading.Lock()

    def initialize(self):
        """انتخاب اولیه تصادفی"""
        with self._lock:
            candidates = [ps for ps in self.all_stats if ps.is_stable]
            if not candidates:
                candidates = [ps for ps in self.all_stats if ps.alive]
            if not candidates:
                candidates = self.all_stats[:]

            # shuffle کامل، نه خطی
            random.shuffle(candidates)
            self._pool = candidates[:self.slots]
            for ps in self._pool:
                ps.in_active_pool = True
        self._print_pool("INIT")

    def refresh(self):
        """
        بعد از هر health-check صدا زده می‌شه:
        - pairهای ضعیف را به draining می‌فرستد
        - جای خالی را با بهترین (بر اساس کمترین loss) پر می‌کند
        - انتخاب از بین کاندیداها تصادفی‌وزن‌دار است
        """
        with self._lock:
            replaced = False

            # draining‌هایی که کانکشن فعال ندارند را آزاد کن
            still_draining = []
            for ps in self._draining:
                if ps.active_connections > 0:
                    still_draining.append(ps)
                else:
                    ps.in_active_pool = False
            self._draining = still_draining

            # پیدا کردن pairهای ضعیف در pool
            weak = [ps for ps in self._pool if not ps.is_stable]
            for ps in weak:
                self._pool.remove(ps)
                self._draining.append(ps)   # graceful: کانکشن‌های فعلی‌شان ادامه دارند
                replaced = True

            # پر کردن جاهای خالی
            in_use = set(id(ps) for ps in self._pool + self._draining)
            candidates = [
                ps for ps in self.all_stats
                if ps.is_stable and id(ps) not in in_use
            ]
            if not candidates:
                candidates = [
                    ps for ps in self.all_stats
                    if ps.alive and id(ps) not in in_use
                ]

            needed = self.slots - len(self._pool)
            if needed > 0 and candidates:
                # انتخاب weighted-random (کمترین loss = وزن بیشتر)
                weights = [1.0 / (ps.combined_loss_rate + 0.01) for ps in candidates]
                chosen = []
                temp_candidates = candidates[:]
                temp_weights    = weights[:]
                for _ in range(min(needed, len(temp_candidates))):
                    pick = random.choices(temp_candidates, weights=temp_weights, k=1)[0]
                    idx  = temp_candidates.index(pick)
                    chosen.append(pick)
                    temp_candidates.pop(idx)
                    temp_weights.pop(idx)
                for ps in chosen:
                    ps.in_active_pool = True
                    self._pool.append(ps)
                    replaced = True

            if replaced:
                self._print_pool("REFRESH")

    def pick(self) -> PairStats:
        """
        یه pair از pool برای کانکشن جدید.
        weighted-random بر اساس کمترین loss.
        """
        with self._lock:
            pool = self._pool if self._pool else self.all_stats
            weights = [1.0 / (ps.combined_loss_rate + 0.01) for ps in pool]
            return random.choices(pool, weights=weights, k=1)[0]

    def report_failure(self, ps: PairStats):
        """یه pair مستقیم fail کرد — سریع‌تر از health-check بررسی شه"""
        ps.record_probe(success=False)
        if not ps.is_stable:
            self.refresh()

    def _print_pool(self, reason: str):
        print(f"\n[Pool/{reason}] active slots={len(self._pool)}"
              f"  draining={len(self._draining)}")
        for ps in self._pool:
            print(f"  ● {ps.ip:<20} loss={ps.combined_loss_rate*100:4.1f}%"
                  f"  conns={ps.active_connections}")
        for ps in self._draining:
            print(f"  ↓ {ps.ip:<20} draining... conns={ps.active_connections}")


# ══════════════════════════════════════════════════════════════════════════════
#  ConnectionManager
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:

    def __init__(self, pairs, port, interval, timeout, probe_count, slots):
        self.stats: list[PairStats] = [PairStats(ip, sni) for ip, sni in pairs]
        self.port        = port
        self.interval    = interval
        self.timeout     = timeout
        self.probe_count = probe_count
        self.pool        = ActivePool(self.stats, slots)

    def _probe_random_order(self, stats_list: list[PairStats]):
        """
        probe همه pair‌ها به ترتیب تصادفی (نه خطی).
        هر probe در thread جداگانه.
        """
        shuffled = stats_list[:]
        random.shuffle(shuffled)

        def probe_one(ps):
            # تعداد probe را هم تصادفی کمی تغییر بده (jitter)
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
                # تاخیر تصادفی بین probeها (jitter)
                time.sleep(random.uniform(0.05, 0.2))

        threads = [threading.Thread(target=probe_one, args=(ps,), daemon=True)
                   for ps in shuffled]
        # شروع با تاخیر تصادفی کوچک بین هر thread (نه همه یکجا)
        for t in threads:
            t.start()
            time.sleep(random.uniform(0, 0.05))
        for t in threads:
            t.join()

    def run_health_loop(self):
        # اول یه چک سریع
        self._probe_random_order(self.stats)
        self.pool.initialize()
        self._print_status()

        while True:
            # فاصله بین چک‌ها هم کمی jitter داره
            jitter = random.uniform(-5, 5)
            time.sleep(max(10, self.interval + jitter))
            self._probe_random_order(self.stats)
            self.pool.refresh()
            self._print_status()

    def pick_pair(self) -> PairStats:
        return self.pool.pick()

    def report_failure(self, ps: PairStats):
        self.pool.report_failure(ps)

    def _print_status(self):
        stable = sorted([ps for ps in self.stats if ps.is_stable],  key=lambda x: x.score)
        weak   = [ps for ps in self.stats if ps.alive and not ps.is_stable]
        dead   = [ps for ps in self.stats if not ps.alive]
        print(f"\n{'═'*62}")
        print(f"[Health] stable={len(stable)}  weak={len(weak)}  dead={len(dead)}")
        print(f"{'─'*62}")
        for ps in stable[:10]:
            marker = "●" if ps.in_active_pool else " "
            print(f" {marker} {ps.ip:<20} loss={ps.combined_loss_rate*100:4.1f}%"
                  f"  active={ps.active_connections}")
        if weak or dead:
            print(f"  ⚠ weak={len(weak)}  ✗ dead={len(dead)}")
        print(f"{'═'*62}")


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
    print(f"[*] {len(ALL_PAIRS)} pairs  |  active_slots={ACTIVE_SLOTS}"
          f"  |  loss_threshold={LOSS_THRESHOLD*100:.0f}%"
          f"  |  check_interval={HEALTH_CHECK_INTERVAL}s")

    manager = ConnectionManager(
        ALL_PAIRS, CONNECT_PORT,
        HEALTH_CHECK_INTERVAL, HEALTH_CHECK_TIMEOUT,
        PROBE_COUNT, ACTIVE_SLOTS
    )
    threading.Thread(target=manager.run_health_loop, daemon=True).start()

    all_ips = list(dict.fromkeys(ip for ip, _ in ALL_PAIRS))
    ip_conditions = " or ".join(
        f"(ip.SrcAddr == {ip} and ip.DstAddr == {INTERFACE_IPV4}) or "
        f"(ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {ip})"
        for ip in all_ips
    )
    w_filter = f"tcp and ({ip_conditions})"

    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, daemon=True).start()

    asyncio.run(main(manager))
