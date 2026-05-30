# SNI Spoofing — Enhanced Fork

این مخزن یک fork از پروژه اصلی [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) است.

صمیمانه از **@patterniha** تشکر می‌کنیم که این ابزار را با هدف دسترسی آزاد به اینترنت برای مردم ایران توسعه داده و به صورت متن‌باز منتشر کرده است. ایده اصلی، معماری پایه، و تمام منطق WinDivert/fake TCP از کار ایشان است.

---

## تغییرات این Fork

### ۱. پشتیبانی از لیست IP و SNI
در نسخه اصلی فقط یک IP و یک SNI در `config.json` قابل تنظیم بود. در این نسخه می‌توان لیستی از pair های `(IP, SNI)` تعریف کرد:

```json
"CONNECT_PAIRS": [
  {"ip": "188.114.96.0", "sni": "hcaptcha.com"},
  {"ip": "104.16.0.1",   "sni": "hcaptcha.com"}
]
```

### ۲. Health-Check داینامیک بر اساس Packet Loss
به جای latency، معیار اصلی انتخاب **packet loss** است:
- هر pair به صورت دوره‌ای probe می‌شود
- نرخ loss از traffic واقعی هم ردیابی می‌شود (وزن ۷۰٪)
- pairهایی با بیش از `LOSS_THRESHOLD` (پیش‌فرض ۲۰٪) ضعیف و بیش از `DEAD_THRESHOLD` (پیش‌فرض ۸۰٪) مرده اعلام می‌شوند

### ۳. Multi-Path — اتصال همزمان به چند نقطه
پارامتر `ACTIVE_SLOTS` تعداد pair های همزمان فعال را کنترل می‌کند. کانکشن‌های جدید با weighted-random بین این slot ها پخش می‌شوند:

```json
"ACTIVE_SLOTS": 3
```

### ۴. Graceful Handoff — جابجایی بدون قطع session
وقتی یک pair ضعیف می‌شود:
- بلافاصله وارد حالت **draining** می‌شود
- کانکشن‌های فعلی آن بدون قطع ادامه می‌یابند
- کانکشن‌های جدید به pair جایگزین می‌روند
- هیچ session ای قطع نمی‌شود

### ۵. Probe تصادفی (نه خطی)
- ترتیب probe هر دوره کاملاً shuffle می‌شود
- شروع هر thread با تاخیر تصادفی کوچک (jitter)
- تعداد probe هر pair کمی متغیر است

---

## نصب و راه‌اندازی

پیش‌نیازها همان پروژه اصلی است. به [README اصلی](https://github.com/patterniha/SNI-Spoofing) مراجعه کنید.

```bash
git clone https://github.com/YOUR_USERNAME/SNI-Spoofing
cd SNI-Spoofing
pip install -r requirements.txt
python main.py
```

---

## تنظیمات `config.json`

| کلید | پیش‌فرض | توضیح |
|------|---------|-------|
| `LISTEN_HOST` | `0.0.0.0` | آدرس listen |
| `LISTEN_PORT` | `40443` | پورت listen |
| `CONNECT_PORT` | `443` | پورت مقصد |
| `ACTIVE_SLOTS` | `3` | تعداد pair های همزمان فعال |
| `HEALTH_CHECK_INTERVAL` | `30` | فاصله بین health-check ها (ثانیه) |
| `HEALTH_CHECK_TIMEOUT` | `3` | timeout هر probe (ثانیه) |
| `PROBE_COUNT` | `5` | تعداد probe در هر دوره |
| `LOSS_THRESHOLD` | `0.20` | آستانه ضعیف (۲۰٪ loss) |
| `DEAD_THRESHOLD` | `0.80` | آستانه مرده (۸۰٪ loss) |
| `CONNECT_PAIRS` | — | لیست pair های `(ip, sni)` |

### نمونه کامل config.json

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_PORT": 443,
  "ACTIVE_SLOTS": 3,
  "HEALTH_CHECK_INTERVAL": 30,
  "HEALTH_CHECK_TIMEOUT": 3,
  "PROBE_COUNT": 5,
  "LOSS_THRESHOLD": 0.20,
  "DEAD_THRESHOLD": 0.80,
  "CONNECT_PAIRS": [
    {"ip": "188.114.96.0", "sni": "hcaptcha.com"},
    {"ip": "188.114.97.0", "sni": "hcaptcha.com"},
    {"ip": "104.16.0.1",   "sni": "hcaptcha.com"},
    {"ip": "172.67.0.1",   "sni": "hcaptcha.com"}
  ]
}
```

---

## خروجی نمونه

```
[*] 96 pairs  |  active_slots=3  |  loss_threshold=20%  |  check_interval=30s

[Pool/INIT] active slots=3  draining=0
  ● 188.114.96.1        loss= 0.0%  conns=0
  ● 104.16.0.1          loss= 2.1%  conns=0
  ● 172.67.1.1          loss= 4.3%  conns=0

[+] 127.0.0.1:54321 → 188.114.96.1  loss=0.0%  active=1
[+] 127.0.0.1:54322 → 104.16.0.1    loss=2.1%  active=1

[Health] stable=71  weak=18  dead=7
  ● 188.114.96.1        loss= 0.0%  active=3
  ● 104.16.0.1          loss= 1.8%  active=2
  ● 172.67.1.1          loss= 3.9%  active=1
```

---

## حمایت از توسعه‌دهنده اصلی

اگر از این برنامه برای دسترسی به اینترنت آزاد استفاده می‌کنید، لطفاً از **@patterniha** حمایت کنید:

**USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`
