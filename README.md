# SNI Spoofing — Enhanced Fork

این مخزن یک fork از پروژه اصلی [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) است.

صمیمانه از **@patterniha** تشکر می‌کنیم که این ابزار را با هدف دسترسی آزاد به اینترنت برای مردم ایران توسعه داده و به صورت متن‌باز منتشر کرده است. ایده اصلی، معماری پایه، و تمام منطق WinDivert/fake TCP از کار ایشان است.

---

## تغییرات این Fork

### ۱. لیست IP و SNI جداگانه + کشف داینامیک Combination

در نسخه اصلی فقط یک IP و یک SNI قابل تنظیم بود. در این نسخه دو لیست جداگانه تعریف می‌کنید و برنامه خودش تمام combination های ممکن را به صورت داینامیک و تصادفی کشف و رتبه‌بندی می‌کند:

```json
"CONNECT_IPS":  ["188.114.96.0", "104.16.0.1", "172.67.0.1"],
"FAKE_SNIS":    ["hcaptcha.com", "cdn.jsdelivr.net"]
```

۳ IP × ۲ SNI = **۶ combination** که برنامه خودش کشف می‌کند.

### ۲. CombinationExplorer — کشف هوشمند و تصادفی

به جای تست همه combination ها یکجا، یک explorer داینامیک دارد:
- **شروع:** یک subset تصادفی probe می‌شود (نه خطی)
- **هر دوره:** بهترین‌های شناخته‌شده verify + batch جدیدی از ناشناخته‌ها کشف می‌شود
- **وقتی همه کشف شدند:** shuffle کامل و شروع مجدد

### ۳. Health-Check بر اساس Packet Loss (نه Latency)

معیار اصلی **packet loss** است:
- probe های دوره‌ای (TCP connect) → probe loss rate
- traffic واقعی هم ردیابی می‌شود (وزن ۷۰٪)
- pairهایی با loss بیش از `LOSS_THRESHOLD` ضعیف، بیش از `DEAD_THRESHOLD` مرده اعلام می‌شوند

### ۴. Multi-Path — اتصال همزمان به چند نقطه

`ACTIVE_SLOTS` تعداد pair های همزمان فعال را کنترل می‌کند. کانکشن‌های جدید با weighted-random (کمترین loss = وزن بیشتر) بین این slot ها پخش می‌شوند.

### ۵. Graceful Handoff — جابجایی بدون قطع Session

وقتی یک pair ضعیف می‌شود:
- وارد حالت **draining** می‌شود — کانکشن‌های فعلی بدون قطع ادامه می‌یابند
- کانکشن‌های جدید بلافاصله به pair جایگزین می‌روند
- هیچ session ای قطع نمی‌شود

### ۶. Probe تصادفی با Jitter

- ترتیب probe هر دوره کاملاً shuffle می‌شود
- شروع هر thread با تاخیر تصادفی کوچک
- تعداد probe هر pair کمی متغیر است تا pattern ثابتی نداشته باشد

### ۷. Config Generator — ابزار گرافیکی ساخت config

فایل `sni-config-generator.html` یک ابزار standalone است که:
- نیاز به اینترنت ندارد — کاملاً offline کار می‌کند
- IP ها و SNI ها را جداگانه می‌گیرد
- تمام تنظیمات را با slider تنظیم می‌کند
- config.json را با یک کلیک دانلود می‌دهد

---

## فایل‌های تغییر یافته

| فایل | وضعیت | توضیح |
|------|--------|-------|
| `main.py` | تغییر یافته | منطق اصلی — کاملاً جایگزین |
| `config.json` | تغییر یافته | ساختار جدید با لیست جداگانه |
| `sni-config-generator.html` | جدید | ابزار گرافیکی ساخت config |
| `README.md` | جدید | این فایل |
| `fake_tcp.py` | دست نخورده | — |
| `utils/` | دست نخورده | — |

---

## نصب و راه‌اندازی

پیش‌نیازها همان پروژه اصلی است. به [README اصلی](https://github.com/patterniha/SNI-Spoofing) مراجعه کنید.

```bash
git clone https://github.com/YOUR_USERNAME/SNI-Spoofing
cd SNI-Spoofing
pip install -r requirements.txt
python main.py
```

برای ساخت config گرافیکی، فایل `sni-config-generator.html` را در مرورگر باز کنید.

---

## ساختار config.json

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
  "CONNECT_IPS": [
    "188.114.96.0",
    "104.16.0.1",
    "172.67.0.1"
  ],
  "FAKE_SNIS": [
    "hcaptcha.com",
    "cdn.jsdelivr.net"
  ]
}
```

### توضیح پارامترها

| کلید | پیش‌فرض | توضیح |
|------|---------|-------|
| `LISTEN_HOST` | `0.0.0.0` | آدرس listen |
| `LISTEN_PORT` | `40443` | پورت listen |
| `CONNECT_PORT` | `443` | پورت مقصد |
| `ACTIVE_SLOTS` | `3` | تعداد pair های همزمان فعال |
| `HEALTH_CHECK_INTERVAL` | `30` | فاصله بین health-check ها (ثانیه) |
| `HEALTH_CHECK_TIMEOUT` | `3` | timeout هر probe (ثانیه) |
| `PROBE_COUNT` | `5` | تعداد probe در هر دوره |
| `LOSS_THRESHOLD` | `0.20` | آستانه ضعیف — بیشتر از ۲۰٪ loss |
| `DEAD_THRESHOLD` | `0.80` | آستانه مرده — بیشتر از ۸۰٪ loss |
| `CONNECT_IPS` | — | لیست IP های هدف |
| `FAKE_SNIS` | — | لیست SNI های جعلی |

---

## خروجی نمونه

```
[*] 38 IPs × 5 SNIs = 190 possible combinations

[Explorer] Initial probe: 20 combinations...
[Explorer] known=20  stable=14  weak=3  dead=3  unexplored=170

[Pool/INIT] active=3  draining=0
  ● 188.114.96.1   hcaptcha.com        loss= 0.0%  conns=0
  ● 104.16.0.1     cdn.jsdelivr.net    loss= 1.8%  conns=0
  ● 172.67.1.1     hcaptcha.com        loss= 3.2%  conns=0

[+] 127.0.0.1:54321 → 188.114.96.1  sni=hcaptcha.com  loss=0.0%  active=1

[Explorer] Verifying top 15 known pairs...
[Explorer] Exploring 10 new combinations  (160 remaining unexplored)
[Explorer] known=30  stable=21  weak=5  dead=4  unexplored=160
```

---

## حمایت از توسعه‌دهنده اصلی

اگر از این برنامه برای دسترسی به اینترنت آزاد استفاده می‌کنید، لطفاً از **@patterniha** حمایت کنید:

**USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`
