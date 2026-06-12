# ⭐ StarJin Proxy

<div align="center">

![StarJin Proxy](https://img.shields.io/badge/Version-2026.06.13-red)
![Cloudflare Workers](https://img.shields.io/badge/Platform-Cloudflare%20Workers-orange)
![License](https://img.shields.io/badge/License-MIT-green)

**سرویس پیشرفته پروکسی روی Cloudflare Workers**  
پشتیبانی از VLESS، Trojan، Shadowsocks، gRPC، WebSocket و مدیریت اشتراک هوشمند

[نصب سریع](#-نصب-و-راه‌اندازی) • [مستندات](#-مستندات) • [پلن‌ها](#-پلن‌های-اشتراک)

</div>

---

## 🚀 ویژگی‌ها

| ویژگی | توضیح |
|-------|--------|
| **پروتکل‌ها** | VLESS, Trojan, Shadowsocks, gRPC, WebSocket |
| **امنیت** | TLS 1.2/1.3, ChaCha20-Poly1305, AES-128/256-GCM |
| **پروکسی‌ها** | SOCKS5, HTTP, HTTPS, TURN, SSTP |
| **اشتراک** | پلن‌های 1G/1d, 5G/7d, 30G/30d, نامحدود |
| **ابزارها** | DoH,优选IP, Load Balancing, Fallback |
| **پلتفرم** | Cloudflare Workers (رایگان) |

---

## 📋 پلن‌های اشتراک

| پلن | حجم | مدت | ویژگی‌ها |
|-----|-----|-----|----------|
| ✨ استارتر | ۱ گیگابایت | ۱ روز | VLESS + WebSocket |
| 🔥 حرفه‌ای | ۵ گیگابایت | ۷ روز | + gRPC + اولویت |
| 💎 حامی | ۳۰ گیگابایت | ۳۰ روز | + پشتیبانی |
| 👑 نامحدود | ∞ | ۳۰ روز | همه امکانات |

---

## 🛠️ نصب و راه‌اندازی

### پیش‌نیازها

1. یک اکانت [Cloudflare](https://cloudflare.com) (رایگان)
2. یک دامنه (اختیاری - می‌تونید از workers.dev استفاده کنید)
3. گیت‌هاب اکانت برای صفحه استاتیک

### مرحله 1: صفحه استاتیک (اختیاری)

```bash
# 1. ریپازیتوری جدید بسازید
git clone https://github.com/your-username/starjin-panel.github.io.git
cd starjin-panel.github.io

# 2. فایل index.html رو اضافه کنید
# 3. push کنید به گیت‌هاب
git add .
git commit -m "Initial commit"
git push origin main

# 4. در تنظیمات گیت‌هاب، Pages رو فعال کنید
# Settings > Pages > Branch: main > Save