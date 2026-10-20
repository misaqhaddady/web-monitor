# Web Monitor — مانیتور وب‌سایت‌ها

ساخته‌شده توسط **Hossein Haddady**

پنل تحت وب برای بررسی وضعیت پورت **80** و **443**، کد HTTP صفحه‌ی دلخواه (مثلاً `example.com/app`) و **اعتبار SSL**.
نیازی به دسترسی به سرور سایت‌ها نیست؛ بررسی از بیرون انجام می‌شود.

## نصب

```bash
git clone https://github.com/misaqhaddady/web-monitor.git


APP_ADMIN_USER=admin APP_ADMIN_PASS=admin123 /usr/bin/python3 app.py --init-admin

cd /home/misaq/web-monitor
APP_ADMIN_USER=admin APP_ADMIN_PASS=admin123 /usr/bin/python3 app.py --init-admin
#ساخت سرویس 

cat > /etc/systemd/system/webmonitor.service <<'EOF'
[Unit]
Description=Web Monitor
After=network-online.target
Wants=network-online.target

[Service]
User=misaq
WorkingDirectory=/home/misaq/web-monitor
ExecStart=/usr/bin/python3 /home/misaq/web-monitor/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chown -R misaq:misaq /home/misaq/web-monitor
systemctl daemon-reload
systemctl enable --now webmonitor
systemctl status webmonitor --no-pager


نصب‌کننده FQDN، پورت، و نام‌کاربری/رمز ادمین را می‌پرسد. پنل روی همه‌ی اینترفیس‌ها گوش می‌دهد، پس هم با FQDN و هم با IP باز می‌شود: `http://<fqdn-یا-ip>:8080`

## اجرای دستی

```bash
python -m venv venv && venv/bin/pip install -r requirements.txt   # ویندوز: venv\Scripts\
APP_ADMIN_USER=admin APP_ADMIN_PASS='رمز-حداقل-8' venv/bin/python app.py --init-admin
venv/bin/python app.py
```

## صفحات
1. **داشبورد** — کارت هر سایت: وضعیت پورت‌های 80/443، کد HTTP، زمان اتصال، SSL (معتبر/نامعتبر و روز مانده)
2. **مدیریت سایت‌ها** — افزودن/حذف (دامنه یا IP، با مسیر اختیاری)
3. **اعتبار SSL** — لیست مرتب‌شده بر اساس نزدیکی انقضا؛ کمتر از ۳۰ روز قرمز
4. **تنظیمات** — فاصله‌ی بررسی، تغییر رمز

## نکته‌ی امنیتی
پنل خودش HTTP ساده است. برای استفاده روی اینترنت پشت Caddy/nginx با TLS قرار دهید.
