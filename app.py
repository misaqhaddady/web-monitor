#!/usr/bin/env python3
"""Web Monitor (by Hossein Haddady) - بررسی وضعیت پورت 80/443، HTTP و SSL وب‌سایت‌ها (ویندوز و لینوکس)."""
import os, sys, re, json, ssl, socket, sqlite3, secrets, threading, time, http.client
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from flask import (Flask, request, session, redirect, render_template_string,
                   abort, flash, jsonify)
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
os.makedirs(DATA, exist_ok=True)
DB = os.path.join(DATA, "monitor.db")
CFG_PATH = os.path.join(BASE, "config.json")


def load_cfg():
    cfg = {"fqdn": "", "port": 8080, "secret_key": ""}
    if os.path.exists(CFG_PATH):
        with open(CFG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    if not cfg["secret_key"]:
        cfg["secret_key"] = secrets.token_hex(32)
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    return cfg


CFG = load_cfg()

# ----------------------------------------------------------------- database
def db():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, pw TEXT);
        CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, host TEXT, path TEXT DEFAULT '/', result TEXT,
            checked_at TEXT, state TEXT);
        CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
        """)


def get_setting(k, default=""):
    with db() as c:
        r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def set_setting(k, v):
    with db() as c:
        c.execute("INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)", (k, str(v)))


# ------------------------------------------------------------------ checks
def _err(e):
    return (str(e) or e.__class__.__name__)[:110]


def tcp(host, port, timeout=6):
    s = time.time()
    try:
        socket.create_connection((host, port), timeout).close()
        return True, int((time.time() - s) * 1000), ""
    except Exception as e:
        return False, None, _err(e)


def http_status(host, port, path, tls, verify=True, timeout=8):
    try:
        if tls:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "WebMonitor/1.0"})
        code = conn.getresponse().status
        conn.close()
        return code, ""
    except Exception as e:
        return None, _err(e)


def ssl_info(host, port=443):
    """-> (valid?, days_left, error)"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), 8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        return True, days, ""
    except ssl.SSLCertVerificationError as e:
        return False, None, (e.verify_message or str(e))[:110]
    except Exception as e:
        return None, None, _err(e)


def check_site(host, path):
    o, ms, err = tcp(host, 80)
    code, herr = http_status(host, 80, path, False) if o else (None, err)
    p80 = dict(open=o, ms=ms, http=code, err="" if code else herr)

    o, ms, err = tcp(host, 443)
    p443 = dict(open=o, ms=ms, http=None, err=err, ssl_ok=None, ssl_days=None, ssl_err="")
    if o:
        ok, days, serr = ssl_info(host)
        code, herr = http_status(host, 443, path, True, verify=bool(ok))
        p443.update(ssl_ok=ok, ssl_days=days, ssl_err=serr, http=code, err="" if code else herr)

    good = lambda p: bool(p["open"] and p["http"] is not None and p["http"] < 500)
    n = good(p80) + good(p443)
    return {"p80": p80, "p443": p443}, ("up", "partial", "down")[2 - n]


def run_check(site_id):
    with db() as c:
        s = c.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
    if not s:
        return
    res, state = check_site(s["host"], s["path"])
    with db() as c:
        c.execute("UPDATE sites SET result=?, state=?, checked_at=? WHERE id=?",
                  (json.dumps(res), state, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), site_id))


def check_all():
    with db() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM sites")]
    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(run_check, ids))


def scheduler():
    time.sleep(3)
    while True:
        try:
            check_all()
        except Exception as e:
            print("scheduler error:", e, file=sys.stderr)
        for _ in range(max(30, int(get_setting("interval", "60")))):
            time.sleep(1)


def parse_addr(a):
    a = re.sub(r"^https?://", "", a.strip(), flags=re.I)
    host, _, rest = a.partition("/")
    host = host.split(":")[0].lower()
    if not re.fullmatch(r"[a-z0-9.\-]+", host or ""):
        return None, None
    return host, "/" + re.sub(r"\s", "", rest)


def sites_view():
    with db() as c:
        rows = c.execute("SELECT * FROM sites ORDER BY name COLLATE NOCASE").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["r"] = json.loads(r["result"]) if r["result"] else None
        out.append(d)
    return out


# --------------------------------------------------------------- templates
CSS = """
:root{--b1:#0b2a8a;--b2:#1d4ed8;--ok:#16a34a;--warn:#d97706;--bad:#dc2626}
*{box-sizing:border-box}
body{margin:0;font-family:Tahoma,"Segoe UI",Arial,sans-serif;background:#f4f7ff;color:#0f1b3d;font-size:14px}
header{background:linear-gradient(90deg,var(--b1),var(--b2));color:#fff;display:flex;align-items:center;gap:24px;padding:0 24px;height:58px}
header b{font-size:18px}
header nav{display:flex;gap:6px;flex:1}
header a{color:#dbe6ff;text-decoration:none;padding:8px 14px;border-radius:8px}
header a.on,header a:hover{background:rgba(255,255,255,.18);color:#fff}
main{max-width:1200px;margin:24px auto;padding:0 16px}
h2{color:var(--b1);margin:0 0 16px}
.flash{padding:10px 14px;border-radius:10px;margin-bottom:14px;background:#e8efff;color:var(--b1);border:1px solid #c5d6ff}
.flash.err{background:#fee2e2;color:#991b1b;border-color:#fecaca}
.sum{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.sum div{background:#fff;border:1px solid #d6e2ff;border-radius:12px;padding:12px 20px;min-width:120px}
.sum strong{display:block;font-size:24px;color:var(--b2)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:16px}
.card{background:#fff;border:1px solid #d6e2ff;border-top:5px solid #94a3b8;border-radius:14px;padding:16px;box-shadow:0 2px 8px rgba(29,78,216,.07)}
.card.up{border-top-color:var(--ok)}.card.partial{border-top-color:var(--warn)}.card.down{border-top-color:var(--bad)}
.top{display:flex;justify-content:space-between;gap:8px;align-items:flex-start;margin-bottom:10px}
.top h3{margin:0 0 4px;color:var(--b1);font-size:16px}
.addr{color:#64748b;font-size:12px;word-break:break-all}
.badge{padding:3px 10px;border-radius:99px;font-size:12px;color:#fff;background:#94a3b8;white-space:nowrap}
.badge.up{background:var(--ok)}.badge.partial{background:var(--warn)}.badge.down{background:var(--bad)}
.port{background:#f4f7ff;border-radius:10px;padding:10px 12px;margin-top:8px}
.ph{display:flex;justify-content:space-between;margin-bottom:4px}
.dot{font-size:12px;font-weight:bold}.g{color:var(--ok)}.r{color:var(--bad)}
.kv{display:flex;justify-content:space-between;padding:2px 0;color:#475569}
.kv em{font-style:normal;color:#0f1b3d}.kv em.g{color:var(--ok)}.kv em.r{color:var(--bad)}
.err{color:var(--bad);font-size:11px;margin-top:3px;word-break:break-all}
.muted{color:#64748b}
.foot{display:flex;justify-content:space-between;align-items:center;margin-top:12px;font-size:12px;color:#64748b}
form.inline{display:inline;margin:0}
button,.btn{background:var(--b2);color:#fff;border:0;border-radius:8px;padding:9px 18px;cursor:pointer;font-family:inherit;font-size:14px}
button:hover{background:var(--b1)}
button.mini{padding:4px 12px;font-size:12px}
button.danger{background:var(--bad)}
.panel{background:#fff;border:1px solid #d6e2ff;border-radius:14px;padding:18px;margin-bottom:18px}
.panel h3{margin:0 0 12px;color:var(--b1)}
textarea{padding:9px 12px;border:1px solid #c5d6ff;border-radius:8px;font-family:inherit;font-size:14px;width:100%;min-height:140px}
input{padding:9px 12px;border:1px solid #c5d6ff;border-radius:8px;font-family:inherit;font-size:14px;width:100%}
input:focus{outline:2px solid #93b4ff}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.row>label{flex:1;min-width:200px;display:block;font-size:12px;color:#475569}
.row>label input{margin-top:4px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;text-align:right;border-bottom:1px solid #e5edff}
th{color:var(--b1);background:#f4f7ff}
.login{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,var(--b1),var(--b2))}
.login .box{background:#fff;border-radius:18px;padding:32px;width:360px;max-width:92vw;box-shadow:0 20px 50px rgba(0,0,0,.25)}
.login h1{margin:0 0 4px;color:var(--b1);font-size:22px;text-align:center}
.login p{text-align:center;color:#64748b;margin:0 0 20px}
.login label{display:block;margin-bottom:12px;font-size:12px;color:#475569}
.login button{width:100%;margin-top:6px;padding:11px}
.login small{display:block;text-align:center;color:#64748b;margin-top:16px;font-size:12px}
.ft{text-align:center;color:#64748b;font-size:12px;padding:20px 0 28px}
.about{text-align:center}
.avatar{width:84px;height:84px;border-radius:50%;background:linear-gradient(135deg,var(--b1),var(--b2));color:#fff;font-size:34px;display:flex;align-items:center;justify-content:center;margin:0 auto 12px}
.bio{white-space:pre-wrap;text-align:right;line-height:2;margin-top:14px}
"""

T = {
"base.html": """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}{% endblock %} | مانیتور وب</title><style>""" + CSS + """</style></head><body>
{% block page %}
<header><b>🛰 مانیتور وب</b>
<nav><a href="/" class="{{ 'on' if request.path=='/' }}">داشبورد</a>
<a href="/sites" class="{{ 'on' if request.path=='/sites' }}">مدیریت سایت‌ها</a>
<a href="/settings" class="{{ 'on' if request.path=='/settings' }}">تنظیمات</a>
<a href="/about" class="{{ 'on' if request.path=='/about' }}">درباره من</a></nav>
<span>{{ session.user }}</span>
<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{{ csrf() }}"><button class="mini">خروج</button></form></header>
<main>{% for cat,m in get_flashed_messages(with_categories=true) %}<div class="flash {{cat}}">{{m}}</div>{% endfor %}
{% block body %}{% endblock %}</main>
<footer class="ft">ساخته‌شده توسط <b>Hossein Haddady</b> · <a href="/about" style="color:var(--b2)">درباره من</a></footer>{% endblock %}
</body></html>""",

"login.html": """{% extends "base.html" %}{% block title %}ورود{% endblock %}
{% block page %}<div class="login"><form class="box" method="post">
<h1>🛰 مانیتور وب</h1><p>برای ادامه وارد شوید</p>
{% for cat,m in get_flashed_messages(with_categories=true) %}<div class="flash {{cat}}">{{m}}</div>{% endfor %}
<input type="hidden" name="csrf" value="{{ csrf() }}">
<label>نام کاربری<input name="username" autofocus required></label>
<label>رمز عبور<input name="password" type="password" required></label>
<button>ورود</button><small>ساخته‌شده توسط Hossein Haddady</small></form></div>{% endblock %}""",

"cards.html": """{% for s in sites %}
<div class="card {{ s.state or '' }}">
<div class="top"><div><h3>{{ s.name }}</h3><div class="addr" dir="ltr">{{ s.host }}{{ s.path }}</div></div>
<span class="badge {{ s.state or '' }}">{{ {'up':'آنلاین','partial':'نیمه‌فعال','down':'آفلاین'}.get(s.state,'در انتظار') }}</span></div>
{% if s.r %}{% for key,label in [('p80','پورت 80 (HTTP)'),('p443','پورت 443 (HTTPS)')] %}{% set p = s.r[key] %}
<div class="port"><div class="ph"><b>{{ label }}</b><span class="dot {{ 'g' if p.open else 'r' }}">{{ 'باز' if p.open else 'بسته' }}</span></div>
<div class="kv"><span>وضعیت HTTP صفحه</span><em dir="ltr">{{ p.http if p.http else '—' }}</em></div>
{% if p.ms is not none %}<div class="kv"><span>زمان اتصال</span><em dir="ltr">{{ p.ms }} ms</em></div>{% endif %}
{% if key == 'p443' and p.open %}<div class="kv"><span>SSL</span>
{% if p.ssl_ok %}<em class="g">فعال و معتبر ({{ p.ssl_days }} روز تا انقضا)</em>
{% elif p.ssl_ok == false %}<em class="r">نامعتبر</em>{% else %}<em>—</em>{% endif %}</div>
{% if p.ssl_err %}<div class="err" dir="ltr">{{ p.ssl_err }}</div>{% endif %}{% endif %}
{% if p.err %}<div class="err" dir="ltr">{{ p.err }}</div>{% endif %}</div>
{% endfor %}{% else %}<p class="muted">هنوز بررسی نشده...</p>{% endif %}
<div class="foot"><span>آخرین بررسی: {{ s.checked_at or '—' }}</span>
<form class="inline" method="post" action="/check/{{ s.id }}"><input type="hidden" name="csrf" value="{{ csrf() }}"><button class="mini">بررسی الان</button></form></div>
</div>
{% else %}<p class="muted">هنوز سایتی تعریف نشده. از «مدیریت سایت‌ها» اضافه کنید.</p>{% endfor %}""",

"dashboard.html": """{% extends "base.html" %}{% block title %}داشبورد{% endblock %}
{% block body %}<h2>وضعیت سایت‌ها</h2>
<div class="sum"><div><strong>{{ sites|length }}</strong>کل</div>
<div><strong class="g">{{ sites|selectattr('state','equalto','up')|list|length }}</strong>آنلاین</div>
<div><strong style="color:var(--warn)">{{ sites|selectattr('state','equalto','partial')|list|length }}</strong>نیمه‌فعال</div>
<div><strong class="r">{{ sites|selectattr('state','equalto','down')|list|length }}</strong>آفلاین</div>
<form method="post" action="/check-all" style="margin-right:auto;align-self:center"><input type="hidden" name="csrf" value="{{ csrf() }}"><button>بررسی همه</button></form></div>
<div class="grid" id="cards">{% include "cards.html" %}</div>
<script>setInterval(()=>fetch('/partial/cards').then(r=>r.ok?r.text():null).then(t=>{if(t)document.getElementById('cards').innerHTML=t}),20000)</script>
{% endblock %}""",

"sites.html": """{% extends "base.html" %}{% block title %}مدیریت سایت‌ها{% endblock %}
{% block body %}<h2>مدیریت سایت‌ها</h2>
<form class="panel" method="post" action="/sites/add"><h3>افزودن سایت</h3>
<input type="hidden" name="csrf" value="{{ csrf() }}">
<div class="row"><label>نام نمایشی<input name="name" placeholder="فروشگاه" required></label>
<label>آدرس (دامنه یا IP، با مسیر اختیاری)<input name="addr" dir="ltr" placeholder="example.com/app" required></label>
<button>افزودن</button></div></form>
<div class="panel"><table><tr><th>نام</th><th>آدرس</th><th>وضعیت</th><th></th></tr>
{% for s in sites %}<tr><td>{{ s.name }}</td><td dir="ltr" style="text-align:right">{{ s.host }}{{ s.path }}</td>
<td>{{ {'up':'آنلاین','partial':'نیمه‌فعال','down':'آفلاین'}.get(s.state,'در انتظار') }}</td>
<td><form class="inline" method="post" action="/sites/{{ s.id }}/delete" onsubmit="return confirm('حذف شود؟')">
<input type="hidden" name="csrf" value="{{ csrf() }}"><button class="mini danger">حذف</button></form></td></tr>
{% else %}<tr><td colspan="4" class="muted">سایتی وجود ندارد</td></tr>{% endfor %}</table></div>{% endblock %}""",

"about.html": """{% extends "base.html" %}{% block title %}درباره من{% endblock %}
{% block body %}<h2>درباره من</h2>
<div class="panel about"><div class="avatar">H</div>
<h3 style="font-size:20px;margin:0">Hossein Haddady</h3>
<div class="muted">سازنده‌ی مانیتور وب</div>
<div class="bio">{{ bio }}</div></div>
<form class="panel" method="post" action="/about/edit"><h3>ویرایش متن «درباره من»</h3>
<input type="hidden" name="csrf" value="{{ csrf() }}">
<textarea name="bio" maxlength="3000">{{ bio }}</textarea>
<div style="margin-top:10px"><button>ذخیره</button></div></form>
<div class="panel"><h3>درباره‌ی پروژه</h3>
<p class="muted" style="line-height:2">مانیتور وب یک ابزار سبک و متن‌باز برای بررسی وضعیت پورت‌های 80 و 443، کد HTTP صفحه‌ها و اعتبار SSL وب‌سایت‌هاست؛ بدون نیاز به دسترسی به سرور سایت‌ها و قابل نصب روی ویندوز و لینوکس.</p></div>{% endblock %}""",

"settings.html": """{% extends "base.html" %}{% block title %}تنظیمات{% endblock %}
{% block body %}<h2>تنظیمات</h2>
<form class="panel" method="post" action="/settings/interval"><h3>فاصله بررسی خودکار</h3>
<input type="hidden" name="csrf" value="{{ csrf() }}">
<div class="row"><label>ثانیه (حداقل ۳۰)<input name="interval" type="number" min="30" value="{{ interval }}" dir="ltr"></label><button>ذخیره</button></div></form>
<form class="panel" method="post" action="/settings/password"><h3>تغییر رمز عبور</h3>
<input type="hidden" name="csrf" value="{{ csrf() }}">
<div class="row"><label>رمز فعلی<input name="old" type="password" required></label>
<label>رمز جدید (حداقل ۸ کاراکتر)<input name="new" type="password" minlength="8" required></label><button>تغییر</button></div></form>
<div class="panel"><h3>اطلاعات پنل</h3>
<div class="kv"><span>FQDN</span><em dir="ltr">{{ fqdn or '—' }}</em></div>
<div class="kv"><span>پورت</span><em dir="ltr">{{ port }}</em></div>
<p class="muted">پنل روی همه‌ی اینترفیس‌ها گوش می‌دهد؛ هم با FQDN و هم با IP باز می‌شود. برای تغییر، فایل config.json را ویرایش و سرویس را ری‌استارت کنید.</p></div>{% endblock %}""",
}

# --------------------------------------------------------------------- app
app = Flask(__name__)
app.secret_key = CFG["secret_key"]
app.jinja_loader = DictLoader(T)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=60 * 60 * 12)


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf"] = csrf


@app.before_request
def csrf_protect():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            abort(400, "CSRF token invalid")


def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("user"):
            return redirect("/login")
        return f(*a, **kw)
    return w


FAILS = {}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        if FAILS.get(ip, (0, 0))[0] >= 5 and time.time() - FAILS[ip][1] < 300:
            flash("تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره تلاش کنید.", "err")
            return render_template_string('{% extends "login.html" %}')
        with db() as c:
            u = c.execute("SELECT * FROM users WHERE username=?",
                          (request.form.get("username", ""),)).fetchone()
        if u and check_password_hash(u["pw"], request.form.get("password", "")):
            FAILS.pop(ip, None)
            session.clear()
            session.permanent = True
            session["user"] = u["username"]
            return redirect("/")
        FAILS[ip] = (FAILS.get(ip, (0, 0))[0] + 1, time.time())
        time.sleep(1)
        flash("نام کاربری یا رمز عبور اشتباه است.", "err")
    return render_template_string('{% extends "login.html" %}')


@app.post("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@login_required
def dashboard():
    return render_template_string('{% extends "dashboard.html" %}', sites=sites_view())


@app.route("/partial/cards")
@login_required
def partial_cards():
    return render_template_string('{% include "cards.html" %}', sites=sites_view())


@app.route("/sites")
@login_required
def sites_page():
    return render_template_string('{% extends "sites.html" %}', sites=sites_view())


@app.post("/sites/add")
@login_required
def sites_add():
    host, path = parse_addr(request.form.get("addr", ""))
    name = request.form.get("name", "").strip()[:80]
    if not host or not name:
        flash("نام یا آدرس نامعتبر است.", "err")
        return redirect("/sites")
    with db() as c:
        cur = c.execute("INSERT INTO sites(name,host,path) VALUES(?,?,?)", (name, host, path))
        sid = cur.lastrowid
    threading.Thread(target=run_check, args=(sid,), daemon=True).start()
    flash("سایت اضافه شد.")
    return redirect("/sites")


@app.post("/sites/<int:sid>/delete")
@login_required
def sites_delete(sid):
    with db() as c:
        c.execute("DELETE FROM sites WHERE id=?", (sid,))
    flash("حذف شد.")
    return redirect("/sites")


@app.post("/check/<int:sid>")
@login_required
def check_one(sid):
    run_check(sid)
    return redirect("/")


@app.post("/check-all")
@login_required
def check_all_route():
    check_all()
    return redirect("/")


@app.route("/settings")
@login_required
def settings():
    return render_template_string('{% extends "settings.html" %}',
                                  interval=get_setting("interval", "60"),
                                  fqdn=CFG["fqdn"], port=CFG["port"])


@app.post("/settings/interval")
@login_required
def set_interval():
    try:
        v = max(30, int(request.form.get("interval", "60")))
    except ValueError:
        v = 60
    set_setting("interval", v)
    flash("ذخیره شد.")
    return redirect("/settings")


@app.post("/settings/password")
@login_required
def set_password():
    new = request.form.get("new", "")
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
        if not check_password_hash(u["pw"], request.form.get("old", "")) or len(new) < 8:
            flash("رمز فعلی اشتباه است یا رمز جدید کوتاه است.", "err")
        else:
            c.execute("UPDATE users SET pw=? WHERE id=?", (generate_password_hash(new), u["id"]))
            flash("رمز عبور تغییر کرد.")
    return redirect("/settings")


DEFAULT_BIO = "سلام! من Hossein Haddady هستم، سازنده‌ی مانیتور وب.\nبرای تغییر این متن از فرم پایین همین صفحه استفاده کنید."


@app.route("/about")
@login_required
def about():
    return render_template_string('{% extends "about.html" %}', bio=get_setting("bio", DEFAULT_BIO))


@app.post("/about/edit")
@login_required
def about_edit():
    set_setting("bio", request.form.get("bio", "").strip()[:3000] or DEFAULT_BIO)
    flash("ذخیره شد.")
    return redirect("/about")


@app.route("/api/status")
@login_required
def api_status():
    return jsonify([{"name": s["name"], "host": s["host"], "path": s["path"],
                     "state": s["state"], "checked_at": s["checked_at"], "result": s["r"]}
                    for s in sites_view()])


# -------------------------------------------------------------------- main
if __name__ == "__main__":
    init_db()
    if "--init-admin" in sys.argv:
        user, pw = os.environ.get("APP_ADMIN_USER", "admin"), os.environ.get("APP_ADMIN_PASS", "")
        if len(pw) < 8:
            sys.exit("Password must be at least 8 characters.")
        with db() as c:
            c.execute("INSERT INTO users(username,pw) VALUES(?,?) "
                      "ON CONFLICT(username) DO UPDATE SET pw=excluded.pw",
                      (user, generate_password_hash(pw)))
        print(f"Admin user '{user}' is ready.")
        sys.exit(0)
    threading.Thread(target=scheduler, daemon=True).start()
    print(f"Web Monitor listening on 0.0.0.0:{CFG['port']}")
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=int(CFG["port"]), threads=8)
    except ImportError:
        app.run(host="0.0.0.0", port=int(CFG["port"]))
