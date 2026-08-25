# -*- coding: utf-8 -*-
"""
내 자산관리 대시보드
  탭1) 시장현황   : 글로벌 지수 / 금·코인 / 한·미 금리 / 공포탐욕 / VIX (실시간)
  탭2) 종합       : 증권사별 내 주식 실시간 평가·손익
  탭3) 자산현황   : 부동산·현금저축·투자·연금·보험·부채를 월별로 기록 → 순자산 추이 그래프
  탭4) 가계부     : 수입 / 고정지출 / 변동지출 기록 + 그래프

- 파이썬 기본 기능만 사용 (추가 설치 불필요)
- 내 기록은 이 폴더의 "내 데이터" 안에 파일로 저장됩니다.
- 데이터 출처: 야후 파이낸스(지수·주가·금·코인·VIX·환율), 네이버 금융(금리),
              CNN·alternative.me(공포탐욕지수)
"""

import http.server
import socketserver
import json
import os
import urllib.request
import urllib.error
import ssl
import webbrowser
import threading
import socket
import time
import hashlib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "내 데이터")
os.makedirs(DATA_DIR, exist_ok=True)
F_STOCK = "주식.json"
F_LEDGER = "가계부.json"
F_NETWORTH = "자산현황.json"
F_MEMBERS = "가족.json"
F_MANUAL = "월별자산.json"
DEFAULT_MEMBERS = ["남편", "아내", "자녀"]

# 클라우드 모드: 렌더 등 호스팅은 PORT 환경변수를 줌 → 외부접속(0.0.0.0)으로 실행
# 비밀번호 잠금(LOCKED)은 APP_PASSWORD 가 있을 때만 (없어도 서버는 켜짐)
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
CLOUD = os.environ.get("PORT") is not None
LOCKED = bool(APP_PASSWORD)


def _auth_token():
    return hashlib.sha256(("awm-auth|" + APP_PASSWORD).encode()).hexdigest()[:32]


LOGIN_PAGE = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>로그인 · 내 자산관리</title>
<style>body{background:#0e1117;color:#e8edf4;font-family:"맑은 고딕",system-ui,sans-serif;
margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#161b24;border:1px solid #242c3a;border-radius:16px;padding:34px 28px;width:300px;text-align:center}
h2{margin:0 0 6px} p{color:#8a94a6;font-size:13px;margin:0 0 8px}
input{width:100%;padding:13px;border-radius:10px;border:1px solid #242c3a;background:#1c2430;color:#e8edf4;
font-size:16px;box-sizing:border-box;margin:14px 0 4px;outline:none}
input:focus{border-color:#f5c451}
button{width:100%;padding:13px;border-radius:10px;border:none;background:#f5c451;color:#1a1200;
font-weight:700;font-size:16px;cursor:pointer;margin-top:10px}
.err{color:#ff8f8f;font-size:13px;min-height:18px}</style></head>
<body><div class="box"><h2>🔒 내 자산관리</h2><p>비밀번호를 입력하세요</p>
<div class="err" id="e"></div>
<form method="post" action="/login">
<input type="password" name="pw" placeholder="비밀번호" autofocus autocomplete="current-password">
<button>들어가기</button></form></div>
<script>if(location.search.indexOf("err")>=0)document.getElementById("e").textContent="비밀번호가 틀렸어요";</script>
</body></html>"""


# ===== 여러 명이 각자 로그인해서 자기 자료만 쓰는 모드 (배포용) =====
MULTI_USER = os.environ.get("MULTI_USER", "").lower() in ("1", "true", "yes", "on")
SESSION_SECRET = os.environ.get("SESSION_SECRET") or APP_PASSWORD or "awm-secret-change-me"
_CTX = threading.local()


def _current_user():
    return getattr(_CTX, "user", None)


def _sig(msg):
    return hashlib.sha256((SESSION_SECRET + "|sess|" + msg).encode()).hexdigest()[:32]


def _session_user(cookie):
    for part in (cookie or "").split(";"):
        part = part.strip()
        if part.startswith("awm_sess="):
            val = part[len("awm_sess="):]
            if "." in val:
                uid, sig = val.rsplit(".", 1)
                if uid and _sig(uid) == sig:
                    return uid
    return None


def _valid_userid(u):
    return isinstance(u, str) and 3 <= len(u) <= 20 and all(
        c.isascii() and (c.isalnum() or c in "_-") for c in u)


def _pw_hash(userid, pw):
    return hashlib.sha256((userid + "|" + SESSION_SECRET + "|pw|" + pw).encode()).hexdigest()


def _user_get(userid):
    try:
        req = urllib.request.Request(UPSTASH_URL + "/get/awm:user:" + urllib.parse.quote(userid),
                                     headers={"Authorization": "Bearer " + UPSTASH_TOKEN})
        with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as r:
            v = json.loads(r.read().decode()).get("result")
        return json.loads(v) if v else None
    except Exception:
        return None


def _user_set(userid, obj):
    req = urllib.request.Request(UPSTASH_URL + "/set/awm:user:" + urllib.parse.quote(userid),
                                 data=json.dumps(obj, ensure_ascii=False).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + UPSTASH_TOKEN})
    with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as r:
        r.read()


AUTH_PAGE = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>내 자산관리</title>
<style>body{background:#0e1117;color:#e8edf4;font-family:"맑은 고딕",system-ui,sans-serif;
margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#161b24;border:1px solid #242c3a;border-radius:16px;padding:34px 28px;width:300px;text-align:center}
h2{margin:0 0 4px} .sub{color:#8a94a6;font-size:13px;margin:0 0 8px}
input{width:100%;padding:13px;border-radius:10px;border:1px solid #242c3a;background:#1c2430;color:#e8edf4;
font-size:16px;box-sizing:border-box;margin:8px 0 0;outline:none}
input:focus{border-color:#f5c451}
button{width:100%;padding:13px;border-radius:10px;border:none;background:#f5c451;color:#1a1200;
font-weight:700;font-size:16px;cursor:pointer;margin-top:14px}
.err{color:#ff8f8f;font-size:13px;min-height:18px;margin-top:6px}
.toggle{margin-top:16px;font-size:13px;color:#8a94a6} .toggle a{color:#f5c451;cursor:pointer;text-decoration:none}</style>
</head><body><div class="box"><h2>💰 내 자산관리</h2>
<div class="sub" id="sub">로그인해서 내 자료를 봐요</div>
<div class="err" id="e"></div>
<form id="f" method="post" action="/login">
<input name="userid" placeholder="아이디 (영문·숫자 3~20자)" autocomplete="username" autofocus>
<input type="password" name="pw" placeholder="비밀번호" autocomplete="current-password">
<button id="submit">로그인</button></form>
<div class="toggle" id="tg">처음이세요? <a id="t">회원 만들기</a></div></div>
<script>
var mode="login";
function setMode(m){mode=m;var f=document.getElementById("f"),s=document.getElementById("submit"),
 sub=document.getElementById("sub"),tg=document.getElementById("tg");
 f.action=(m==="login")?"/login":"/signup"; s.textContent=(m==="login")?"로그인":"회원 만들기";
 sub.textContent=(m==="login")?"로그인해서 내 자료를 봐요":"아이디·비밀번호를 정하면 끝이에요 (이메일 필요 없어요)";
 tg.innerHTML=(m==="login")?'처음이세요? <a id="t">회원 만들기</a>':'이미 있으세요? <a id="t">로그인</a>';
 document.getElementById("t").onclick=function(){setMode(mode==="login"?"signup":"login");};}
document.getElementById("t").onclick=function(){setMode("signup");};
var q=location.search;
if(q.indexOf("err=taken")>=0)document.getElementById("e").textContent="이미 있는 아이디예요.";
else if(q.indexOf("err=bad")>=0)document.getElementById("e").textContent="아이디는 영문·숫자 3~20자, 비밀번호도 확인해 주세요.";
else if(q.indexOf("err=login")>=0)document.getElementById("e").textContent="아이디 또는 비밀번호가 틀렸어요.";
if(q.indexOf("signup")>=0)setMode("signup");
</script></body></html>"""


# 요청마다 새 풀을 만들지 않고 하나를 재사용 (부하·스레드 생성 실패 방지)
_EXECUTOR = ThreadPoolExecutor(max_workers=24)


def parallel(thunks):
    """여러 개의 인터넷 요청을 동시에 실행합니다. thunks: {키: 인자없는함수}."""
    out = {}
    futs = {k: _EXECUTOR.submit(fn) for k, fn in thunks.items()}
    for k, f in futs.items():
        try:
            out[k] = f.result()
        except Exception:
            out[k] = None
    return out


def http_get(url, timeout=9):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as r:
        return r.read().decode("utf-8", "replace")


def to_float(v):
    try:
        return float(str(v).replace(",", "").strip())
    except Exception:
        return None


# 시세 캐시: 같은 값을 짧은 시간(45초) 재사용해 야후·네이버 요청을 줄입니다.
_QCACHE = {}
_QLOCK = threading.Lock()
QUOTE_TTL = 45


def _cache_get(key):
    with _QLOCK:
        v = _QCACHE.get(key)
    if v and (time.time() - v[0]) < QUOTE_TTL:
        return v[1]
    return None


def _cache_set(key, val):
    if val is None:
        return
    with _QLOCK:
        _QCACHE[key] = (time.time(), val)


# 인터넷 저장소(Upstash Redis) — 있으면 폰·PC가 같은 자료를 공유(자동연동)
UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "").rstrip("/")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
USE_REDIS = bool(UPSTASH_URL and UPSTASH_TOKEN)
_RKEY = {"주식.json": "stock", "가계부.json": "ledger", "자산현황.json": "networth",
         "가족.json": "members", "월별자산.json": "monthly"}


def _rkey(name):
    base = _RKEY.get(name, name)
    if MULTI_USER:                       # 사람별 칸으로 분리 (자기 자료만)
        return "awm:u:" + (_current_user() or "_anon") + ":" + base
    return "awm:" + base


def _redis_get(name):
    key = _rkey(name)
    req = urllib.request.Request(UPSTASH_URL + "/get/" + key,
                                 headers={"Authorization": "Bearer " + UPSTASH_TOKEN})
    with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as r:
        return json.loads(r.read().decode("utf-8")).get("result")


def _redis_set(name, value):
    key = _rkey(name)
    req = urllib.request.Request(UPSTASH_URL + "/set/" + key, data=value.encode("utf-8"),
                                 method="POST", headers={"Authorization": "Bearer " + UPSTASH_TOKEN})
    with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as r:
        r.read()


def load_json(name, default):
    if USE_REDIS:
        try:
            v = _redis_get(name)
            return json.loads(v) if v else default
        except Exception:
            return default
    try:
        with open(os.path.join(DATA_DIR, name), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(name, obj):
    s = json.dumps(obj, ensure_ascii=False, indent=2)
    if USE_REDIS:
        _redis_set(name, s)
        return
    with open(os.path.join(DATA_DIR, name), "w", encoding="utf-8") as f:
        f.write(s)


# --------------------------- 시세 수집 (45초 캐시 적용) ---------------------------
def get_yahoo(symbol):
    hit = _cache_get("y:" + symbol)
    if hit is not None:
        return hit
    url = ("https://query1.finance.yahoo.com/v8/finance/chart/"
           f"{symbol}?interval=1d&range=5d")
    try:
        data = json.loads(http_get(url))
        meta = data["chart"]["result"][0]["meta"]
        price = to_float(meta.get("regularMarketPrice"))
        prev = to_float(meta.get("chartPreviousClose") or meta.get("previousClose"))
        if price is None:
            return None
        change = pct = None
        if prev not in (None, 0):
            change = price - prev
            pct = change / prev * 100
        res = {"price": price, "prev": prev, "change": change, "pct": pct,
               "currency": meta.get("currency")}
        _cache_set("y:" + symbol, res)
        return res
    except Exception:
        return None


def get_krx_gold():
    """국내 금현물(KRX) 시세 (원/그램). 종합 탭의 '금현물' 계좌용."""
    hit = _cache_get("gold")
    if hit is not None:
        return hit
    try:
        d = json.loads(http_get("https://api.stock.naver.com/marketindex/metals/M04020000"))
        price = to_float(d.get("closePrice"))
        if price is None:
            return None
        chg = to_float(d.get("fluctuations"))
        prev = (price - chg) if chg is not None else None
        pct = (chg / prev * 100) if (prev not in (None, 0) and chg is not None) else None
        res = {"price": price, "prev": prev, "change": chg, "pct": pct, "currency": "KRW"}
        _cache_set("gold", res)
        return res
    except Exception:
        return None


def get_naver_bond(code):
    hit = _cache_get("b:" + code)
    if hit is not None:
        return hit
    try:
        d = json.loads(http_get(f"https://api.stock.naver.com/marketindex/bond/{code}"))
        price = to_float(d.get("closePrice"))
        if price is None:
            return None
        res = {"price": price, "change": to_float(d.get("fluctuations"))}
        _cache_set("b:" + code, res)
        return res
    except Exception:
        return None


def get_naver_standard():
    hit = _cache_get("std")
    if hit is not None:
        return hit
    url = "https://m.stock.naver.com/front-api/marketIndex/majors?category=interestKR"
    result = {}
    try:
        d = json.loads(http_get(url))
        for item in d.get("result", {}).get("standardInterest", []):
            result[item.get("reutersCode")] = {
                "price": to_float(item.get("closePrice")),
                "change": to_float(item.get("fluctuations"))}
        if result:
            _cache_set("std", result)
    except Exception:
        pass
    return result


def get_fear_greed():
    hit = _cache_get("fg")
    if hit is not None:
        return hit
    try:
        d = json.loads(http_get("https://production.cn.cnn.io/index/fearandgreed/graphdata"))
        fg = d["fear_and_greed"]
        score = to_float(fg.get("score"))
        if score is not None:
            res = {"score": round(score), "rating": fg.get("rating"),
                   "source": "CNN 공포탐욕지수 (미국 주식시장)"}
            _cache_set("fg", res)
            return res
    except Exception:
        pass
    try:
        d = json.loads(http_get("https://api.alternative.me/fng/?limit=1"))
        it = d["data"][0]
        res = {"score": round(to_float(it.get("value"))),
               "rating": it.get("value_classification"),
               "source": "alternative.me 공포탐욕지수 (가상자산 시장)"}
        _cache_set("fg", res)
        return res
    except Exception:
        pass
    return None


# --------------------------- 시장현황 ---------------------------
INDICES = [
    ("%5EGSPC", "S&P 500", "미국"),
    ("%5EIXIC", "나스닥", "미국"),
    ("%5EDJI", "다우존스", "미국"),
    ("%5ESOX", "필라델피아 반도체", "미국"),
    ("%5EKS11", "코스피", "한국"),
    ("%5EKQ11", "코스닥", "한국"),
]


def q_to_row(name, tag, q, dec=2):
    return {"name": name, "country": tag,
            "price": q["price"] if q else None,
            "change": q["change"] if q else None,
            "pct": q["pct"] if q else None, "dec": dec}


def build_market():
    out = {"updated": datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")}

    # 필요한 모든 요청을 동시에 실행 (첫 로딩 속도 대폭 향상)
    thunks = {}
    for s, _n, _c in INDICES:
        thunks["idx:" + s] = (lambda s=s: get_yahoo(s))
    for s in ("KRW=X", "GC=F", "BTC-KRW", "ETH-KRW", "%5EVIX"):
        thunks["y:" + s] = (lambda s=s: get_yahoo(s))
    for c in ("KR3YT=RR", "KR10YT=RR", "US2YT=RR", "US10YT=RR"):
        thunks["b:" + c] = (lambda c=c: get_naver_bond(c))
    thunks["std"] = get_naver_standard
    thunks["fg"] = get_fear_greed
    r = parallel(thunks)

    out["indices"] = [q_to_row(n, c, r.get("idx:" + s)) for s, n, c in INDICES]
    out["fx"] = q_to_row("원/달러 환율", "KRW", r.get("y:KRW=X"))
    out["assets"] = [
        q_to_row("금 (달러/온스)", "국제", r.get("y:GC=F")),
        q_to_row("비트코인 (원)", "가상자산", r.get("y:BTC-KRW"), dec=0),
        q_to_row("이더리움 (원)", "가상자산", r.get("y:ETH-KRW"), dec=0),
    ]
    std = r.get("std") or {}

    def rate(item, label, tag):
        return {"label": label, "tag": tag,
                "price": item["price"] if item else None,
                "change": item["change"] if item else None}

    out["rates_kr"] = [
        rate(std.get("KROCRT=ECIX"), "한국 기준금리", "정책"),
        rate(r.get("b:KR3YT=RR"), "국고채 3년", "단기"),
        rate(r.get("b:KR10YT=RR"), "국고채 10년", "장기"),
    ]
    out["rates_us"] = [
        rate(std.get("USFOMC=ECIX"), "미국 기준금리", "정책"),
        rate(r.get("b:US2YT=RR"), "국채 2년", "단기"),
        rate(r.get("b:US10YT=RR"), "국채 10년", "장기"),
    ]
    out["fear_greed"] = r.get("fg")
    vix = r.get("y:%5EVIX")
    out["vix"] = ({"price": vix["price"], "change": vix["change"],
                   "pct": vix["pct"]} if vix else None)
    return out


# --------------------------- 내 주식 ---------------------------
def market_symbol(h):
    mk = h.get("market")
    code = (h.get("code") or "").strip()
    if mk == "코스피":
        return code + ".KS", "KRW"
    if mk == "코스닥":
        return code + ".KQ", "KRW"
    if mk == "미국주식":
        return code.upper(), "USD"
    if mk == "암호화폐":
        return code.upper() + "-USD", "USD"
    if mk == "금현물":
        return "GOLD", "KRW"      # 국내 금현물(원/그램)
    return code, "KRW"


def compute_portfolio():
    holds = load_json(F_STOCK, [])
    # 환율과 모든 종목 시세를 동시에 조회
    thunks = {"fx": (lambda: get_yahoo("KRW=X"))}
    for i, h in enumerate(holds):
        sym, _cur = market_symbol(h)
        if sym == "GOLD":
            thunks["h:%d" % i] = get_krx_gold
        elif sym:
            thunks["h:%d" % i] = (lambda s=sym: get_yahoo(s))
    r = parallel(thunks)
    fx = r.get("fx")
    usdkrw = fx["price"] if fx else None
    rows = []
    total_krw = 0.0
    total_cost_krw = 0.0
    for i, h in enumerate(holds):
        sym, cur = market_symbol(h)
        q = r.get("h:%d" % i) if sym else None
        price = q["price"] if q else None
        qty = to_float(h.get("qty")) or 0
        avg = to_float(h.get("avg")) or 0
        val = price * qty if price is not None else None
        cost = avg * qty
        if cur == "USD" and usdkrw:
            val_krw = val * usdkrw if val is not None else None
            cost_krw = cost * usdkrw
        else:
            val_krw = val
            cost_krw = cost
        pl = (val - cost) if val is not None else None
        plpct = (pl / cost * 100) if (pl is not None and cost) else None
        pl_krw = (val_krw - cost_krw) if val_krw is not None else None
        if val_krw is not None:
            total_krw += val_krw
            total_cost_krw += cost_krw
        rows.append({"name": h.get("name"), "broker": h.get("broker") or "기타",
                     "member": h.get("member") or "공용",
                     "account": h.get("account") or "기타",
                     "market": h.get("market"), "code": h.get("code"),
                     "qty": qty, "avg": avg, "currency": cur, "price": price,
                     "val": val, "val_krw": val_krw, "cost_krw": cost_krw,
                     "pl": pl, "plpct": plpct, "pl_krw": pl_krw})
    return {"rows": rows, "usdkrw": usdkrw, "total_krw": total_krw,
            "total_cost_krw": total_cost_krw,
            "total_pl_krw": total_krw - total_cost_krw}


# --------------------------- 자산현황 / 종합 ---------------------------
NW_ASSET_KEYS = ["부동산", "현금저축", "투자", "연금", "보험"]


def networth_of(snap):
    asset = sum((to_float(snap.get(k)) or 0) for k in NW_ASSET_KEYS)
    debt = to_float(snap.get("부채")) or 0
    return {"asset": asset, "debt": debt, "net": asset - debt}


def _is_month(k):
    return (isinstance(k, str) and len(k) == 7 and k[4] == "-"
            and k[:4].isdigit() and k[5:].isdigit())


NW_CAT_ALL = ["부동산", "현금", "저축", "투자", "연금", "보험", "부채"]


def _to_items(snap):
    """카테고리 값을 세부항목 리스트 형식으로 변환합니다."""
    out = {c: [] for c in NW_CAT_ALL}
    if not isinstance(snap, dict):
        return out
    for oldcat, val in snap.items():
        target = "현금" if oldcat == "현금저축" else oldcat
        if isinstance(val, list):
            out[target] = [it for it in val if isinstance(it, dict)]   # 기본+사용자 분류 보존
        elif isinstance(val, (int, float)) and val and target in out:
            out[target].append({"name": oldcat, "amount": val})
    return out


def migrate_networth(nw):
    """예전 형식을 {가족: {월: {분류: [세부항목]}}} 형식으로 자동 변환합니다."""
    if not isinstance(nw, dict):
        return {}
    if any(_is_month(k) for k in nw.keys()):   # 아주 옛 평평한 형식
        nw = {"공용": nw}
    out = {}
    for member, months in nw.items():
        if not isinstance(months, dict):
            continue
        out[member] = {m: _to_items(s) for m, s in months.items()}
    return out


def compute_summary():
    port = compute_portfolio()
    nw = load_json(F_NETWORTH, {})
    months = sorted(nw.keys())
    latest = months[-1] if months else None
    latest_nw = networth_of(nw[latest]) if latest else {"asset": 0, "debt": 0, "net": 0}
    trend = [dict(month=m, **networth_of(nw[m])) for m in months]

    ledger = load_json(F_LEDGER, [])
    lm = {}
    for e in ledger:
        m = (e.get("date") or "")[:7]
        if not m:
            continue
        d = lm.setdefault(m, {"수입": 0.0, "고정지출": 0.0, "변동지출": 0.0})
        amt = to_float(e.get("amount")) or 0
        t = e.get("type")
        if t in d:
            d[t] += amt
    return {"stock_value": port["total_krw"], "stock_pl": port["total_pl_krw"],
            "usdkrw": port["usdkrw"], "latest_month": latest, "latest_nw": latest_nw,
            "trend": trend, "ledger_months": lm, "portfolio": port}


# ===========================================================================
PAGE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>내 자산관리 대시보드</title>
<script>window.MULTIUSER=__MULTIUSER__;</script>
<style>
  :root{
    --bg:#0e1117; --panel:#161b24; --panel2:#1c2430; --line:#242c3a;
    --text:#e8edf4; --sub:#8a94a6; --up:#ff5b5b; --down:#4d8dff; --flat:#9aa4b2;
    --accent:#f5c451; --green:#37c26a;
  }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:"맑은 고딕","Malgun Gothic",system-ui,-apple-system,sans-serif;
    -webkit-font-smoothing:antialiased;}
  .wrap{max-width:1180px;margin:0 auto;padding:20px 18px 70px;}
  header{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px;}
  h1{font-size:21px;margin:0;letter-spacing:-0.3px;}
  h1 .dot{color:var(--accent);}
  .updated{font-size:12px;color:var(--sub);} .updated b{color:var(--text);font-weight:600;}
  .brandbar{display:flex;justify-content:flex-end;margin:2px 2px 0;}
  .brand{display:inline-flex;align-items:center;gap:6px;padding:6px 13px;border-radius:999px;
    background:linear-gradient(135deg,#1c3a44,#20303a);border:1px solid var(--line);
    font-size:13px;font-weight:600;color:var(--sub);white-space:nowrap;}
  .brand .emo{font-size:16px;} .brand b{color:var(--accent);font-weight:800;}
  .brand .avatar{width:26px;height:26px;border-radius:50%;object-fit:contain;
    background:#fff;flex:0 0 auto;box-shadow:0 0 0 1px var(--line);}
  .tabs{display:flex;gap:4px;margin:16px 0 14px;border-bottom:1px solid var(--line);flex-wrap:wrap;}
  .tab{padding:11px 16px;cursor:pointer;font-size:15px;color:var(--sub);
    border-bottom:2px solid transparent;font-weight:600;user-select:none;}
  .tab:hover{color:var(--text);}
  .tab.active{color:var(--accent);border-bottom-color:var(--accent);}
  .members{display:flex;align-items:center;gap:6px;margin:0 0 18px;flex-wrap:wrap;}
  .mlabel{font-size:12px;color:var(--sub);margin-right:2px;}
  .mbtn{padding:6px 13px;border-radius:999px;border:1px solid var(--line);background:var(--panel);
    color:var(--sub);font-size:13px;font-weight:600;cursor:pointer;user-select:none;display:inline-flex;align-items:center;gap:6px;}
  .mbtn:hover{color:var(--text);}
  .mbtn.active{background:var(--accent);color:#1a1200;border-color:var(--accent);}
  .mbtn.add{border-style:dashed;color:var(--accent);}
  .mbtn.grp{border-color:#3a5a8a;} .mbtn.grp.active{background:#4d8dff;color:#0a1428;border-color:#4d8dff;}
  .mx{font-size:10px;opacity:.55;} .mx:hover{opacity:1;color:var(--up);}
  .tot-row td{background:#12303a;font-weight:800;color:#5fd0e0;border-top:2px solid var(--line);}
  /* 자산현황 세부항목 */
  .nw-cat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px;}
  .nw-cat h4{margin:0 0 10px;font-size:15px;display:flex;justify-content:space-between;align-items:baseline;}
  .nw-cat h4 .st{font-size:15px;font-weight:800;}
  .nw-item{display:flex;gap:6px;align-items:center;margin-bottom:7px;flex-wrap:wrap;}
  .nw-item input.nm{flex:1;min-width:80px;} .nw-item input.am{width:110px;text-align:right;}
  .nw-item select.mv{padding:8px 6px;font-size:12px;color:#9aa4b2;max-width:88px;}
  .nw-item .auto{flex:1;font-size:13px;color:#9aa4b2;padding:8px 2px;}
  .nw-item .aval{width:130px;text-align:right;font-size:13px;color:#cdd5e0;padding:8px 2px;}
  .nw-add{background:var(--panel2);color:var(--accent);border:1px dashed var(--line);border-radius:8px;
    padding:6px 12px;font-size:12px;cursor:pointer;margin-top:4px;}
  .nw-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
  @media (max-width:760px){ .nw-grid{grid-template-columns:1fr;} .nw-item input.am,.nw-item .aval{width:96px;} }
  .autosave{font-size:12px;color:var(--sub);margin-left:6px;}
  .page{display:none;} .page.active{display:block;}
  .sec-title{font-size:13px;color:var(--sub);margin:24px 4px 12px;font-weight:600;letter-spacing:1px;}
  .grid{display:grid;gap:12px;}
  .idx-grid{grid-template-columns:repeat(3,1fr);}
  .rate-wrap,.bottom-wrap{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;}
  .card .top{display:flex;justify-content:space-between;align-items:center;}
  .name{font-size:15px;color:var(--sub);}
  .country{font-size:11px;color:var(--sub);border:1px solid var(--line);border-radius:6px;padding:1px 7px;}
  .price{font-size:25px;font-weight:700;margin-top:10px;letter-spacing:-0.5px;}
  .chg{font-size:14px;margin-top:3px;font-weight:600;}
  .up{color:var(--up);} .down{color:var(--down);} .flat{color:var(--flat);}
  .rate-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;}
  .rate-card h3{margin:0 0 14px;font-size:16px;}
  .rate-row{display:flex;align-items:center;justify-content:space-between;padding:11px 0;border-top:1px solid var(--line);}
  .rate-row:first-of-type{border-top:none;}
  .rate-label{display:flex;align-items:center;gap:9px;font-size:14px;color:#cdd5e0;}
  .tag{font-size:10px;padding:2px 7px;border-radius:6px;font-weight:700;}
  .tag.정책{background:#3a2f12;color:#f5c451;} .tag.단기{background:#12303a;color:#5fd0e0;}
  .tag.장기{background:#2a1a3a;color:#c58bff;}
  .rate-val{text-align:right;} .rate-num{font-size:18px;font-weight:700;} .rate-chg{font-size:12px;font-weight:600;}
  .gauge-num,.vix-num{font-size:50px;font-weight:800;line-height:1;text-align:center;margin:6px 0 2px;}
  .gauge-rating,.vix-state{text-align:center;font-size:15px;font-weight:700;margin-bottom:14px;}
  .gauge-bar{height:14px;border-radius:8px;position:relative;
    background:linear-gradient(90deg,#ff5b5b 0%,#ff9d3b 30%,#e8d44d 50%,#8fd44d 70%,#37c26a 100%);}
  .gauge-mark{position:absolute;top:-6px;width:4px;height:26px;border-radius:3px;background:#fff;
    box-shadow:0 0 6px rgba(0,0,0,.6);transform:translateX(-50%);}
  .gauge-scale{display:flex;justify-content:space-between;font-size:10px;color:var(--sub);margin-top:8px;}
  .vix-desc{text-align:center;font-size:12px;color:var(--sub);margin-top:10px;line-height:1.6;}
  .src{font-size:11px;color:var(--sub);margin-top:14px;text-align:center;}
  .stat-grid{grid-template-columns:repeat(auto-fit,minmax(190px,1fr));}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;}
  .stat .lab{font-size:13px;color:var(--sub);} .stat .big{font-size:26px;font-weight:800;margin-top:8px;letter-spacing:-0.5px;}
  .stat .sub{font-size:12px;margin-top:4px;color:var(--sub);}
  table{width:100%;border-collapse:collapse;font-size:14px;}
  th,td{padding:11px 10px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap;}
  th{color:var(--sub);font-weight:600;font-size:12px;} td.l,th.l{text-align:left;}
  .tbl-wrap{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:6px 16px 10px;overflow-x:auto;}
  tr:last-child td{border-bottom:none;}
  .brk-row td{background:var(--panel2);font-weight:700;color:var(--accent);}
  .mini-btn{background:#2a1416;color:#ff9a9a;border:1px solid #5a2327;border-radius:7px;padding:4px 10px;cursor:pointer;font-size:12px;}
  .mini-btn.edit{background:#12303a;color:#5fd0e0;border-color:#1e5a6a;}
  .mini-btn.save{background:#123a22;color:#5fe08a;border-color:#1e5a3a;}
  .mini-btn:hover{background:#3a1a1d;}
  .form{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;
    display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;}
  .fld{display:flex;flex-direction:column;gap:5px;}
  .fld label{font-size:11px;color:var(--sub);}
  input,select{background:var(--panel2);border:1px solid var(--line);border-radius:9px;color:var(--text);
    padding:9px 11px;font-size:14px;font-family:inherit;outline:none;}
  input:focus,select:focus{border-color:var(--accent);}
  .btn{background:var(--accent);color:#1a1200;border:none;border-radius:9px;padding:10px 18px;
    font-size:14px;font-weight:700;cursor:pointer;font-family:inherit;}
  .btn:hover{filter:brightness(1.08);}
  .btn.ghost{background:var(--panel2);color:var(--text);border:1px solid var(--line);}
  .hint{font-size:12px;color:var(--sub);margin:8px 4px;line-height:1.6;}
  .month-nav{display:flex;align-items:center;gap:14px;margin:4px 0 16px;}
  .month-nav .m{font-size:20px;font-weight:800;min-width:130px;text-align:center;}
  .nav-btn{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:9px;
    width:38px;height:38px;font-size:18px;cursor:pointer;}
  .empty{color:var(--sub);text-align:center;padding:26px;font-size:14px;}
  .pill{font-size:11px;padding:2px 8px;border-radius:6px;font-weight:700;}
  .pill.수입{background:#123a22;color:#5fe08a;} .pill.고정지출{background:#3a2a12;color:#f5c451;}
  .pill.변동지출{background:#3a1616;color:#ff8f8f;}
  .chart-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;}
  .chart-card h3{margin:0 0 12px;font-size:15px;}
  .chart-scroll{overflow-x:auto;}
  .donut-wrap{display:flex;gap:22px;align-items:center;flex-wrap:wrap;}
  .legend .lg{font-size:13px;margin:6px 0;color:#cdd5e0;}
  .sw{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:7px;vertical-align:middle;}
  .pc{color:#8a94a6;font-size:12px;margin-left:4px;}
  /* 매입원금·수익 막대 */
  .cp-legend{display:flex;gap:18px;margin-bottom:16px;font-size:12px;color:var(--sub);}
  .cp-sw{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:middle;}
  .cp-cost{background:#3a4658;} .cp-up{background:var(--up);} .cp-down{background:var(--down);}
  .cp-row{margin-bottom:16px;}
  .cp-top{display:flex;justify-content:space-between;align-items:baseline;font-size:14px;margin-bottom:5px;gap:10px;}
  .cp-label{font-weight:700;color:#e8edf4;}
  .cp-val{color:#cdd5e0;font-weight:700;}
  .cp-bar{display:flex;height:22px;border-radius:6px;overflow:hidden;background:var(--panel2);}
  .cp-seg{height:100%;}
  .cp-sub{font-size:12px;color:var(--sub);margin-top:5px;}
  .two{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
  footer{margin-top:30px;font-size:11px;color:var(--sub);line-height:1.8;border-top:1px solid var(--line);padding-top:14px;}
  .err{background:#2a1416;border:1px solid #5a2327;color:#ffb0b0;padding:12px 16px;border-radius:10px;
    font-size:13px;margin-top:14px;display:none;}
  @media (max-width:760px){
    .idx-grid{grid-template-columns:1fr 1fr;} .rate-wrap,.bottom-wrap,.two{grid-template-columns:1fr;}
    .price{font-size:22px;} .stat .big{font-size:22px;}
  }
  /* ===== 폰(모바일) 최적화 : 표를 카드로, 글씨·버튼 크게 ===== */
  @media (max-width:640px){
    .wrap{padding:14px 12px 60px;}
    h1{font-size:19px;} .updated{font-size:11px;}
    header{flex-direction:column;align-items:flex-start;gap:2px;}
    .tabs{gap:2px;overflow-x:auto;flex-wrap:nowrap;-webkit-overflow-scrolling:touch;}
    .tab{padding:10px 12px;font-size:14px;white-space:nowrap;}
    .idx-grid,.stat-grid{grid-template-columns:1fr 1fr;gap:8px;}
    .card{padding:12px;} .price{font-size:20px;} .stat .big{font-size:19px;}
    .form{padding:12px;gap:8px;} .form .fld{flex:1 1 44%;}
    .form input,.form select{width:100%;box-sizing:border-box;}
    .mini-btn{padding:8px 14px;font-size:14px;}
    .btn{padding:11px 16px;}
    /* 주식·가계부 표 → 카드 */
    #stock-tbl thead,#ledger-tbl thead{display:none;}
    #stock-tbl table,#ledger-tbl table,#stock-tbl tbody,#ledger-tbl tbody{display:block;}
    #stock-tbl tr,#ledger-tbl tr{display:block;background:var(--panel2);border:1px solid var(--line);
      border-radius:12px;margin-bottom:10px;padding:8px 12px;}
    #stock-tbl td,#ledger-tbl td{display:flex;justify-content:space-between;align-items:center;gap:12px;
      border:none;padding:6px 0;text-align:right;white-space:normal;font-size:15px;}
    #stock-tbl td[data-label]::before,#ledger-tbl td[data-label]::before{
      content:attr(data-label);color:var(--sub);font-size:13px;font-weight:600;white-space:nowrap;}
    #stock-tbl td.l:not([data-label]),#ledger-tbl td.ldate{justify-content:flex-start;font-size:16px;
      font-weight:700;border-bottom:1px solid var(--line);padding-bottom:8px;margin-bottom:2px;}
    #stock-tbl td.c-act,#ledger-tbl td.c-act{justify-content:flex-end;gap:8px;padding-top:8px;}
    #stock-tbl td.empty,#ledger-tbl td.empty{justify-content:center;color:var(--sub);}
    #stock-tbl input.ed-qty,#stock-tbl input.ed-avg{width:120px !important;font-size:15px;}
    /* 그룹헤더·합계 줄 → 한 줄 바 */
    #stock-tbl tr.brk-row,#stock-tbl tr.tot-row{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;padding:10px 12px;}
    #stock-tbl tr.brk-row td,#stock-tbl tr.tot-row td{display:inline;padding:0;font-size:14px;border:none;}
    #stock-tbl tr.brk-row td:empty,#stock-tbl tr.tot-row td:empty{display:none;}
    #stock-tbl tr.brk-row td.l,#stock-tbl tr.tot-row td.l{flex-basis:100%;border:none;padding:0 0 2px;}
    /* 자산현황 세부항목 폰 최적화 */
    .nw-item input.nm{min-width:56px;} .nw-item input.am{width:96px;} .nw-item select.mv{max-width:72px;}
    /* 가계부 '이 달 내역' → 컴팩트 2줄 카드 (자리 덜 차지·가독성↑) */
    #ledger-tbl tr{display:flex;flex-wrap:wrap;gap:2px 8px;align-items:baseline;padding:9px 12px;margin-bottom:7px;}
    #ledger-tbl td{display:inline-flex;width:auto;padding:0;border:none;font-size:13px;text-align:left;
      justify-content:flex-start;white-space:nowrap;}
    #ledger-tbl td[data-label]::before{content:none;}
    #ledger-tbl td[data-label="분류"]{order:1;font-weight:700;font-size:15px;color:var(--txt);flex:1 1 auto;}
    #ledger-tbl td[data-label="금액"]{order:2;font-weight:800;font-size:15.5px;margin-left:auto;flex:0 0 auto;}
    #ledger-tbl td.ldate{order:3;font-size:12px;font-weight:600;color:var(--sub);border:none;padding:0;margin:0;flex:0 0 auto;}
    #ledger-tbl td[data-label="구분"]{order:4;flex:0 0 auto;}
    #ledger-tbl td[data-label="가족"]{order:5;color:var(--sub);font-size:12px;flex:0 0 auto;}
    #ledger-tbl td.c-act{order:6;margin-left:auto;flex:0 0 auto;padding:0;gap:6px;}
    #ledger-tbl td.c-act .mini-btn{padding:5px 12px;font-size:13px;}
    #ledger-tbl td[data-label="메모"]{order:7;flex:1 1 100%;color:var(--sub);font-size:12.5px;white-space:normal;}
    #ledger-tbl td[data-label="메모"]:empty{display:none;}
    #ledger-tbl td.empty{flex:1 1 100%;justify-content:center;}
    #ledger-tbl .pill{font-size:11px;padding:1px 7px;}
  }
</style>
</head>
<body>
<div class="wrap">
  <div class="brandbar"><span class="brand"><img class="avatar" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAaQAAAGkCAYAAAB+TFE1AAAAAXNSR0IArs4c6QAAAIRlWElmTU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAIdpAAQAAAABAAAAWgAAAAAAAADYAAAAAQAAANgAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAAaSgAwAEAAAAAQAAAaQAAAAASFOYJQAAAAlwSFlzAAAhOAAAITgBRZYxYAAAABxpRE9UAAAAAgAAAAAAAADSAAAAKAAAANIAAADSAADXJVMT0qoAAEAASURBVHgB7J0HuF1llf4Ry4B0CD2EFAiBJJBKenJTSCeNUEJRwYqjjuLgWMdYRp0ZZxzHsWLvvVdUIqKgotgQu4Bi11FndGb+Ttn/97fWXnt/e5997r0JAbnJl+f5nn1y7in7fPee77fftd61vn32yf/yDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIM5BnIM9AnoE8A3kG8gzkGcgzkGcgz0CegTwDeQbyDOQZyDOQZyDPQJ6BPAN5BvIM5BnIMxAzsGnuSQPNMXG7/r9905nNsXra2IF4Tr/jpEP3abzW6mljtm+ZO1FjUjW2zp00wBiYNGrI1+v3Pvn+PAN5BvIM5BkY4TMQMDh3waQd58w7ZcfmORMLgafYMGuCxvhiw8zxxdnVGFesnT7WxqrTTyjWzRjrP5s1Ycc5c0/ZsXXepB1b9Trnzp9UbJ1/as84V/cNZ1ywcHJxnh7LcbNe115bANO5GsQ2zBIYBc0RPvX59PMM5BnIM7D3zkDAZ+t8Le6Ch5RKsWXOycWWM08uzhGEtur2ubrvvHJsmT2hYGyYOc7AtFG3BYfinHkOnAZcFgg2Nk4rzlvQZyzU/e3R77Ed99vrB+h0DpzH5rkn8zm2Tzpwn4G99zebP3megTwDeQZGwAxsXahwGKpF43wt5udLvVygcf68U+zI7Qu0sG+RGjL4zBpXbBJ4NgtOwAelY+ApgdMXNgCkhM35Op4vdYPCsbFIx2Rs0+0YFy6eUt3mvvRxPJfXqYe/rr1PCawUUluk7lBRC086fPsI+NXkU8wzkGcgz8CePwMGIeVkLlhw6o4LBYeLtNBfpOM2QWVbCaNzBZwNCrltmOHqB7XkymdSAqBupVMBR68LUC5aMqW4eMnU4pKB04sHMJYyzigeGGPZGcWDlk2rxqXLpxWXLp9eXMZYMb148IoZxUPOmqkxw25zHz/ncfE8XovX5PV5HwbvyfsDrh5ImYqbtJ2c1Z7/G8+fMM9AnoE8A/ewGbhAamjbwik7LtFC/UDAoOPFQENq4gIpoq0Ky6GE1k8bU6ybfqLCdb0QaiugXvg4eAAE0AiYPGzlrOLhq2cXj1h9ZnH5mjnVeOTauUWMP9ftP183r3gUY/384tGMs+cXjzl7gY8NC4u/YGxcZEfu53E8h9fgdR+u13/YqtnFQ1cmANN5cD4X6fOisjjn+ByhoM4XnDFl3MN+Zfl08gzkGcgzsOfMwAULpwxcsmTKjkulQB6M4tARGAEi1BD5oHMUgjtbEFqrsWn2SVJChOJqJRSLN0cWc8JmF2qwwKNEWOxRKpeVSgYgAB4gAVweLXAAkscKJI/btKS4YvNA8ZfnLC2uPGeZjsvseOVWHW0sL55wro+/OndF8VfnMc4qnlgO+z/3l4Pn8FqP3zKg112i119s7/MYvR/vG8ACWpwTSgtlxXlX6qkM7xF+3KIwJGBaP2vXTRGrp40e2KTn25C5ghwWr4nZQq+rMX77+hmMsdvXThsrlTZ2O4/leXvOX17+JHkG8gzkGdAMPGhg2sCDlk/bQYgLZYJKuVTQuASQKCxHfgg1REhu7RljzC3n+aAmhAw+CnehKi5S6IsQGCExg4/gxuL+sFWzavhIrQCCAA+QADoAxqBy/sriSResKp68bXXxFI2nXrimeNpFazXWFU+7eF3x142xXv9n1Pfb4+zxPGdt8dTyNq/D6z1Zr/0kvQfwAlhP2LrcINcE1hJTW8AScDI3AJXPZupJcALGhCj7KSas6ljQl006ZvvyycfuWH3GCTs2ykm4Tg7D9QpxMnAe4kLU/cVmzbWZQeafYjm6rXrtrfwOAvz6nZxX5uDKfNwOcl2M/AedZyDPQJ6BETcDK6aMHsCY8FBBgoEaunTpNAvLkR/CnEBeCDW0QeE4Fslz5rEwJo44WxiVSwJcJYA89CZ1pYX7oRZ2q5UPITPggzL5yy1SPFIrgOCJggJwcOgIHgaV9cXTL1lfbH/A2Robimc8kLGxeOaDGJv6DP/5M/QYHusjnruh2K7X4LViPF2vzXsAMd7ToAWs2sA634EFMDl/VBTqiTBf5KUuaIGJ+V0h+ACgFZOPK3S7OEtj5ZTji9Uaa04fXayTwtwox+FmgQhXIurTzCECD/PPsDyd5jmOyuMVCheajR0oxYhQInC031Fpac929hH31cwnnGdg75kBFsrzBSLL0ZA7EYwIyz1gsRL6WlRDDW3WFfu6M07wkFxlzW4qIkCEUnAIoYCksPSa5GYIeTmAFhePV8gN5UP4DEVi8CnVDjB4+iU1dAI4z7p0U/GsSzf7uGxz8exkPEu3bcTPe44810c3vAJsJcAMXg4uh5VAZbDqBRbQRFEBU8KJfMZHrp3j6kmff5tgHopptdTksklHFctPPbpYcdrRxVmnHVOsFJRWTzmuWCsgEfbcKNhvEpTIxQF/lChgIkdHiDRMJBcvnlxcIuiTx4tBbu9i3Uc49IJWnsvqtnTxgLHEwooKA+49f+X5k+YZyDNwj54BB9GpO0jic3X/8JUKPy1X+GmJ54e4GkcRcbXOYkmtUF0jVKsi8kIsgJcMTLVQHEro4SWEyP8QgiMvY+E3hcBYvGsAAR9UT6idGjrPvmyLoLOzowbVTkFKsOoFVQ2ptrqqlRWAOtsUFWE/PtcTpPD4rBgngPDlq+cYoEMxkWcbOPmIYunEI4plp4wqVpx6lMB0dLFq8jEC07HF2qnHF+sSOG0u4VSBCShJCZHDA0QPUgg08nuEQLmgeIh+BzgMG6HEElCE9AAkYCLXt0lgIjd1j/5jzSeXZyDPwJ45A7Tj2bZoyg5bLKVcLNSkRexB5Ii4uibsoytyrs43zjjRwkgViJLwXA0iXxBZDHktXhcDAmqBMBz5nycqxEXeh0U7FBAhNyCA6nG1I/g8eEvxNw8+Z5DBz/1xPHZoYMVrlwoKJdWjntL7aiWFompCqh3+KxVUFfYTmARXwnx8VnJe5J6A8WM2LLBwHmFMukwwn6sEncUTDi2WnHy4AHV4sWziqGL5pCOLs6SeVgpQBqfTjy/WS5USIt2ofF0bTtsEl0sWTRGUzrCLCVQuAMRtSI6L30fkALHK8/7hEDzXQoqnJorJTRN75l99/lR5BvIM3KNmIEAUrrFHrlFSXguYhed0pX2RzAdh3SZktO70MjwHhDpAhDkBWzZ5IUJyvC75lMcbhDwPRDgL4wDmAnI/nvMJCA0HQEPDqQLUsNRUDSgguFMqqpGn6gMnKT1TTCWYLJynkCTmCFQTobwHqWaKnA/qhM4USxXCWzj+4GLR+EOKJScd5nCScgo4VcqphJOF9QQnQnooWIqO+d2hbFFF/E753fL7ePR6t7tz28OIs0xNEVa12ipBKXJNVShPXTVw8t2j/njzyeQZyDOwZ8wAIFJh6Y7HnO02ZhTMI3QV/ZAVUkW6sg77Nosbixwg2mjW7TaIlEhXmIgwEIWltvDpKhxrNCoA+zWqAHWASkAtWCgO0wH5G8v5DKWABgPQYD/bWeUU6qoJqApSfVWUKyg+T62eeuEEfCOUx1xginjSBSstZ0YIE/PDhcoBAfpNAgBQmnfiAcWCcQcJToe4cjI4lWG9UjmtUr6JkF6oJhQTShZFi7JF4WJE4Xf7iFVSq2vJ2y00mzwXCleUOa7L15wpk8l0s65jwUfteigvUUwZTHvGApA/RZ6Be8IMUAcDiP5iA0WgcoKtwwk2RzkGv0qO8Nz5SXjubNmNrZtCoojOL3NEhHzCpEA4yBe6JZbMxxXHoks4LiBkobFStQwehhsMNDv7MwfTzqmmgBPHPoDqDPXV4b0eOMkU4XmmxAQhMEWeCVMHqvKBmlNccVwADAhKc8bc38A0f+yBDThFSG+FHhPhvMgzbUrVksKBF6OWpF5DLfE+KKW4aCDHhQEDNcvvkVArapeLjXYYj0a4Ob90T/g253PIMzBCZwBFRAdrOhSQy6FbAYuSmxaU6FZox8NzUkBycHGVjd24DSJcWtQOoYjCqBD5IQpTCUPhkLO8EGoockJDQeghgsxQY9A80nAg1QLTsPJNKZjat5ug6nb0STW1lBN5MgCd2skJYT7lwtWWW0NdAnmcePT2GzjlqGL28X9WnHnCfhWcKtV00qFmhrBQHjmmRC3hzOP3uPXMCQUXGLVaOsPVknJJXJAAIVOygpLVW+n3R56Ln6HaMKaQYwrjA268zXq9jaglFeKO0K9EPu08A3kG7u4ZwDW3cfbJOyg6tfY4gpGrInUXIDyHaUEJcBLh50V47ozRKryUvdgUkVu4Cd9wtUwnAnJEEZqrFREmhVBELRB1gaSCz9biOQ8ZbLRA1fVaO3VfDSUUU6WawhQxrJxTG0zp/x1SfeFU5py8BqoEkzny3PgAyDF7oFxwJQIDzA7UJc089r7FrOPvZ2CaK9WEYiLPhAnC1JJyTP3U0jmzy9wSakm/R37vOO8wO7hSkqqN8GpZZIz9nvPgMdRR4Zokt4RVnHPSBY6AmdXS3f2dzu+XZ2BEzgAtZLapbghnG1fBwIP8AQudWbkFFxYnTAvunlOHBbm8WGzcsCAYaQEi0U3CG6gRyrFwj+WIukNz5pIjzGULfku5GIgGA1D6s3MEqwRIOwWe1vt2PrcXTgGp9GjOvQBWHIcNri5ARa6JotxeKBHmxAZPbofwGYaHrfqdnKU80Yxj71PMOu5+xezRf9ZQS2F+wDa+/BR35WF8WDP1OMst4cYjF8hFh7nwpHIxrviFhTsgTeFKJdmFxTYv/MWyjlpCBfO754IEtWRQ0gWLqSWgpPCiVPj2EflFySedZyDPwF03A9bzbM7JO6j3eexG78GGKrq8ctBN904LUj0kvlmoNig8t1ZW4gjREZ6xPJEWLnIJ9JMDZCxMHuJZamYFHGN0LyAEZSAyuzYLfQcQBlVCKYi4nYCI212v9ye9rxtmFbx6gFWCqTJG9IOSd4LABEJeh7l+hJrHkv85VxcOK6eOLqYfc+9i5nH3tTDenBP2L/NLtfGhmVuqoUReKTU7UK9ETil+r+QUseTTFQMQodaeeqGbL7DpY7zgsYRrLbeEUkqgRAgvQ+mu+17nV84zMOJmAGvuxVq8UEWEWwjTuYNOLWx0hWt2bqkmrpKtwFU5hjW68j6bXIOF6LzNzLZSFVFciYW7NiwoT1QuWPSAIw9C+MnrhhS62g2qqJFL+pNCZ1dBmIQCO8BUh/PaUKrNDuSUyOcQRuN3iJKh2wJNaoHStKP3dbWUhPBSRx51TNQwEcJDKeHCO3uaLPsllMgp0foJ0JELxNiCDZy/G97zied5+DX6/KWhRBQyYVtyiYRy+bsJpYQ7cN3MCTsIFY+4L08+4TwDeQZ2zwxgWlBhq7XfIdTDwkJugNoTrmqp0qcRaoToSHQTxvEQnXrPKbeAs6ttWqCI0heqxb5QJYYFqx+6FOt2mUO5UzBKFNGIhFA/eJVwijmyY6qWHEp1TikKaddZzz5Cd9QqYULhwoAedWzvvvy0Yw1KrpYUwkvANH/sQVa/FHklimrDGk69EvVkGFdo/wSUsPlzscLfStjB7aID9SswRoNag6SUE+dThfCksjyE14bS+CJDafd8t/Or5BkYMTMQpgUWLBYK8gBh5yYZzZU1DVG5Embx4crYQnTTTxSMTrCrW8JzgOhCAa0yLayaZfkmXotaFQvj9AnPRWeEzrCahd7a4bj0/3sqiLoAlZofuB3dIEooYQuPItqyiau3HVpuapdOC/wu6epN5+8lUkBnHLVvSy0Rwru/2cMXTXCzQ+SUzIGnQtoN08eU7ruTrDErFynUKfG3Qo4xQnfAMGz7tHJiACXOCRWFG5DnEMIjz+i9+dzogFJaP3NCsSJvfTFi1pJ8onkG7tQMYLm9SKDxbRBoR0MTTzcueOsfOi54vgjLr4fo6EF3QnG21JHliQxE7p7rNi1g4yafsNaKOl0VeTeDAJEd+6ojB07tpGsZFe6R+aEumCT3tfNb8f9hKTsPa9Zz1w9K3l3cQmUCA79jcjj8Xh8g5x2hu7XTTixmjd6/OP3IfUookVfChVdDyR14MjpQRFu2Hlp3hnoQ6oKEfoT8TaQmB9Q0+UYL3WHhF3xQSd7Y1kOKASXySoQTOSf+dsgrtaF0trbJyHmlO/U1z0/OM3DPngHCc5vnnryDmh/qR1BFmBfqEJ3yRbJ0c9WLpZuGqIRoyB/QceEcXWFHYSudoFlMyCNUyW0l0lkA6bDQZVqwHEgjBMUimyzY6e1YrNvH9DH39NvJuWO28JGqvPR2C7h9P1uqllIohfOO5qxSJDIWmErS7xpIYFTh9xShu5XKDZ1+5L4a9zIoYQ0HSmF2WDBOtnDVKpn7TlCigHbNlHDenZiYHE4zowuhXZQ1FzamjCuV5G2eXMGVvfkEKzdeyBquvBIGCe/L5xsSYglHKWUo3bPXk3x2eQZ2eQbYFfQSgeZKLVCE6Fik0hAdha4sKnR7ptCVPEE0RF2rpDZ5Iq5kw8YdIHLTwgKDmxW3arHhSpgr4ypXFA6xNoz0/85wXd/FuA+87omPL2E0OIRSIHXd1ufldXo+Xy+UcCqST6KgmLnHVMBFgTVlVegURRKLf4TuFkw4rJg6ap/i9KPu1enAo+0Q/fCAEl3Ea5ODh+5cJXl9Ehcx/A25SlLeUH9nALFWSdjUo5O5h++AEntXEe7j78nMDgoDh9EB9x1QYhfbXf7Dz0/MM5Bn4J4zA+SKNqnAFSUUTTk7Q3S6SsXOG925rQ8dIRrlHAJE3nfOd321mqL12hAvckW6Ira+c+w/pHwGi+MzA0QcrY1OupCijvZQIA2phrrgM9h9g0PJ3XfNfBK9/1BJhM6uVIjMVJLyhQ+XFZw2T5vUs479lE4/6t4GJXJKldGhrFXyAlpB6WQ5704ZZZ3D6Rq+XjZ/jC1csITBgVyjqSQpnlBJOO4iZItCqmCpvxHrxyeji0NpwBQc9Upc8HDxYwW0UkoGJeWUMpTuOWtKPpM8A7s0A8TgqfcgyRwwshCdksoom4erYSYuKSzaLFLbFKILSzeb521RuI6r1ujEzYJB3B+nFFfc0c+s0WnBYKTFsQWjHiDdbTByt1pasDq8210QGMZ9u0UZdcOprZasdql032GfN5VUGRzq8BjGElRxqCQMDoRjsewvmXhkMfnwfRxKsoQHlM4cvV8xtzQ5ROiusoKbwaErl+S1SWku6ckXRL0ZijmKeettNfjbjM0IcWVWUEqU0obZGB3Gk1Ma2KUvQn5SnoE8A3+6GdikRqgsNg8WQLhCJolMXL+ZLyJEV+aLBJ00X7Rs0tFWTNnOEwExHFJsFkf+ibAMr89V8F8rTBT956wbdwtIdTK+VEm7HUhDg6cqPtV7t2/3h9QwIJSG1Ha7OmrCqRm+qxWnNZ+9FJXkuSQL26FEFLZj0Se3R7EsjjsuQtghlguOdTIpzDr+/sXkIxS6K00O0+nqQD7J2gy5FbxSSUkuidwiOUY6dtCENWzgFFJjpOBvjosVlJqbG1wl1aE7V3AAk8JaOz9d7BC+M6VUQol8Eh0d1s2QJTy77/50C0t+5zwDOzMDkw7dZ+DsWSft4MtLKIQCSVdG/mX3rgveGDXqiy6xFkC1eWG1kt0kvq3Lgq6k0/2JWGRQRZWdm6tfilwjXxR7/AwDRh6u25mQ3Z0ATkfuqgeQ8ZgSVk1A7QSU7mIgWSeKBIDxOTxsFyqpztdEaMxVyGKrDXPLNR0cJso1Oa44a/JxxZRR+xZTDEpucpghkwNNWb1otjY4eC7pWNuFlias1lZIZhdCvWxT7x0cogZtif7+6N7QpZLqPBfQ4uKGixz+xggHR04JR+cWvb7nkwQlFc/uzHciPzbPQJ6BP8EMrJ42ZvvZsuMSonvKNhptljDSlzw1L7AYuXmhLnaNfnSE6ajqDxs325E/UgnnVBXFPkVceVP4aB0XFCZ6RgUjtlEI9xe5o/oqPhZPO5pCCsh0Lfjxs14101A3/V7/zt7fOL+dAOfOAumhUkD9Rp+WSWnozubCPqvPeb+wHSoZAwG/S8KugGObIEIz3NVyUM4fd4iF7gxKpcmhrZIGlEuiNskcd7pwoVjWu4KjkprNVymWtbokujfob7HKJRG2s9Bd6QYs65NoyMrfVpXrkiOwdt9N8masutDC5LBm2tgMpT/BGpPfMs/AkDPAPkWb1H8OVURIzRpstq44vQVQFLu6k44QS+2kG1us1+ISqghocZVKTJ8r1seaKvIQHYuLFz2q4JF8kcGITeU8qd6EEZ0FOoDUqUI6ANT13Lvzvp7z7AJn676dAVIJouc+9NyiPZ6j+wxUnVBK3zPmNwESbjv9bihItQ39yrAdyjYUCBclhO3OKcN2SxWmPe3Qfap8Ei2G6HtXq6SDKhs4KglzAxcwbEtPR/DY1O+BMiXQgJf8ZLQUQq1jePH9rRTaxeBQbjrIRU2oOA8t6wJKoUX+lgktYqShW7htPugdwiOftH3IL0d+QJ6BPAN33wxg5QZE1G2gWBhh82066XwjvUbnhcrWPdaKXTE2kFBGFQEwapO4wn2crqofr/zDlYQAI19kW4iXMBKQAkaN3BHdBLqcdQGUcrG/W9ROvOeuHhtqKYVBx+3hAslg1AuiXjA1c0hRKBy5pBr4DqRnlXmkytGG/fvC1d7fLtlIzxZ7OePO099BhO2mHnlvV0mygp+BSopckgpmw3FnKkl1SWYBl7mhoZLmhwWclkLex7ChkqwcwHf+DZUU0ARYZnBAJelv7jGm5Dx0RxcQeiQCpbCCk09aefqY7Xffty2/U56BPAOdM4CV+2y5jrT7pn1JCYcQpw8LLYuAFbvqKpOtp1l8aI7qm+l5GyDCdCsnH29V94RGXBXNFYykilTciAGCmH5swMbrU1+EnTgsvG11NKSzbleBsNue573gendyDZUxyHEnoDRk7dEgyqgNJP7frZRqGAaU+hobsH8Twg37ty44+H1zEULYbhNhO6mdOSce5CrJcknexcEKZmUDTx13ZgFPzA21BbxuvGoW8LJQlr8jL5ZmF+Dy76dUSU2Dg9vA3YDjuxI/TKE7zhO35/k6V+zgXISdjRV8+thiYMoxA51fknxnnoE8A3f9DAhG29cqEa3aIgu/EJKhRQ89wlBFWHvdvODNUQNG1BhFTzpgtEowYrM1dhglp0CI5FGhivQ6LAokmllIrL5IV9rmpGMhUQ6gF0bt3NEQCmmXINMPKLvz/t0AJVNJ3crGFM4w1VEKpy4oVSoJtan5rIGkIln9jsjvESazkJjUrdm/BQfySHRtuGy5FnqFw85RG6B1WtwXq8fdqWXYboqpJLeBWy6pVEnsn4RKsrDdZDc30E7IzA1S6mZusLAdFnDfWZa/Sy+UdRMMEHKFROiuN7SIAYN8F+FF/i5R7hG6O08mh3Jzvwjd5XzSXb/s5HfIM9A7AytPH719nWBE2ILwGTACGH5FudiUDVXv3hy17tSN++nCcg8jg5FawDxEV8g46Ng+wEJ0WqRSVYTasnyRDBI46YAROaP+6qgfkPrkkTqBtDvB4kA091kZPuy63auW4hz6gKlSSrVCCTBUx6HCdrsEJCmlVj6per8AEp+zUY8UnRFqezV/K2k9Ehcq7rYbW6wo3XaRSwobOI47NvZzlXSwFcrS4y46N7AnFuaG6NxATRuqBhXG3yN/VyhtMzdY2K7MI5m5wfNJgDMKec0GbjZ1dwWGCYMyBJr5Wj6p7OJA6G75lNEZSr3LRb4nz8BdNwO46NYpTLdJV6GhWAxGuuIlREcCmatJvrwsBCSWbZtxLQ7WfUHP4yp28cmjCsIgXL1SL5IaF67Y4iG6XhjRsbleREwdtcwMjfxRuOyqPFIs8sM7doGj733xXnfmmACrCag7C6U+KmkXgNQVumu47QzwACk6NtQKqXeh93okUx7Kz1yg3I+57RS2m3XCAZVKoq1QdHBIHXc0XiVs52674yyPFFtTWE2SVFejJintb6cLnAjbWaFsCaWeXJKpJC/mBWr8TeP+9L2USiu4ogQUzK6dPq4YmHTM9rvu25dfOc9AnoFqBui4oA7dBiOzW+sqkwSwV9+TLxKMBJfovIB5gZ503n3Bu3UDoyUnjTIA1SG6+W5cSEJ0PTBSzB8YEf5pqKPhAAlIJIv9oLfvDFB253M7IdoBpkop9bGED0MlpSG54dxuh+1CIXkOKVFHuOwI2SnfFy67yCHF30wUyHLRcqFUx2Zz240tFp18RDHpkH2K0w7bp1GXNFPbn7vj7kDbM4n+duyX1NNKSDVDtoGf1Ax5JP7Wejo3lLVrzbCd6pIivGj5LrpLlMXcUu9Rm4QT1LqDy+AQoTtU0qrTxwClgepLk2/kGcgzsPtnwGCEMlKIArcUxgKDUamMwrwQMMKgQF8x9qrZpivfaAW0RMqIYkNCdFZb1JEvChihwHgf22BNi9qwgITtW1fnDdv37gTF3f1aPWDqgJJUiRfQ9gnfDZZLkkoaDoTiMWYDT0J2TRh5/shqkMpODW4WKPchwsHGIq+coAGp7NhgqkNASvNIK5QXOu3wfZsqqdxlNsJ2C8cf7Hkk21W2mUeysJ3MB1wMXbZMeaSVs+1iydx2AoyF7cotSTwX6TnJxvmS79IFF3nRyCURVibvxY6zdHEIg0PqulN+NYfudv8SlF8xz4DPwJrpY3fgJnIYrbEYe1MZeU86rkIxL4Qyst1dBSPauhDbXyxldL7+z1Vm5Iuo9TBLtxYJEs4NGGnBsLyR1BGuusGB1LZ9A6W7A0zxPnf26MqiL0gFpkHDeJVS6obSoI67YUJpZ5SR94vz/YdCcdB1m8LTWODJIVmdz8qZCoPVQFo/Y2xx1pTji5nH71+rpKQbeITtFow7yLqAk0daOTm2Oa93lCUEyN8g6ou/Sy6CuHBiR2L+zrjg8Zokh1Hd447uDWu93VECUFoKEVrm75e8Zxgczg2VJNed97o7MYfu8uKZZ+CumIE108cJRrUywimV5oxwShFbt5yRaj4MRloA0jAdG6ktmjCq2KwvLPkiLN3edWGxYDRgIZEGjGTt5n0qddQXSKnLLgFS0q3B1VIKi3ThT+/fPbd5v6GGg3Kw90vPsXW7AaaWWtpVKA0BpB4QSXG5MvL3txAon1vzTl7PHGs46wjVYRLQ4s7ib+pIlm/62dH6KdxrwAJooJB8S4qxBfskzRx9fwOSOe6OqHvcediOmiQVyU7wPFJs3rde+afa/u1bnFMkS9jO9ssycwP7ZS0zCzrnluYlI3yX7uXk5gZ3j1KXBER5LZT+JUuU+5JRBxt4qpLOmnJCcVd8H/Nr5hnYK2eAGqN1M8ft2KAWKSgjFhTyRigj6jmsxqiCUd194VItLO6mO9Wq5skZrZJratXU0aUyatYXha3blJG2CcC1ZzCSOnqqYvwWrusCUmr7rvJIHVAKOFWhvF4QDAWQ6ufpa+3m2/0h1QISIcNdhdJgoTvCcAJTGz6po67bvFD2rUtCdOSMUB6oDIwM/N2QOzJ1VJoEUBtclKA2MDUEkKKv3ZrTTyjmqY3QpIP3KU5VLik6gdO5wd129LfzPNKA8k3eATwJ2yVdGyxsV9a4RSuhx2+ODRwxN6wTRMvcpDk4UXaukhykdAL3Hndm3NEFFWrLznuZGxzOnV+3FQqDw/JTj82hu71y9cwferfOQBS8blSdEFd9hFoYNYwWWuiDsJtbu70vHRbbqs5IDTOjN93SU462x5FUTotdUxihuoCRgQ91VIbrhgZS3anB9j7Swkin6aprw24Gx9CvG+/fdXQVMeRrSG10A6oJpzqEtxNKaSgopfmhSgm5IurqVxddvVnQmyBSyEu5Rn6fDiNf1Pmdhzpi91iUNeqFfCOteaxjg8K7q04fXcwff5gppIa5oerc4PZv8kh0ALew3Wketqvqkcpmq20g8TfIRVWE7aIxbxtKlQW8w9yASsIlSq60oZJml5v5eQeHbHDYrStTfrG9bgYCRlzlbdSXyxYUgQJgWGJXX2bi8AYjXd0+TMliFpSAkeWN1AaGvBEW3PnjDzV3k9m6k84LbRgRzqELAw1Zq3DdsBRSAqSGUmoDYTgwaD/n7vr/IOfWA6fdACV16e7KKaUKKA3JWbEr5gozdJShuSEUERcwT7pgpcJ0Z1khLArDYeQ7BJsjk9CXgEToC9caLjuAtEF/e6ukkJaccpTU0b08j6RC2egCzl5JaR5psXaTja4NaxXq6wSSjA20EUKRocwqIOk8CdsRXqwcnGWdW7gD+Q50mhvKcyeXREshyyXpAo7OJTjuVk87sVg2+fgcutvrVtH8gXfLDHjB6/gCazcweqK+rICCGHq4jFhIougV5xIwukzKiHZAwGibQhfhqFs68cgeGEXOiBg+V6h80XmPSh0NBaTU+l2F7YBSL5iaiumuhQvvZQMotkf8rDy6ghvsfLoB1VRNAQgdqxDeTiilZOuIcMpxbKsg3tMVXXwuLyAlpBU5IjMASNWycBOeMzXN340MDDjqMDGQN8JMgInF8o6JukZlPGBgqhb102z/q+j8vezUY4rTjti3ziOVG/h5w9VynyQZG9I80pqpxwlIY6rtKGhJhELigimMDVwcRdcGuosQVkQNVbmkEkjuuEuarhpUvekqr/EIzA2CHK9dbXuuOruNpblBZqDirKknZJW0W1an/CJ73QxQ2LdK20nzhTIQCRa2XYAWEhLQfAk7YVTZu+tao4GTj7S8QITp/kJV8iwCXCUDozAx7ByQUqddEvM3GAWUWmAKOLSgUAFkV++P1+05DnEe6eOHBagAgh+HhhJuvARMdE+ozA5+u2okmz6uKmgFdPGeQAgABYTIDblRIfJDDh/feI/N7VAehOQAD6Gx6m9GizfhOcwA2LzNjamLGdQRC7p1P5A5AFPDRuUt2dZ8+WnHamvz+3geqWwlRJFs3QF8/2LeWOWRJhxaLJ3oW5uvUfePaLTKhRFOu4ukXshRubHB65Gqrg36GweiHrajv53vKBufG5VkpgyLEpQb+OnzWf6LsJ0uyixsp+8A5oatMjeQc2V7CrqZrD7jxGL55ONzLmmvW03zB75TM0CdEVd0mBhQRKgXoAFEbGFR/mdQGOlKlNb/W5RMXiIYnaeFIBqkBoxYrLpg9ERdpaYKiStWFgEWCc8hqWVQamyoVNJgUNoJMKSQGPbt9PV39XaojuQoSHUrqIBEG0xdSqkFpQ7wkH9yd1w8P17fz8XdZp4XenppUCCUCoCq7RnUmYPQLQn+gAyJfgaLNKAhnEU4jpqdi6VUUBLkihgoorjNZozn0vldCmOTLojWCEjLBKQzjr5fcUppbIgiWbo2zFAH8Nna3pyN+xaOp6+djA2npttRjLUcZrUdhc6BriEAhPo3zAlcHPF3zt+e7TZsKsmh5BBuFvWSQ0372/F9CLddjwVcYbuwgK+Q4y4Xy96p5Sk/eW+aAdtUT3F77N3E2AFRNEkNGHk7oGbOKApfrSWQYISJYfUUxfD1OnxZH60rZL74QA0Y9VVHAhL5Iwv5aNGrc0gplKIWqVRJgpInoRMolSG8KHT0MN6uwmLnnmcLOGqizxjeuSRgAow9cApoDBdKXrtk4KlyQKkC4nX8fUIRMKe1OUHhKqmH2OW1VgWzDDiABsCQP6FAlIuQdNDrDTv0FkFms1RDDBRE3N4iFRMDEG2QK3O9lAU5JBTS3LEHV0476213hOzftnGfgHQ8xgYHUhgbVk0+tlgrQwR5JMoNTCUJdLaLrACJMrM8kvKgEbYjGsDntIugEkoevvO54MKIn9ddJuqdj82UodcEvgCXpqt8XqIM1O5xkaftKYqlk7Pjbm9aU/Nn3cUZkInBGqUSItmsxQEYoWIiZ0TIDaus1Rkp1BIGBmBEbD6F0aYZXtAIvFi8gBGhkQpIlkvoCNe1FFJt+06BlKqkGkqeiA44RXipdewDiTY8hgMNe06VY2i9z3DvL89n8Pcr4dQDJRRUDaY6hBdKp+vorr36eby2A7cZjnNFikJ1E8uAhdwoAqV/GyrH8jwCD0oGqMTCS96REFVjKARMGJjtGdYowc8g0a+dVu0+7l+nn/McIMTttTxGC/hylQpgajhzzIHFKQft08gjnX6k9kg65j4yNghIY+5fLCiddstOYRfZY4o1MjYQtou+dufrYon8JmE737Rvtim7tkoyKOHuFJRCkYd9vQYSO8riFPRdby/X3zrz43mwuiYJ6BJt4LPRTkjfs2LhSbml0C4uU/lpe8sMsCj4F2e8fckeLyWDmrGcUT8YlQYGYMSXHWUEjJaeerQVDZI3CHVkQCpfs79CSk0NZVFsFbbbWSgFnFrKabiwGNbj0vfYldsdICsBEaCoj/3AVEMJ0NRg0v2XNn8WIUA3W/h7hynBF9woXl1lFyN0UCAMxyKLArIaG1tgPQwVgCHfuFJJexZb5UkUYjuu71h66rH6+zjWfs5jVzCkps/Sc0n88zoM/h8wWjDh8GKGujUMBqQ5AGncweoCcricdkcWViA79TjtPOwFstTB4fi8QBAFSlxI8bkIMXLhxN85f+9ciKGUCEkCZHJkgInB/1Hv/JwQX1ywMU+ELMMp2AjbJfNFHqk0N+Rc0t6ysObPufMzQN7INthTiI3wC8lorvz4olEjYspI3bj58lbKqANGVMYPyFF3vsIVxOfZz4hQX62QHHKdQFIxLF90yyFF2C6cdlYcC5AGg1Kilhq5pV0Bxc4/B4Vmg/fuGvp5HVoc7HYNqRpGETYsoTRkGK+Zf6rdfvHafo5mTFAYypL1Wmh9w7zFtriS/+Fvge0VztHFBhcrACiu8oEFYFFORPsWHa0mqEcWC9QSav74w4t51ThMtw+z++ZPOKJgLGDocQv1eAbPWzzxqGKxatSWaAxMYhxTvu6Res7h2qjvYOWQ7tsLpDJkZwpJITsD0smHF0sFpBXasG+1jA1sa362wnYbVXpA6G7rnJNkKZ9oGwEGmOgqQg4oFD3FusCJ+QgwASPUkZk3SpOPA2lA6j9pJVS67dphO/JI4bYDxDv/Lc3PyDOwF8yAwiLWuXujvjA4gh5r4bVFFYyIs/NlxdYaTqgqTKfF6nwS0LryRBnRiQF1xJUiRoZeIJFDWqocEvbfVshOX/IaSGVhrBYAwnbN0J1DiSt6H2lOCSjF6AOGElYVQAIkrWM/ePSHTrzvYMfWOZXv2f1eJTw6FVM/taT7yQVVhoxWOI730/xE+CkWWfKEhFb5PROSw2BALQ3hJkvI68oe9TMgAAERoAJ05o47tDjzxENszB5zkLaKONDa/NDqpz3YRoKf87gzBZg5Yw/RONReA2gFxACaDb2HvT6vq9ebMupeHUCquzWQQ1ow/hBtZ1IDaZWAtEbbmq9T2A4obdDfKLvRbpaS52/2XIGWnorUPV2yZEoZyqNOaab+hmdb13pC1ljWMTLw98nwThPe+oifR7cJgOZFsl5P5TCX2252s0gWIGVzw16wuOaPuHMzoEVmgHg9OYBN+pISdqBHVyijGkY0SnVbbsCIlv7sNUMYhIapJI+XKtbPlSFfzE4g6arzii0AqWX5PldFkwGkyCNVKikJ3fVVSmWsv3LgDQaFfj9rwaJL5dh9/Z5f309dDqOG42C3m+/bC6dhgKkNIHJTFnJ0JWYQ6gARiyzqldwHeSHf/VSLJ0l45XcIneFwQ8EACeDj0DlAIbT7F9OP27+YduyfFdOOuZ+54E4/+j7FVNmz08F9p0vdMM7Q46Yde79i+rH7WQiO1zBwlbDitWcJQEDLAXeAv4eed6q2n4iQXZgazoj2Qdo9du6JBzaAtFwXRitlbFitPNIaqSSgtF5/o2cLShv4exWY+Jvfor99LOY4+zBkhOPvosXKNQnOD1s1y6IEfCeIHLgpB5cof8dY2+uaKqICHrard5QNsEc4fLVyY8Bd6jKH7XZuucqP3tNngEWHL8p6QYm6CTovUPBKmC5aAVmdiEIaZt1VCAcDg8FIV5ZW+KovNjBapNj9Jr0WRYJ8MXuApC8uxbD+hW4CKS2MbaiknYZSoppKOO0cHAYDR+/P7LV5Hxvx3v2O5eOGBJUAJSXTBFMAJkJ33ceAkKs4P19TQ+RAFO40RaQ2PswxV/ZccJDvwBHnITlPvHMFT/iM0BpKZtYJBxXTlcMBKA6dexdTjtxXqmXfYjLjiHtpiwj1mksG/7dxhI4aPIbH8hyeO/WoezdAFbACcNOP289AZ+8nwPF4LN8AiX52Zvu2OqR7F95g9f6qQzpIQDpUCumIYqm2oViukN1ZAtIqAWm1nHrYxzFKsDU6XcQ5upmC/48zZymuUOYBgwYXaUCKvY4euPR0Wdi9KStzxoUb+VFgbrVWghUK063vaoEkhWXmj8UOedx2dG2wsJ2+c+SRmOOFJ40a2NPXmPz58gwMawZiXyMq2ElKX75WXzQDCTAq80X6YhFfb8OILgxRa0TeiMTxmbqqJVzBF7YBJH1ZqT96LEDSaAOJJHIFpEolRS4psYFv66eU6rxSXavUDwrt+wMmHUcURTqGBR1//V05j6aaKlVTPzCFM65SQgDLQWZqqAxnGoQEIkKeJOPJf3Blz2J6mQpRUQMsvDjgLCSn3A0hOUJlQAgFg6JB8QATg46UCl23J8UQIE7RmMgQMCYCDkZ5f3qM56B2gBevV4EKwJWg4v0CeMCM5/HaVoek2zRYNYedapBmHb9fMWfMAcV8NWDlomiJCmOXTTpaQDpGxghv5mtAkkICSIw1uo2bFEt5PTBmjC7/P8acgLYJpeDExRrFrhfrYoy8Gt8HoIPjNKIKzCl/95hAwm1Hbzvm2DqAm/3bd5MlDweQBPyskoa1WuUH7dEzoHoIs3hT93G2bLoP0BcHkDBSW3cvjFTEKIABo3POlKNu5liz1bIQYGTwbchrIHHV+BhdRTqQEtt3hOzSPNK5ZfugLigBoxhaXLnSt2EmhzA7xNEdUeGMqnNNbRjtnv/b+1C423kucU7DhaarmhpODqamWkI9OYDS+w1EADRVQyWEABFFzoSdMKYQnmORxMhCbcyAWvNgOCBMRggNlUKIDSgABABCY1NgAxhOjnHgPsVJfcbJut9GPLY8VtAqgdUFKQOfoGPvW8Lo5AP8HPjZFLYyJ1ynXWNnn3B/1SjV6mhAYeNlCtexsd/KKccLMKMFnxMMQIAJALGlBc6+Fcp5hsvP/m/3ufPPXH8KrQEuLNt0jUDpEIIjtIfrEHUJmAjT+YWYl0UEkIAX+TgUaHRt8C4odG0YXSwROPfohSZ/uDwDw5mBNbpKZDFiXyLCdkCILxXHaOVyma4C2ULCckZLFKbTF8vs3WXeiNoOEsW4mPhi8yWsv5ge0sDy7UBq1SEJSI9Pa5EqlbQLUGrklVIAdN0GHE1gBbji2AWw+Jk9dxDw4FZ76kXeXcI7THSdQ+u+Us2k71sDKQDVG8arzRX+mApEOgfrri0IRXdtwkosmB6eO9VCUuQylun3hiLCZEA+qIbQvSoYoHAAkIFHUJjQNe6v+xnxM90en4yTdL+NgBTHNqBaqsrgp/vsvfVaEa6z7Sei/kgdGuaceKDyW7U6WqpFnkJa1BHgcQDJUl4CiJ8tM3dgOPqOVj7nmJ5B7gxYAaaVBjIprOke4iakh/MwBROGH/sOyI3Kkf8z34CLx3nYjnokb7ZK2G6p7PE5bDecFSs/Zo+dAdQRXyzU0QZ9OfjicNXMSPNFFA+GgQF7LDAyE4Oeh32WvBEwQh1ZyxiF6xxIGBrc8u1ASm3fHrJrhu1qt12E7szgMKRSSkN4oZoAgo+hFUsLDIOApv1a8R6VUgvFNtRxqHNrwClgFMcyjCcVlAIrQGbhOb2/FW4KRuSJSLrzu7hsxXSFjiZbwTMmFhZZbNaE5lBEgIiQHGE0FIuF4AAG6icgo2MKmfH76//DGQmYGs8v7w+IpYCK2/H+HG3rCZ1bqo7OVO3RvHEHFwsnHKbc0Sg511BHxwgkAAmYoICONUBxP5ZyimwXT8RyjvV8lGznDLefL9L9DEwcPBZQVWBSOA8woZjWCObkg1A9KM0A0wP0nWFLc75TAaSLlUey3na6kKMDReSReC3LI518ZA7b7bGrbf5gQ84AxXmoI3MeKRRBXRFhB2Bkfcf0pXqQQg10XTYDQ8BIYQdMDBQYYp9dLxgtkPMK5cTzyR8BpjR/ZCE7qaS6DgljQ5pHqs0NkUtyKA2ilLTYWmuhKoTXBaYAVHIsYVDBZCg4pI/vAxq3pPP+SUiR8+L/1UjOof06eo827FBjARk79gDIw3LxmApEej9Cc7UqWmK/E8Jz5ED4nZO7oHaI8Bw5IkJzhOUAkUEoFIkAACjOWzLbIVSCZ8J+un9nh547oRwpwMbpvnGCEiMFVQDKjvoZMDJXXRmqO13966w7Q6WODhVQjhBojtRnc3XkKkiqR1AhhLeEOidgI/gsOEn1UPq7nScDhNvNk1op3c/PeEzURzmYBDXCe0DO8kzkoHRBRihPkEH94FAkPHeJvjsYGvgumbFB88/FgG1JQYhcDkYuCAmVAiRquGaN3m9gyC9ufkCegT1tBpS4dnV0pq7U9KW4aNGU6mrOvkByE6GK2FyvhpHs3YKRmxjkQCpNDPQJI+HN86hRauePvEuDF8Z2he2u2FL3tIuapE4oaR8dc97pit+LZjE6OJQaYKpAEHVLg4CgDYZh/L+CT4AwOZphIPl/le/quq8EVUNddYApgNN1DIgZXHXuvB9zYnsOYeXeuMguEqiDYcHkir68GjfrNuE5jAOpYYCQHBCYfOT9inMFouc+8uLi5U+6vBpXXLCuiDEsKCUgCiClx4BTCqYuQKGI2P9o6pHe3Xv6sfctZqpV0JljDijV0eFa1EeZs84AJJW0BJWDAhJY6PIQAEIR4hrEgFONE6mLKmujyvqoeXocBbkKp5li8oJdV0uAqYKS5hXFiTOPdltABxMDFwHAiAGgPI90qoX5+H1EHimMJHOz225PW2rz5xnODHCFzJXyBbqaY4ECJjGqEJ2+TBerBgNrt4Xp5juM3MSgXmO4lQSjeeMO884NqKOVdbjOFVJt++4K26UqKWqSmlAK512XUmqDqaWYBoGAqxYHlgOmP7R6VE/5ug6fEoqAcThjW59zbIOwBaaAkeWwkp8FzAJEoYroLIAq5XfKFTu/axZPFtS5+n3NHH2A1QtZeE7hL8sPlSDqglAKpK7bQCtGwCo9orBipDBKbxuYSpUUQBpbKifcfNO0Cd+0o+9tJoYKRqWRgYarPg4RpPaXyUGWcV0kcaFkg7qnqH3Sz3iMPY7HUgMVdVBlIS/Fu164e5Be9xBTUBQBE9qrw3iulhxKhPDk3NPFHXNNCG+rQnOE6NhGAyBhbODCj7AeP8PVSB5plRUbk0c6FkWWw3bDWcDyY/acGUAdcaW8WepolXIIfImAEBbWS5exNYBUUcAoCdO5o853faVRJTBaPfU4M0RcttzDfQEkapBoMlmH7ebbAhntg8xtt7F220UuqQmlyCl1QSlVSy0wAYZy4e9RTl2QGsZ9/WDDDqg2UG3tET8rj52vkb63FFMAxo4CD8onVFAcQw3xGAORXqNSRXLQ0YmbfBGLIFfqWJZJylNLxCLr4bl7m9WafIyZBaSIdgVEXXAa7n0ArA0tDBFp2C5um1Ei+VkAq/q5zh/3nTn3lPOKsOMptrvsvj0uv3gcnx8HH5ZzwDVdoUvGDNU/AalZAt5sFeli9kBVVWE8KS+ccYQ9TSnpe4RpAihhDrK8khQQIVKUEuqIgbEBtcrvhfAe8OI5GBvo+8fvKIft9py1Nn+SYcwAVfcUANIqZa3AQu4HF1CljPSl6VFG8yZWW5DjqDMYKVG8UPF3QnsNIMldRA7pcnUE904NMjaofZAV2yqPRPPKOpfUD0qRU2pBSQtuZXRIzQ4WxusAU5dqMVi5UhkMWKaAyuf3Aw8hRMJjg49uWFWA0vk0QnttMLXUUyg2g67ODxDSaQFV9JdbBqyOjKtx3F+EhFjoyBVVpgUtvlbPo8U4wnPtsNxwoXJXPS7UVkALWHYNwnwoKwv3tY7p4x+nMGOMgCCKLWBMforbOPpQY1OVTzNACUw0c2XugDlhPsJ4qCVMDyjOFEpudnAokVfCvMCWGxTVEr4DSAAK+zfd0QnxAbAA0iLlkeaOPXRgGF/j/JA8AyN/BrQ4bbdtJdQq5fz5p5hziMWLkTrpCNNRZ3SBvjj0qNsajroZipVTyyFlRDsW7OJciQeQsLk+TEBy63hAKQ3b1U1WyW/EVhRRKOtKKXJKLSiFJdyg1AZTopgqODmgGvmmLkANcl+onwZwAGEy6GfWHM2fp4+12wJYpaaknjrBJCgRSgzFlAIrHh8goq6InBtzx7yz8G3WYsdCx2JJwp6w1NQj712ZFlh8yROxON9VUBkprwuoQnFNOmRfcxOioIA23SQcTFJNAhOhPNRSBSW58ppQOj5x4NH5wcN3dEcnf8TA2EAYNYpkuWiw1kwYG9zxmMN2I3+pzZ9gODNAuI5WKXQ5ppcXidiLddVGiM7CdPrCXLSoCSNz1AlgYWKgJxgwoiIekFVAWiGHngFJeaSGSgJI3SqphpIrpcgpRQiPbgKWU4rCWYNSGcIbBEyV+QE4paMVRnPlU+5OW6khVx224KN+BB9UWQM6vHc5UCZxe8ij4FUBKsCUQolz2NZy6un/DbWGItJzOR/e+0oN6ouYexY88heEgeiUrattW0hx0JkqkgJAFaEO7mmq6E8JMOYCRWWKqwwNAmzATVgvQnqE8hxKyi2FUqqgdEwZvquhFDkljA5AiHAdg+Jx8kj8riyPVDrtgBvNZYfzXc6PyTMwomdAC9R2zAwbZdcGSGfJJcQ20YTsgFI7TIcyogtyamJYo7zRqimq7VA7FtRRCqQHC0gPkcvuoRgbKiBh/+7OJUXoLqD02HKri6ZaEpC2pFAqQ3idYEoW+1AwAKUaLTiloGrdtucEhAQeFv7G4P01zA1Y3ub/6SCXw8/9uMx/FvAKMNm5leeVginCihUk/TEBIldFen2BmibsqA6hAABAAElEQVS42O258sa5xe+YhY0GqDQv5SofGI1EVfTKpz26ePXTH1u8+W+fUrzrn55lR/5/V8EroBQhQHJU5K+owSKcB9hRm3Qdx5HnUDrcrOGulNpQcqMDoTm3hHt3B+BEKA9QRR4Jc9HAJF3oWR4ph+1G9GKbT37oGQgzw5YzFdfWFwG3kHVdAEgoI125XbiwDtM5jNRcUgCj+HUtoTrljYDRPLmacAw9YEC5JwvZeRGg1TGFSrKOD2nYzlUSW1FEXVIFpQ2E7yKE184rtUJ4ppb6gAnVosW+Hn3CZxWkmsDqBFEClYALIKiUG+fTGq7sAGkAdak/RpAyaHWAyZScKTipJIEowoWh1OwzlXDkPHjtKwRxCi9xc7HokcPg9xrmBVx0AaORoope8eRHGnCuesqfF6/6678oXv/sK4t3vfBZxYde/g/FR175T8VHX+Xj/S/52+J9L3le8fZ/eHrx2mdcsdsg1YZSqCZTTFKXmCAwhmB6YJ5x4WENp16pCaXS6CADEUqJ3w95PUCEqYFjdG0gvGrWb4VYrWPG2EO3D/2Nzo/IMzCCZ4DEKeE6QEMLfq6kUUjsAQOYtgGjBZ4z4jGWN5o9vgzVqSq9DNWtUNEh3bypPDcgLZU7T/ZiFsYGkAZRSQEl73FXGx1CLRGCcqUUxbP9oNQGUxLOA07paIAqoNUEVrrouwLi9X3xryAjxUbnA4artxI6dn/9s9hpN/Ji8ViDF2DqgFIaagw4esiwVGnAERjqvSJnRAjIbN1yerGYsXUD3bEna98gg5EWURbZu0pVDPd1X/HkP6/O4aqnPrp4hYDDc1+p21c99VG6/Ui7jQJ67TMeX7zuWX9ZvOm5Tyre9vy/LoDPJ1734uLat1xVXPf2VxfXve1VxfXvfG3x6be+srj6tS8q3vfi59ljX/m0x1TvMdzz6npcF5TIM512xH1NLeHiI7fkeaUDzeyAAw8opQW0UaeEqzUtniV/xAggASxrIVQCac6Jh+Q80ghea/OpDzEDhOu4emb/F0CzXK1QaKlPHRLmBYeRth+X0SFgtOVMmqZ6nzpcdWxyhjqigSWhOnJOFrIDSMtUxwSQyCMpbGf271Vek5Q67qI2CdedFcx2qaUepZRCaRhgitCZFvxGmM3+34JUAAtYleqjApGpIIdNAAgIsF1Dc/Te50AFqj54PIAyiFleTIqpn1qKcGMrZOhgXOYw1GsRCsXAsFHbGYStO3XSsWiSL7o7jQtABygAmKue8qjiNVIuAZjXP+tKg8wbn/PE4o3P+SuNJxZvet6TNZ5UvFlHwnKMt/7904q3/t1TDUTv/ue/KT74sr83GH1GIPrC+95UfPnD7yi+8pF3FF//+HuKL37gLcXn3/vG4po3vLT48FX/WLznRc+x9+iCzM7cR06pn3svwniEQIE+W2SQV8KBh/su6pTSVkNc/DmUdIGnsCo1SMAI8wn/B1Z0bMAR6V3WD8t5pCHWtPzjETwD4a5jl0x2yOQqjgI9rN+oJHPT6Ta5JYDFYyxUh/FBW0qEkQF1xOZmhOtYDBtAWk7fLvJIXeaGCN1FPimcdyWYlAcJtYQlvFsppWCqQ2GN0JkWeRbu5uiT60mBlYblWiAKCKHYAjCdx43aWsNGhB/rI49vQCnyYh1QqsKNLUCi0AAarwPMCZWyqLGQUb9CboM9iqzrAjC6i110ACfAg8p5zfYrTNkEcFA2bxFY3vGCZ9gALgDjXS98dvH+l/6dDZTNB1/+fBsf0H3cBiwfeeULio+9+p+LT77hJcWn3vyK4rPveE3xpQ+9rbj54+8tvn3th4vvXvfR4tbPfbL43mc+Vnzzmg8UN33o7cVnpZg+/rp/EcCeb4oJAO4MhNqPBeSNLhItWzlgAvh0HUcpEb7DfUdXB/rkef87bzOEiy6gRI0SeyJhaABMAAk3HgWy5JEWKeQ6b7xaOo0+cGAELzn51PMM9J8B/tDZ/4X80RY55ijmO1chg/OkkoASBgZgdO7cEkaVq26M1RyFOlqoWDmPNyAtbgOpFbaTuYG+dmEBt2LZNanJoXbfRXuhGkrsnVQu6KXKaITwSrVhhbS2uAtQpfLwY0eOpwdUNbiq51rYzZVMDSJA4+fCObF1w1CD3Jjnx/yxPN+gJKgZmJJwn4fwajXXT6kFjDAxEB4lD0HugStyOi9YC6CyF91dAyPP7ZDXQfUQUnuDlA4q562CDwAi1wNkCLGhbIDL1a/5Z4HixYLLS4tr3vgyA8yON73cjoTg0kEI7rq3v6pADX1GEPrce95QfOmDbyu+dvW7i1sEnu98+iMGoh998dri51+7ofjJlz9T/PDGT+n+Dxdf/ei7ihvf92YDE7mmyDFxnm3YDPf/KZS64ASUUEoYR1CnWMIjdOf5pLpw1muUUEpeOAuUgJEBiQJZfT/JI1GLBJAmjdpnoP83Ov8kz8AIngG6OpM/Akj0+aIwlu2aHUgK0xmM5KiTOgJYEarzmiO3ebMVNLknCvuwF4dCeqBCdg1jQ+W289BdDaUomO2vltzswN5JseiHyojwVzRlLdVSBSaHCICqINUJqgCXYFQaEcjHxGIPLBihgCoQAZhSxXGOvYNOFBT/JkOP4zlh3AgoBVjTEF6VVyrDjaHwXBV5vojnPVbngb2bvBFX1dQZsQjSpTsao+7u+iLyPaghy+s80/M6hNZQPigeAIThALMBeZ6ADUABLDe8+/XF9e96XXHj+9+i8WaF2N5kigZV86UPvrW46cNvVwjundV9XxFYvvLRdxZf+9i7i2/u+EDxrU99qAIR8PnxTdcVP/vq9cWvb7nRxq90/PGXPl384PqP6/EftNcEZCgmlBZges+L/kYK7nG7BCbySQGj9BhOPFx41C2hTgndYXKIwlkiEYTuuCCsWgwJPOSMXClNMLMDOUBARR5piez6ppBOOCjnkUbwmptPvc8MWP5IfczOFoQ2Czbsogl4ABIgcmXkoTqAFaE6etW5zVthB+WOlqlZJSE6gIRCihySdXlQ+AhjAwWylblBuSSrSzIbeCil/lCq8krlgt8LJcGpRy05QFzNCEo9gApQpcc63Bcg6gIQKohzMBAJNGznzqCmKkbXfdXPSjjx/FBUbShx3pxDKLQAE2FIh5GH6Dg/novapNqfq2ryRtiOcXwRpiNnBIx2R30RTjdUEGroDX/zVzbe9vynm6PNwmwKi3lI7aXFDkJqWvyBDjkeQmvkeb76sXdpvLu4+RPvM1AAC+BCyI2B2rGh8Ft6+7sKw31fcPn+Z682yNz2+WsKFBFqCBD94ubPG4h+860vFf+q8etvftH+j2K6XY/lebd88v12Lp8TDIEiSg0woeDCxTdclRT5pBRGcTuFEvNPnVKE7ugUbvmkZOsKQnexbQU1gECJrt8cgRTh1wFdZNBZIxsb+ixo+e6RPQNef3SC1R9tlmuOFvzAaKvyD2ZgsNseqkvVkdm85aw7i31kpI7WnjFG4ToMEBTPJkDC+h3GhtJtV+WSAkqE7qrwXS+UYsv0HiidnYS+tCC7Ygm1xBE14yPUTe+RRd1HCizuM9WxcbGFBxsAAoolhACM11J5K6RHaot3GxZ+jBBk/MyPfy7DgcEKKKGSKij5ZwgAcq5xTuHCCxBxf63WFtnGelwQkHcg/MOCR+4iGqQSpruzMDIjguWCrnDDgVxu5HyoAWJRRwWhgK5VaM1Vz5uLL0rlAJ+vK79zi6DzbYGGAVR+cMMnitu/sMPCbHdI2dzxpesEl08XP/nKZ4uffuV6gwy3f0b4TUeHzg36me4TfH75jS8Uv/j65wxC3P71LV80CAGi33z7Jr9dAulX+vkvBSueS26JQX4J0wNgIhRIGBEwYZwYLpB4XD+VBJgCSsw/lnD6382RaqVDBs1YG1bwZMsKAISZAaVLcax1/haQ2Kxv/oRRZpLIeaSRvfbms++YAUIGawQT1NFGueb4gmzRooZKCkfdOXOUW5KrLtQRobk1pytUpyLYFacp7CB1FE68ABK270u05TnW706VlBocojapC0pWOOub+bH4k09q5JRSKFWGBxZ2NxHE4t57rGEFeNqgCtVhIAoAtSAUW7mzg+5wxuWrCUc6pOyz6PMANgvdBZRKsMb5xnmhlGJUsJQywuQBsAmL0qxzjUI+ljdSeGjqUfc2a/edc9ORG3qkDAqPtrAcdT+YEVAT71U47qOvfmHx8df+iykNlNAXP/BWU0AA6Jul4gE8mAxcyQCTGwSSz9v4lSDym29/WfC4yY6//c6XCx9f0bFj6LH8HOD8JnnO7/TYf/vuVwuO9nz7uVRSBaQbDWBACYj9VIrqe5/5qBkgbrlGiklgInx47VteYVACTK8bpvHhZU98RGfYLlVKYXKgqwPWe1x3Vp80ESu4CmYFGjYL9Cas2kfJQnfjDEaoJQCFsWGZlO+Ck44U0A7PxoaO9SzfNcJnAAMDhgYcdjRGJWQQQEIpOYwUqiN3VD6mrY5mjT7IbeJmEXeF5EByY0MFJOzfhO6UdI/QXeW6GwRKoUDScFcTSpGLqXNLlemhUk61ggpYEeKrw3y1skJppSCy9y3BCFACRKi6h61ijyc/cjv+b4oPwCbjEavZnPDM4pF6jaZKKqG0wcN3rvTc6ACYrmgBsw1L5pLqfhauAYWACAtF3oj8xa5auwlfEZZ7nXJDhObepiJT8kK43T72mhcV17zpZVJCr5e54I2mgr529Xvc5faZq4tbCaUpd/Pjmz5T/Fzw+eU3bjTo/E7Q+O13v1L8/tZvFP/+/a8X/3H7N4v/uO2W4r9++K3iPzX4P7f/60ffLv6Tn2n85w853lL8Qc/5j9u+Ycff/+DmwsfX9TpfK/79e18r/u17ApJe+3dATeACWP/6zTpsFyoJIBHC+7lUFqoLVx7jGwofAiXGJ17/YgMT7r/hqKXnXH6RbTAYEGofUUqRT5p61L62z1KlkiZ5LokwazjuPHTnKikUEi2fyDctPPkoAU3h2GP2y3mkEb7+5tNPZmDxxGO2s7slm/BtVJwalxytg9h6AoVkJgbyRoIR6ggF1cwduToiXHeeXF1YxMPUQC6jyiOVYTuu4j2XVG/fDJAGhVIJgB4o9dQqEfpKQnjK70RuxqziqKdSQfWHlVvKyQ0RSgN6gMMAtMZVUMDnoSt991x20O0Z/EwjtnyPI88FSA2VpPcws4Perw7dLayce4+T0gu1FMcA5l8IYA8X5DCRkPjm4mKO5Y3uV+WN6MAwnAU1fQz1QhSmkuh//bOfYOE5TArkhzAC4Ihj0UYNoYS+odDX90sVBIAIsWEmQOEAIEDyB6AjyACbP/74uzb+3x3fLv77J9/zUd73xx9/p/h/d2jw2PLxAMngpNcIIP3h1hRIDiUHUq2S+oXtLMwHkDQI/RHG+/FNny7B9BHB9Z0OJuW9CEUCpdc+8/FDziNzHXs4dQGJ++gcjkpi4z9rLVTmkqqu4ArbEXLFBg6ACNURuuOIagqnHUDSbr4ZSMl6lm+O8BmoDQ3aOGzG2GKRvhxmXFBS3CzgASPlllBHbEnedtYNnDLKwNUDJOWR6rCduoUv9TZCtq+SGRyGD6VQJf2h5LmYyMcEmMx0UJoPajiloOq9DRQMRGVu6BECkUFICg7IPOQsV3covQevqD8DKiWGb/dOZ4qyOwXQAlCoKQHkclSSQBdhO1d7rdCdATVUXX0MaznnyfOZV683OsGS3ezyGi2BMDGkoBnO7QpECldFj7gPKLfyMdmzsWDjhvuyXG83yxhALogc0A9lKvjFzcrRSAX9VgD6d6kXAITiASpABwj9789+4OOnPyj+56ff9/GT71dQqkEFlHYFSFJJhO2kkuqwXhq28zyShwtdJQWQCOH9RHms279wTfFdfS6s4je+/83FDYIS9U7v/ZfnWrHuYHNIji6AxLENJf6PSqJDBjZwayuk0BtbVaRhO1dJgpIu9HDXoXyBErcBEl2/ufBge/kRvgTl088zUM+Awjs7iFlv0B87Ba0LlGil7Q+KyMHkYTpghDqKvY6oOwpnHU47t4irXglTg/qmXVgaG3rCdqUF3Do3GJSSRVyLdiiluit47b7rgZLyJj0hPNSGFup0RH5m0KOUBj8PowKwMFUkcAARFBCQAUIA9UHaqNDUHopP47LlKD8/WkgSWDFKYPFcXgOlFCopwnYBJVdJzdBdF0Qfo3MN9cZ8UcDMgkXuj9zEruaNrJBV9m3qciheJTzHIvzhq16g8NVLrCWP1/y8x3JDt39BFusvf7YKxRGCCxWEwgFCAaD/+/mtxf8yAkg6VkASmHpUEgpJQDKVJKgNXyHVYbs6j1SG7ZSrQrVhfog8Uiikn0khGZC+fJ0ppTsUasQmjrvv5k+816BEDRRgxvAwmBMvVUn9oOQ28PtWQApzQ9q9oQ7duQ2c37EDya3fcwWy2WMOznmkejnLt0b6DCyThXS1AUlXYTIqsKhtbADJlREwMnWkx0RXBpx1S0850jo3kExHIQEkGnlibLBapCRshwPMVNIwoWRhLoW4WMC9eNZDXQamMp8TKsMXdTc7mNqIMFgcW5BKgRW3a1U0x8JqvC9gROUEiDh/Pod9Fj6PBhsXVkOg8p11a1CFkuJ1UEkBJD6HnX8opeRcB4OnQVOPjb2NUos3PeroDEAx5s7kjcywoJDUG/7mCVbASp6IUBXK4Pp3vs5qgbBnf/e6j5kTjpDcr5WbsXBcqYT+WIbegE7xi9uK//t5jFt128fuBNLvO0J2zTySVFLkkRL7dzuPhEIyIH1FCkkqiTomgHSHVN+PbvSi2m/JHUgbok+/9Spr4EqRLwDvUkttlRSKKVVL7F47+Yh9qkJZujdgRKF7A2FXwujUJQWUABEhO47UIqGmqEVyIO03MNLXoXz+eQZsBpaf5g471NEagclySVJDm8gZlSaGgBGPwcxgXRkme93RfIUNMED0AsmLY8kjUSDrbjsW8NJx1wOlOvQ13JxSLOgplEJthD0cyAxn8LxQRYTUgCHngcIBMA9cCoSm6rMQhqyH58hK40YJKB4bgAr1BJQqlRRhO4UCsYeTo4rzNpUUYOo42mcpz9VcdeqgQZ6BkA/dpW0rCdW7DA9Gcs5pUaW3HIYFGpWSJ8JdRniOljyfk/OMQtRbrvmg2bRRRITmcMVhKPivH33HQnH/U0Ko+OXtghHjNoeSgSkFUq2S/icJ2/VTSIPlkAYH0vDySGFsiLBdAIlC2gDSD7+wQ/VLn1SN1AflHlQLone8xmCNy7ALSNzXVkk9UCJsR12SbPk47VBIVpMkcwPfScwNOO4MSvpeuuNubAIkr0UCSDNGH7g9L2d5Bkb8DOiqbICrsXVKlKKOKIhlDyMzNVQw8rwRoTq3euuqTXVH9KxDHa1SHVJdRItCSowNVdguNvgLZVHbwD3sVTrvLMRVu+/MKCAwdCklb8haW6iBiauNOozHIt8e7cLV+DlgwGzgqijCcwrNmSISiAQh24qDLhQxZCTgPtvAMJSg4FupJ8BUKiZXSb1hu4BqAOlR62tbewVSfY70vGlACywxj2BkoOEmexuZq+4w75/Wb6Gs71fn7Kc9unLPvf0ftrthoawjojbHQCRlcOvnril+KhWBPft3crERlvt/d7gpwVXQrYWBCBh1AgmlFAqpBtL/DgWkPqYGM0gk6uj3curh1kuddsPLI6l+qWVsAEjkkXqBdE1x2+c+YXmlr6mmCkMHhb/vFMDrOb28uj2kSoruDbLl00ooBZJ3bpBKMiiVKqnMJVUKyYpjR5lCUluobGwY8atx/gD7LJx41HauwkL5LBh/qJRRDSTARPdvzA7xGMJ1Z6GOTj2qGJg4yvrdbZEbz7s6KGxH37sybOd5JC3apih8x9lLqnDX7oCSXG+lAy8W9gBTerSi2hJYDq1mkSrPJfwVuaJQRYAFRUTokcXfmswqX8MWHOYm1G3uj+052MDQ4GRQmlqF81wleT6JsF2aR4rzDpUUgGwf088DOJlHjAw4sWicakYGObcmDksdAaPHeK7ouU8s3v6P24sPvPTv1VPuRVbQeqNCUzjnvqVuCeSJfi6L9K+/dVPxb1r0MSmYmlHex+Dzqx8WBeOXjBJIbShZ6K4EksDUFbbrVEgpkG532zf28DaQHEY1lP4N+3dibPhtWa9k9m/ySFUOyeuRIo+E025wIH2yuPUG7xDx9avfXXxe7YcoBH6H5q8LSkOpJHfbKWw35iBtS6ECWYXsqlZCpUqK0J03Xk0UkoDE7322LkQykPJivkfMgEIE21cKSCgkjAmLTj5CAPKcUZgYyBsBo0odlYWwSycRIjrQFFUDSI08Uhm2M7ddhO4EpoCS1Ec475pKqWl06FRKSV4pbNQs7o0RHRMEo8t1u/pZcrtWRXWuCFV0icJzFwkwAAfTAFtxxKC/XzSdreDUAJMrQssvNRRSR9hOcEmhlIInvV2duz4j5gnOiX6DUXNE49RT5dyiG0DX4pje96oSRjjoMC2QqKe7Alf9X9VC++1rP2KuOWqH/lWLOY45QnOYECw/FAAKGMX/+wEpCdv1MzbsLJB6w3UtIFX1SL15pH7GBoAUTjtTSF9SDumLn1JzVoXs5Ly7TYW9t8ra/v3rr7aCWro8UAgMyFGY6RxzeyiVdJJUUnRuAEgRskMhdakkwnaM2BcJIKGMaZy7RyxI+UPs3TMgA8OOVUqcUkOE8iF2nQLJ1FEJo3YhLOqIcB0hPgOStRkKY0MzbIfCcJVUQ6kyBpghwJuvmhlAYTvCW1E4G8WzASXvfUfxaZgdvK4HsDSGFu5UPXG78XM93nJFpYOO98EpR/6HvBDnjAoCQlGPFUe233BFGM1na8Vkakkg4zUGBVLitjMg6fzSlkMpgLgd506ojpwcWxOwMBHuiV51wymAfdVfSxmpyJVOC8CIpqf0mqOwFVVEn7g7VEdk9m3VEKFGCM+R7wEmxa9/5ONXOtpIFVKikgbNI5XW78Rp1x9Iso3jskMhSR1FDVJdEFuDyEJ2KpA1hWRA6s0j0dcOINUqqdv6TU3SHW0gKY8EkH5gQPqYOfC+IQfe9UDptS+yPZtSKNG9IXJH7WNq/yaP1AjZSf0YkBSKJWznKokedxStp0A6sjhTtUgAKbcQ2rvX8j3i0xMewGGHmQGjwjqpoQASRbKDqaMlApK78RxI5whItbFheEBiwW667jqKZgWKyuSgxRgg9UApgROhtyFH+fhw0DVCdAovoooIPQIdCoQxeMSwAuGyaBgw0VqpVksewiOvVAFJwK1CdqWxgc9Tu+3qQtkUQgGgOAJP8lvMF9tK0EYGRySL0ZQjfRvyoYwMdFyguDNgRIHrZ97xWuuuTT3RbZ/fYYYF6ojojvDHH3+vcLOCQnG/vqOGEVBqA6mtknYRSI06JAvZefeGANIfbqNLQ29BbMCIYwApDdt5m6GueqQaSE3rtzvtaHVEB3GMDbdVQPq49cGjVunbao0ElKhVInyHOSSF0mBhO6tHUoiVnWVTIFEgG0Ayx12ZSyJsR+ugUEhs1GfFsQr5zRqdnXZ7xKK8N38ILKZr5JpbrXDdwMQjre4IEFkBbOSOZHboUkcrZYYwIGlxrkJ2Det35Ffc/h0KiYWaUSf+vZ4nanpMHaXmhg4gmckBs4MW6MEGC3j3z72uyFXRdDMecE6oG0wZgIgaLOqxNpR5NNRijDB98BiDknVEZ3fdSYLZqWZ0uES5Jz4j4b/UaVcpvrKLQ1jAAzxxNACVEOIxDEJ1bCuxQedF+xiq/LF5s60ENu90IWzfNhhp229qaLB0f0SLJ+GmL6jI1YtbP2Wq6HfKvwCj/47wHGE4gxFA6oJSqZCGBFJqbOivkIYEErVOJZAqI4MglAIprN8pkDyPNAwgtazfAAnrdzjtbpWxgfqk73/2Y7LAC0jXfsgatH796vfYfNKclZBozH+/sB2KCZVEB/Azjr6vtqM4vArZ+cZ9alisiAVA4neNSoruDWdNOcG2FTEgjTusmKni2OnH75+NDXvzYj7SP/tcOey4CjMgKfQ2f/whtv0EQDIzg/ITqbMuLYRFHZFXwgBBZ+naZRchu6hFIuHvTrQmkHbCbdcBpEohGZRKFx63WyPUVPuIQgEMLPBAg1xRhOeAK2rIzRx0Wi5zaIQuNfjcmDyYJ9RSfPZQSagrU0hSWt1AUh6JeiSdg7sHvVA2oBNHB6l/plByzOFmnR9XyixG7ABrHRmGMDKkMKIFzkdf9UI1Qn2Ntf35wQ2fLG7XgosqAkb/ra4JnieSCvpXAShGBaUyZFeppLsASFYUW7YOahXFEkJshusSGOn8HUZeHNsEUvS1860oukJ2g9UiOZDcaVcD6aPWt489mVBJuO+oU3rnC55ZAQkwDaaSCLNSyDxv/KE9QIo8UqWSFKIFSnRqQEUtUj+7uQIS3RqmHZt72o30NXmvPn9Zvrev0NWXhesEpGWycbMfEjCyjgyxEJuCqjfgw+q9pDQ/WP7IgES4jr2Tmi47c6ApfMUC3QBSh6mhkT9KFZIW774huxJAbeD4/z0sxsIfz/ejckWqLTLjAqpokYfnAEuACAgBn7VKIK+VQqQTOuBm8H9MIAYlzRVQQiXVQDq1KgimbslqkhrGBm8n5Dmx3l53AdXqMxDe0wBuWzW/zeapQxsZcNOxcR7K6N3//GyD0aff9irbZZXtH35447UVjCxPpLyO5YkCRHHsCyTCd2keqZ/1O61FGkIhdQCJxqpp/ijUEeG5GkIerqv/TwuhMo/07QCSGq2a004dG8qu33UtEltedBfHpkAKpx3NWL8jJ6IB6ZPvK3DeUad0zRtfamHRUEmP01bn7RxS/B+nHbVjdP4OU0MopBRItoGfQES4zoCki0nfylwdvwUkLk726gUtf/iRPQPmsBOIcNetVP6IhTaAFGYGmqim4Tq2mMDMcFYrXBf5I4BU1SFZt4Zw2TWBxOLK8PxR0oIHM0M5UDAe3moDqc4j1SAq4aMwmC30PRAKKNWqCHs2wOScUUWAGMgAIQBEbs3HaAtprtI8EdpkACZch+TYQiWRS4rPDuR4/QpIVdiutn4DxzhX8knVKO+vITrDWhThqiNUR+iGbQeGY2R4ZbldxFv+9qnFu1/oMGKfoi9pJ1bMC+w79Bu2bJCd24pUDUaJKgoYcayAlITt2nmkHut3v+LYEkgddUgWsiuBVBXFKoTYtHvXRgbPF0XeqBdIqUqKRqsVkGT/rrt+02QVILn1u92toQtI37ONAz9sBbO3GJDeo51t32H97z726hcWr3nGFaaUBgvb4Yq0jg1jDhKQ6Gen+r5yw740j2RhOwvdjS6BdFy5lbmApOdOPy4DaWSvyHv52esPf0csuGywh5kBEHm4rmn1rsN1UkcTj7BFuxGu63LYtYDEAp32tRs2kJKQXbWI2wLujU5jUa8X8Bo+hMYYATdCdBgpUGuE6MK0QJ6IDhUBopUCtQ3i9oJ1PbRXjX4GlAA1ACPfZrkkAem8+coj6XXJRRmQpMDcuHF6lUdKe9vF+TXPXedcwpjzRs3h+CM06h0ZjrKrYYwMWIb7GRlokIqB4U3Pe7JtoEfO6Nq3OIy+o4WUbSHYfwgYVfkioPOvPy5HC0w7C6Q+pobU9t3VqWEoINXhuoDQV23LicrIIHddqpBiO4potBo7yIb124EkY4P2ZxoekOpaJPZSogErHRzYgfbmj7+n+Kq2VmfbdXahTa3g5yyc0a2SKuv3AU2F1DI2ACTPJTmQKIZePPFohdq9fdC04/aX0rrPwF6+rOWPP1JngKsvu+LXAkuHb3PVAaQwM5Az0aKb9q0bULhunkIL5sTD7t03f9QyNGhBNSBpgQ5Dw3CB5CopIOPHbgg5fNLFPEBkC7uUF+EzziOF0dn6vGv1WYEzsDmLprF0otCwpLK2ZqeJLP8H3MCJx6GSyCcxXxWQpLZqILnTzlSSIEiIEFt5rQDrVknpedq5CkI8jtvMl4XqFE4lb3DmiQdXHRkI93D1HaGhOLJ1BDDC8UWYjp50dOlGGWFg+NGXrrM+dNQX4aT7359h505hNBSUyjzSYAopBVKfwtiu5qrDARLhugpACsmhggBPPZqw8s7f1CP5DrKxpbnvNvt5bUGxs0BSLZK2QXcgfcS2XWeDv5tlm//qR99V3KQt2tmqnU0LaVQ7WB4pOn/POH4/U0g4J+lTR49JvqMx2LzPckm6SEIlG5D0WLYypxZphjqHTztuv+0jdT3K572XzwD5I4CE+qFDAwohXGRhZkAF2CKthbgnXFcBqSt/NDSQuizfsVjHYhwLNZBpqogUUE1FEc9xJUI9ky/uhAfpumAwkiuO/JfBSCE6wnEBouWCD/m0pYRObBxlLZW4DzABJeaEuQkgWR4JhdQDJIXtSpXUdtuln7V9m/2izHAhgEao7izlD1h8PFR3L3NndamjgBG7umJgoOjVtoxQ9wVgxBbhv1ItjsNI20H8vKwtqpRRwIhjP5U0fCD93y+aDVaBX3Rq6AHSj70d0R8J2ZVdGugMUVm+zdBAuA7gOIgsR8SGfA0oBZD8cc08Uu20u/NAktNOc4r1myJZuoJjbCCPFNtWvPdfnmOdwQcL29Fd44xj7lss1IVhmkcy+3cDTLXjDiABL7Yy9+LYA9msLwNpL1/XR+THH5DDjg4NAIm+dMsUsyaRH3kUFtrozNAI15mZYZwl/6nPcYXUBNIF1jaoDSRvRsrVfk+TVdvKITpj1zkkQFLDxaHjIa6AUReIagClizww4r09ZzTRzp98GXkzCoNRP8zBUnJkpzAITTJo5zLKLPH8DChhd69CdiikMmTXyCGlTrsSSKm5Adj0jHIbC8wdWOAZ2wjVKb9FqI6FKq056trnCBi9ZvsV2lDvSrN2v/fFz7VWQJ9TixvaAP1QOSP60QEjil0NRqicThjdjUBqb9BXAalVg2R27xpIFYxsE8AUSk2jQxNIbEVRO+1+IWPDriikKI6trN+V086NDV98/5uLz72b7dCvst8HKimMDO0jln1CsO60098df4NlLol8EmAyOEkxRejOgCQlRbcGapFmjhaQstNuRK7He/1JsymfqSNd6Uc4igW6y8wAsGKbiZnHH1CF6wxIWiwxNJxr9Ue1ocG3n3DLd9qlwYCUGBrM1JAsxLGTbMAkBRK3XSnVOaH65wnISlMEr8GiH266MDBw3gEj8kSE5VBCDiG1bxF0aaG06CRtmlYO7uPny08TkKQocSaGqYEc0jl6zcGAZOFJM3HUdUkBHT9i7NAQOH1OzjAreoTqCNvgwormqf06MlxlexldaY46ujB88vUvsdqYbyi/QdFrDaPvlDCSO64vjFpA6ptDSh12uh3tg8qQnSuknetjV+0WW1q+bevy22T3FpAiXBcwYkda8kO2bbmUUoTt6gJZqSScdvqZ5ZGUN2sASe2RKiDJ0OB7IvVuQVGbGprdGppAel/xNTntMDawVQUXAuSS+F0MFrZjK4rTjmArioOkkryFkIfuPHxHe6gAEyACSg0gqR5tpvbBytuZ7/VL+8icgApIWlwJxaEUzNQglRTqaC05Ff38LEJYLXcdhoZG/qgqiPUODSmQ2pZvFud2/ohF2W3fdaeGflCqIQSYekFUKY9SZdCTDigSTuOcge4afd4URoulgoDQQgFo4YTDLIRJGJPB/wESdnfgHeE6wprkjzpddqGQFCIEwuSR2lACPM2B69DnhvMFRnTyxua7QKG66cftZ9tes9ModS2RL4qjq6PHFW9RfzoKXz/xuhfbhnrAiK3FaQVE3oWedK6MgFFX3qhPyK4CUhmua9chpQ67fvmjRriu3qAv2gb1FMVGuE6W76g/ciAFYBwyv5Wl+3ctlRRAcoNDPD61fnv7IHaODSA1etlZ66D2FhR1P7tOhVRavwHSl7S1Ox3T2aoCGziOx35hO+tpp98rO8iyFQVbiaCIayg5mEIlLZNKB0jkmqhHoxZp9hhqkf4sW79H5pK8d5/18snH7ohw3azRB5li4Eof1xhW73XTaCeEw0zJfakCGqnirqNOp2oX1GloGAxI/Q0NFZAAU6Jwaig1w3d9QRRgK2EECAAibYCwdvfC6Ch98UcZiIAPxcHzx9Vjgf4PkAjbsTUH+SPmra2OolvD+YnLLopjPUyZQEnQCfAEnONI09kKRrJ4sznbIi04M084oJh65L1t22vCO+3cEbuXUvz6huf8lTnqPvSKfyyue9urtc34O2TvvlpbR9xg+xdho7aiV+BR5YdSALVvJzmkXQDSTuWPyi3O//hjdopNimJvry3fOOwifwSAABEDO7eppBJKqCQeB4yqx0slVU47bSz467KfXQAp9kNqNlf9tKzxaaeGfkCS007bdHwjrN+l0+4LAtL16oZx7VteIdX6VAMS8GmH7Pg/HRumCyh03/BckofugFINJg/fAaOlUs0BJMoAsH7TgmjvXtnypx+RM0D+iCt9rvgFJ1NH5q7TVX+79qg3XKeN+8gfleG63oLYVv7I7N6hFAZRRwGTDiABpi4IRVjOVFH5/AiBscgDBWqDGjDSZ8e4QK4I5ROKaJ5ANG/sQdpS2se8cQebQjJ1JIVYqyPVa8kAgitxS6NTg9chbVtAYax3a8DRRwuhVCXV8BGgBcwAFkeH0SSrN6Iin8LHWcBIlfx08u4XqqNh6uufdaV2en168cGXP9821sNRh737p1+53uzdwAibtYXUKhjdCYU0qMOut/4IVRZmBo6VoUGdIRoKqaxBqrYubwNJkCFcR6jO+tMJRr9RGM7g1AZS2VIIZZg+J92Gog2kxvYT1ly1P5C+r1quKI4FSFi/v15av8Npd7163NG9gY7gqNl+QOJ3e/rR9ynmnHiwNczlQgSV5EopUUuE7wgzK6+0pFRItnOsnHbKIWXr94hckffikyZch6sM9bP81KPsit961zXCde6+S8N1Ve+6drhOoaV663LBSPVH1OGwuAIEX5Q9ZMVibDmScrfYpjLqVkcBoy4gdYHI8jDASO2A2jBi76dlgtEShd8I0YUqmjf2YAPRnBMP1IJwoN1GLS06+XDPHWFmKHNHhDQpiK3qjwTmaLDqvez88/PZOYf687tKCgjRsdsHHdB98z+aplL8SmsgMzEIRtE4deLBvcqIBc46MdAwVaG692mn148rVMcur4Tq2MuIbcZRFoTDDEZm706UT98cUvoY3W4rJANSmj9qdmgYXB3VQAoY/XfqsBOUuopif/8Dt3un+SBgRG1RqpIqhWRAKi3i5JFKiFktUqWQ6uaqaVFsvf3EIECyfnberaFdiwSQbpT1my09rnvbK20reFQS4dYuKEXHhtnKBaGSFshx51Cqw3dLyHUKQmFyCCBV1m/bMTjXIu3Fy/vI++grphy3fZUWZjbZWzD+MAvXkQepwnWyM1u4TsopdoWlOwM2aUJ2oY62mpmh1ela6gDzwKAwKsNpljMaTBWZy86VkeeN+uSLyterTQEljHQurozGW47MYKSrS9xzmBXmK0SHCkIRGYjGHKCN0g7Q7QMsbMdjaDiLQkxDda6OytyRlKK3DarVEc1VHcipSqqVkEFIyoni3GoIXoPCSFfP53bkjQBShOre8Y/PsHojkuhf/di7ix8ob8RW4+RcCIHZtuLkfXYFSBWMAFNq+R4KSIObGVBJAaTIH5nluw+QqvyRwGKhOoEIuKB4OIZK6gSSwnhtILntexAgEa6z/ZCiuWoasosGqwmQrimLY2X9NiCVTrvPvP1Vlkd634ufZ+HWLiBx32lqkkseiVqz+fpu0gG8E0r6Ox5AISmcRw4J6zdOO1NIR91n+8hblfIZ77Uz4OpIxZ9aaGP/o+5wncJ5eszSU2R91hejX+4o2uUQqjIYlc1UQxl4uKpURsOEEWrIRzjq+sOotkm7SYBFntodetNh1MCwQYgSyzYwwriA+gkQAaEzx2gROEFDR9QSj2nkjZK6o1BHTTMDBbHq9M0c2Dw4lEIhooBsVBDyDuiAmwGMNgr4q9WyyJTR6FoZkTPqB6OrlCjH4v32f/BQHW2BblINDKG6n3zls1XeiIaptqNrgKURskMJDZI74rHxvAaMBKbOHnZluC4thu1jZvifdrgOlWQhu293KKTSYdfOBWHh1gBKrpLcaWc5JMEYiNV5JAdZKKTBgHSHOlncEfmjG4cA0qfLbg0GpLoWyazf73Gn3ae0ASLbU2BsAD49UNJ95JFmyLwyC5UkVyVmlhpKEb5DJblSAkg0WF1wkhsb6Gc3JQNpr13bR9wHV7hqO7kjs3IrL0JPOgvXyS1Wu+s8XEfOJNx11NqEOrLu1pU6YrvyciFGGWlUi7AW3waMFKarVJFyQl3mhTo8FyByJ93Q4TqHERDsgZE+LzVGASNyRSgiA5EgNNvG/nYEUgsnHGowou6I+iTmi35/GBlw1mGMSMN10VQ1do6l8Da6NXjYDiXk4TuOASGO1BkFjAjTkTNKa42AEfVGnd0Y1BroNdvdVYetmA3ibnj3G4qby1Adrrrf/+AbpkD+T3Cw/YsCLIMCCUC1RjyvC0gd7ro0XNc3d5SooypclxoalPNKi2Ld8h25INxyMiaU9UQYFAxKqCSpp1ohpUDiuS0gSUFGL7swNZBD6uljNywgfaiwbg1JcSzWb7Y5x2n3qTe/wvJIr3/2E7qBJGMDv2/yhWzYh2suQncBpdR9R/huMUDS34w57WRswPo99ej75m0oRtzKvJeesLoEa8tyt3IThqMehyt924ivdNelrYKwOrNNeZc6qhfiUEYOo2beJHJGvidQPwgBIi+EbbvphgZShOowDwCCfspogdxyhOgAkUFo9P7a1MzH7BP2L+aqBoScUsPEoLlaLbchXRkMSModpWYGrz0q668E5oCRK0UPXaYAMghJQfLzbTpGmC4MDIRr6PyMtXswGBGqe7VgFK46tpNgbyN2fL3189dYqI4kPuGw/5U6cRiV4Trg0gbOYP+vYIRSGma4rq86+n5lZohQnR1b+SPv0pAWxaoGqXTYNaGi3V8FXraSAEqoJJx0KZDIO3mor4ZZpZBSIElRNh12hOvK/NGNO8r9kPqE7FKFVALJrd8CUmn9pkCWVkLvfMEzTPFWKknKKFx3NFolbMceV0DpTEGJHYHJJ7WhBIzoZRdACqed9lbKQNpL1/cR97Hp12ZWbgvXHePuOqmfABIL72qApfwShgfCdTweddSoO5KRoQ7VuTJisQ11VCkjmQuiZc5gMOoN0Q2lkFxtmaNO9TyYJVjkcfyh5ujYTZ1RhOkADeqHkBzw0e6axazjyyEooZhSEwPqsOpZJ3VkndBLdbR5thfCbp3LlhN1Di3mAygZkOS0c/DURzbXsyHjh9UZ6VwNRli7BaPY2wgYsTi17d2AyGD09MfaNuQ078RVt0PhoC+qoee3r/2Iru4/Yx286Y5NjsbCagGSgMtgAGr/LJ4Tr9HPXdcohPXN+FJ1lDZSTUN1tTr6rtu9CdnRNqhdFJsAidAc8IkGqYTeDEpSTOSRHEhfF8R89AfS500hperoJzddV5ihwfJHiaHhCzuK2wX72z4XhbFJDsmAlCikq704liarYf3GafeJ17+4+NDLnl8ZGwJKFr4DTGXYDpU0TVCaqRAcBdEplFBDQIjQLscAEsaG2co95VqkEbcs750njDoi/ESCfrnCUbjNCD2l+SNCU6vK2qMI11lH7NJZ1zYymMVZi2wPjJZMtS7XwMicdCigcjQLW1Pw9Lvda/m2Dgzko/T69MTDZs02EsCIfYz4nFi7cdMtVKEhMEIVAaKZx/9ZNfi/mRhw1GFi0ON5nsHI1JFgVPas2yA1mYbqUEfhrqPOqQ0kYJQCCFARTmRgtliv/BZ1Riww6UZ7Q8EIIBGqiy7e2InpCICrjr2N6OBNESnKw3M8paoxoKByytEGT9f/47F2HKY6+kW6M2xt9a5s3mmorqo9itxR3cPOgHS7apBur4ti3b7tdm9CdKgj9jTygUr6ouWR6MwAhBxInnuyPFKZf6oVUi+QGuG6L36q3i32C9cMCqToZ8dGfeyLZAoJIMlp59Zvd9rR6PZvH/WAKmwXUAJGDNx2k0fdy0J31BVF6I6CWVNK6uQQUCJ/5EA6quppl4G0d67vI+5Tq6BT7ro6XLe+DNcFkCiGbYfrZumqnW28U3XUG6pLlFE7byRohDLaeRAFoGqYATU3MXjOKK01IvS4TvVBmDYwa1BnhDmhgpEU0czjddV5nI9ZAtMche8ohHVH3SgzcZBfA0jMRQ2j0uat9/Acmlu9+wEpQncBII70+It80VqdJ52bSVoHjEhoDwdG2Lzf+Jwn2q6kH3nlPxWfUX4CVx2b7f1MXasJ1eGq6wbSTobtKiAlUBvK7l2G6/qpo85QXWVm6ACSlF50aTAgYd0WdH1PI88BUUtETzrCdqgn5mC4QPr51z+nbSeu778PUuSPdhpI7yxuKoF0g2qRrnubnHZveGnxkVe+oHjhlY/oCySUMduKACXqklDOc1RjNE9WcFRQCqUKTFJK0dNuutUi7TMw4haofMJ71wzY9gqon8RdZ4aG6M4Q4TopBBQUOSbyJti9bRFGEaShOpSRRoTpwlVX1RoBIw03KgRchj42t4+o1VHUHJEzik4HbmJQ4avs1zSH5TNiRBjQ+VNnRM7IlJFgNEMgioFKInw3Xz8PGBHeQz02YKTPn7rqeJ8GkFohuxRA5wtAKKcYW2QEoRUQ5gVcUoRiyBXQwyxgxNVxvzAdysj2ONKmbxTAvl81R5/UAveF9725+OanPmT7G1Fz9B9SFQYjQmjmghNMgEiE3CrIDJFLSh8Xz+0J13XVHpVW74azriN3pG0v2lbvqkPDj77lITsUUgUkryfCtIDCsXCdIIQpIQb3YXYgz5QCqcojJQopns9usQ4kdopVuM5aBqX5o9Jh1wdIvkmfOn5fq47f1mDVd479ykcFpKQWya3fL7Mde7HohzJKj6GSTjlYUFIuiRo0ujegkvh7mTf+MGstxIUMAKLvXYTtFkhp00Jo+nF5X6S9a2UfgZ92ZRmuc3ed271RFAAJ5xjdGdrhOup0MDO4OqrDU+Gqq2GUFn96W5zIG7VhZM1Ro0lqcgz1FD9v1x2FKooQHdAjT4USARBsI7FaQAVGuOMWy6aO8gFGwMdApPDHDA0UEhZvYLXwpLItUMBIzw9lVJsYZPzQPNGVoRdIsWW7h+wCPnE8V0BCFW0SyNh6nH1suKqN7gthXjhJIKJgsstNF3kjjmxFjjpiSwMS5HWo7lPWq45F+I8Kg/3fz2VkwP12lwBp6Nqj4aijCkb91FH0sesCEvkjheu8U/cN6kXng1wSsKqBdLM1ZHVDBEDz9kEBtHi+AenLAlJX/mgIhdQDpLJ9EBv1NWuRXq1c38vktPtn26MqBVHcDiChlPnbmHzEvQqZFEwldUEpBRJ/VxgbzPqdN+obgav0XnTKbCbn4To5cxTGoj4HINXhOm3ZrRBVdPamIBSlkKqjNFQXMAp11GViSGHUu5eROneflYyAE/fpdm3zDvNC2QlbIPJGpb6VBPktPgs7vWJhp2s3LjkMCiggg5EgNP3Y+2rcx8AEpGgRVPeoc3s3n90t3qmjzvNGzBUw6gekCkCCDwBCSXIfndDpvMD2EVTXc4XLFS9Xv3ReQBGdpMVnMFXkQHqk5Y3YdO9dL3xWwe6v16kAls7ShOp+qpDTb3X1/5+3f6vsVYdyCSBx7KOQUEE7lTtCbXUBSXmjX9T7Hv1vhzqiFqoK1wGhGFZ3pFBdmBkSQ0N7H6QKKAYkD9f9zHZ6vd6gRC4Js0MKpAj3Aevq+YKWAc0aq97QHa6L/NGuAClpH3QjxbHveb1bv2U+wZ7/vpc8r6+xYbzySITtJimEy98JBgca63IRU0OJWjpySrVCAkjsHsvjci3SXrS4j7SPijqqYCP1QNKebgtc9ROOQiGRK4n8UoTraAeEOnIjQ+Kqq8J0LWUkWLSVUYAodnjlGPc1jyWcEhilIbq2MgKILPoovHU46qQ8lkrlmDKSsgsYGYiOuY8cS4KRoITDroKRwGW1RpoPQnV8/rTeCFjz+gyAtPnMWiGhytL8EfDhfBi457bOPUWPP7lYpzwd3bq92NVddBGeY9HpV2OUqqKXP8kbpwKjd77gmdbJ+1Nq1vmlD77NCmB/rCv738hZ9gcpCSuAJVRnW0D0AxJwGsTckP7Mbpcw6wnX6fV5n4a7rhmuS511NYwGC9VREJvYvauQnYwJ1jaoVDgyNPxSlm26dEf+hyOhO7aW6AISYTtyUNjCTSFJTUUNUtoyqCqIrYBUWr77hey0jblt0hchOxSSAck36ottKKIWCWX7gZf+XXH+0jk9YbtQSBzpbWcqSbmksIEDG6zgdGVADRmQWsaG2WMOLqYcfZ9s/R5pC/Xecr61OpLr7GRXR1zps9AakCxc5+ooWgWhjthiInJHqCPr06YQGY46yxfJwMBuqJ4zEoyU20lzRgahlbOKh/aMmbpPQ3BKB4ppcGVEmM57vhE2BBLscouqofCVrt0LJhxqRgWU0XQDkeyzR+sKU7exeWNw4DFWayRHHfbugBH1RmzZbsWvAjVAsoJgoGRAioaygrSUWQAojtzHOEcDVbRGoGTb6blaPGwfI4VgWGQIzxGS6dd9oQmjy4ur2OPomX9pexyxA+w1b3yZ1baQN/qhrMmEqf5NPdvo/bZLQOoBUAKryB1xNCB1qSOglKgjhQujiWrlrEvUUaWMpJBMFZXKKHaIdbt3uUssDrvbVINU7YMkIAm+QAc1RKguYMIRQOG+GxJILYUVr+EOuzp/9KMblT+KGqROIPk25umeSLcISDcDpHLn2Ko4VnVidP1mW5APyvo9mLEBIKGeuXihLslUkpQ14Ti6ONBaiL8rTA6VscE6NngLoVyLtLes7iPsc+Ksq9QRZgaFjSz8pAWWBXeD1BGLMI/x2iO115FyYGGt1JFgFJZmlImbF+qtuX1DOcwL04oHywVHyA0IPczG7OJhqzSq/8f9fgwwoZbIGxHm43UAm+WNsHWXewQRFqTolnMBqBT1YmIwe7dCjNi7qScCRigiQHTG0fvabe7jZ1H4ir0bE4PVGyV5o/XT1Y0B1ahBR4YAUhWykzIKSFdqSPMDhJgzVBHuRbYbJ75PceNpygNEeA5FxGLzuAvW9exn1AYR/zcTg5TRm577JGucSrgHC/Et6iz9vc9eba46kvxhZLCODJVCEigivBbqpgJMCp3Bbg+hjkwhDSdc9z0P10WYjmNXqC7MDD/8ZmvbcrduW8duAQnoAKRQR3RXcCDdYO475sRNDTebQ+8PttPs/2fvPaCtKq+27VfsLfbejZ1iofcivaoIiiACIkVAUcRCUaRZUFQQLIAoYsWuqNhjjWJNjFFj15iY1/R35BtJvmT+9zWfNddee59zkOR/v8TgcYxn7MOpey/Pea513/Oe83m7pJDKgETCbs31Iz+cby2AFBO/AVIcZe5Ayo+hWOSHJq68/nK7+rxxVRQStSR+P8K2K1NJqiUR6U5QklJSIzcqyRtmlbIrjRDaVopq41qF9B+2V38nni61FfqKgA2gofjP6abYdX3CrvPeI+LgO1kHbdQe9RawSrZUmkCQYFQ3jQMSHOj/KVl0gpGAAlgcRoLQyDWsEV0qgKSvrU4d+QF2+jnAaJBgRHSa5+XnGgmknqjzePd2rn5QQdSKymG0UYp3Z71GzKjDqsuHphLvFtgIMTA+iVUGpFBHgk06ciMpJCDkS3UinlMffR6z6EjQsVlwV5uHFjIQoYq+KbjgYNL5Rj7F+8Iz7fZLp/qJo6tUDMf2YRoDs+qonWA9USNBdaBKqOOgVpJlh3UXtl2mcHIgAZo1gYiPZTDK1RHfo0Ih/YN2Xa6OqoVRNMOGOiom7EpAItZdBFKM+uERuMk1iwAAQABJREFUxUT0G1vOgSQQcX2ijpRbdhVAiu9RpSEWhfTKmiw7FBJHUJCyS2ci+fgg/T9KQEoH9Xlz7N03+jEUT9680IfgLpwyfo1AylVSlrjj94mAQ4KSmrtl3xEHRyUxgDUaZIEUNafvxAZX+yL/c65AUR1F1NsnLmjjPAp1JCCldF3JrmunQ/iox4Q6iiCDw0hWXQov1AwjlJCDqGsTG1VYI/V2EVChmFJNKUXBy9VRIcTgMKrnQ0uZrM3oHkAb8e7oNaLJlZpRJYxSvFsH7SnM4TAqqKOoG1FDCyA5jKRycoVUDZAAU8CJoahMhqCviOZFNgwPLWyZ7Lm4411bVQSQgNFNM86yWy+eZPdcNTNN8RaMXn94hSsj6kY+q04bLlYX1hjJuv+3QKqAUbF+VG3vUYp657WjQhPsGq26UEey60qRb4CURv84kNQAS0LOrTYl46j7YLcBJOLcZUD6pHogxWBVVFYAqVQ/ipFBawDSS0xqCCBVTPwujg8q9CI9q+G30YuE/RrpuuIjvy+xqDO6SpJ1R+KuHEqaOrIn8+6YCs5xKmmmHYBiwsN/zk5V+0y/E1dAtaOn2XA7Sx3RU4S1xZ088WW36wSkMrtOqqHRbpurtlRSRyninXqN1pSkAywJRgGipgJSrHhfQGkt1FE2gYFEHRahhxikSNJYoJSoo9coh5EroyKM1k/xbqZ3K/4dVh2z+Tj5NY0GKo94lwEJYAt8vSvqR0AIW+5oPaKIAkQ0K7IJMPrHQwvy/7HnsF7WWhUJRMBo0ZSxHu/Gprv7yhk+IZo5aG8IRj/T3TibpteNVKBn+Cgb/t+UanMgCQyukHLbLhQSjwXF4+pnTQqp8Llh91Wqo+qAVG26Ltl1a1ZHWd9RFvXO03UVMMGyS0BS5FsJOYAEiJg5xyNwIT1HnQmFhFVXhFpRIXkoImuKXTsgFUYH/fAJHe/xuJWOMReQni1M/HYglU9riObYp1UDfFQNzffOn1U20y6gFDDid4ffIWpJWL40y9KXBJSoSZLWTEdVJJUElDxpp6MoOGG4Xm30+zuxz/9HvMiuDfacRmKMKDPqqLX6bdjMc7uuYZauy+06Hfp14PYeECCBR7LOgwwtD/bGV8IEHl4os+nSINQEI1l0UkGjuzWtfmVqCZWU23WCWAoylOy66DdKdSPOEEohBp4L6o6Zcp0EWeLdqfF1Kw8rhDJqsKNqRqod0XeU4t3p1Ne8+VUQ40j2PMggu47QB9+XtF7RrgNIXkPSz/VUIlanFr1ZgKijFBFHTcdA1EoQsaF8c5w7QchtOsGImpGPBRKM7p03y6g10OG/WlOjsYQ+efnpTAGkulFYdW7XoZD+ISABnZqgtLZAqr5+lKfrqgszhF1HvDuWz61LVp3DqKCOinZbAAkVREIOIAFowgc88m9m2pE6JJXH1zqQBDZ6kUpAilBE+h4lIP0gHTnBHDvsulivCEasbJZdmmeXgPRhHNLnQFJz7FMP2tsASZH8Nx+5S2nIND7oh/fooL47l3gvEsNwmdB+XIfmNaokB5J+h4oqiSZqbnpcKampmiZYP6rCD/RLI4VI3jWRlVcLpP+Irfq78SS1weZhBkDDKB3vodGGil1H/Sjsui4OrTSZgQ0YFUCkmXrNCa1k00mhUC8CEqWaUQFGggz2HDA6tXuzKov38/GRXVNdCSWVhxm8diQgeZiBsUARYiiHEaECZtR5vDuDEb1GRZsOGBFiAE68n0Qdn5P6jRTxljryupGUIqCOiQwlIKUakocaUEi6FqggQMhjGYjUeBsgol+Eu9iw5thIWGtVKxKEAkY83nDBeA8w3J3ZdBxZQLz7HW1yJOqwqdiUCTFge2HVRaJtrRTSWqmkAoz+4frRR/58Il2X23WFMEPRrstPhXUgZUGGLOqdKxsPJKTINuk5FFIACZBwZhF1HlRSAAmFRMy7BKR3PKkXQIoaVJ7Sk7qK+pGfgZQBqQSlApBefrLGAas+z86nNWTz7KppjuVcpFU3zDMO6zt7cN8agRRKCSDlKklJzYBSgx1VK92FqeDpQL+IgQMkYuENdt5g2ndjt6t9ld/qK9BVMCr1FZUaYVFH2HVRP8Ku6yaFwObMIFU2+9QIm51+miXqUEaAqBjr9iSdFA6KpxxGzR1IYwpgCiA5lPT5rpKAUkEhUT+KVF2awqAD7QqJOsYCxfTu1Pi6tfcU0VuEIqqEkU/vLlh1WJbFIEOMCIpG2O6qSSWFRMKuZNcBJYIguSISiAh9YJ1go3gvUQagABEbCfZLETTf9PZiHbQXyggYMe+Mk19XP6CxQErUffzDJz3SzJ0/G3VYdb7xK8xQUkhRRyLQkK2w2sJ6K4YVqrXu/veBVMWuC2WUp+qqUUdSNaGOUg9SOs8ogMQMOoAEiFAvwIN/Y2dSQ0IRERnnerGIjjuQdA2ZgxdTGiqPnMiB9Go2WLWoklBIVSZ+p+g3ll0JSIwPUvS7CKR7ORfphuxcpHk++mnSycetEUhFlbT/likGTn0SKPE7mKy7dKAfEKIxlhpScz1qWngtkL7VO/V35MmxscYR5KTmiuqIdB1AotfG60eyvzpJMaCiXB2pPkKcmZE8TGGgzyhXRYpil2LdJRihisZ0b25jelQsvY+PlQGpqJJyIKWoNz8HJeaJOv3sGAvElO0u9Xf3mHax8RVbLsGI8SooIw2iJN6tgamMBWqZp+q28yneQDf6jopAIjruQCJhJ/ABJKLbvB0gai0QcZInPSHeS5TVh2LDCHWUn2vzDwAJm44+I2pGBBiAEcVvjpNggjebLZMYfpttsmzuoTySEklAYlxPKdhQANIak3aVtt1awqhYP/oVPUjqPWJlcKxUSDUCKay6PMiQknWhjnIg+ZQFAUlxbgeS6kT0HDmQBAysNOw16kjUhkpAEowy+68KkFSDIqnI9+DrPNAg268EpGTb5SpJ/x8+faW6id9ZsOHZwjy7vDmW8UF3Wt6LtGKp9yI9fuN8NcfOsfnnja0WSNzQhELyx1BJghLJTaCUhxxk3aGSUsAhQQkg1Ua/vyMb/rf5ZXY/bO9pFOc504jaEY2wgIZ0Wl4/0kaLXddd9SM+j8kMPiZICopeGoIMNL8ChhxGUjDEsqPHCJUzWqEFh5FANLZHi2zxdloBI4A0OqshhUryZlmAJMsu1BEwAoAoI4614LwhwhelXiM1vmoKQ9M91WtUCSP1HQEjEnVMYvAJ3jqQDzXl6ihL1hHsIJ1XDqTdszqSJlYAc66fR8qVmtt3G7dFDtYmUGnLhRJi89hHp30GjHjkfWtj2S05/3SHEcNSsXAev+lqn94NjHJlJCWAxcQmjcXlQNJgUqAUG7+DQEAoAWlto9//C0BS3aoIpP8rKMXzCnAGkGq067DpilZdqCO361LkO9ltRSAJJgIJdt0nstF4TEB6OQeSq6Ps+5YDKYUiqiTsMiCVQenV0hEU/AyvI+nnfaxgw8ck7V6MpF0h+l1dc+x9y3WIIkDSQX36//zQtXPs6kmnfSOQ4qbHrTsBiVolUOLmiMMcmQhOspOThtMA1m1dITXaY8vaXqRv82b9XXhu1FnChvOaiWpHwKifFnadjwvK1FH6PKkj2VkU8KkdER4YoMPjSLYBCGw0gBE9RhHrBjI5jHoKRhULtcTHTwVG2Yo6kteQCuooWXVpRl0xUcckCaxHAMLx4w4jwYYjJFwZ7ZApI4dRGpjqdSNZddSN2gjG9F4xl49GWCw7mmFzKAnG2ID5kmXJzyIw0WzvrfSHrj4i6kO6Ow0FBHiAzQEkn7T42D6bqGZUABIf/0Ygqc+IehGDUlfMTYfs0cHPURKvPni714xyZSSLCaVAsZ8NPQEpqaTY+NcOSNUl7UIRVfQdha0XNl/YfqitsAKjBymAlCXsItCQz66Lqd6VYYYq6ihZa5XqKE3q/lEWSEhHT1BDov4DgLhOhAwABXUgGmZTDSkl7CIkUQRSmmOXxg5VUUjVQUnqywMOAEkqCQCmYIPSdjmQsui3LNZ3pGzfznuR7rTX9P+07KA+/b9eed1lUsNXfiOQQinltSRUkn4v/YiK7dbLrTtXSUxwUAycehIjhL4Le17ta/yWXgFZTNOw4fyAPW28DFGlEE9A4dim1I9Kdp2ro/q7qna0g6uFNCYoU0eqHaGOchgJSJU1o4DROIFoXK+WNq4nS29nYMqBlFl2qKlQRwGkNJmhdMge4Qlswn5SRoAzEnWca8S4H2DjUxioGVXAiEQddaOiVYc6YtF7BND4PsAGKDFqCDCxfAaePofp5kfsurGsEN2FUh8SWIp1oXrbb2gopeLan88RjBxaGawCSDXVjVBFN6rh9bZLp9i9mtqNRceJrxxB/sYjK+zdZ1Z6nQI7ieMkiC+zSdNv9P8OSAGmisc1AqmmhF15/1Goo3wyQ9SPAkiV6kjwdauuqI7Ug5QGoyYg0fyaA0kgQq0Aic9f0yglgIS9qa9HdQEkFhFwVFay/NIcO0IQawJSSSlFPakQbhAEP34JIFWeHCsgPSUgVdOLlB/Utyw1x67Qcebx+1LdY8AoHitVklt3+WF+Gytxl+bcASVqSt/Srar2aa3rV6CrrDoiy7nqyZJ1WHD9tTzQoE2+mK4jzEDtCHXkUW99Hsk6rx1l6iivGUnRABKgguKhZuQQEoxOA0ixCkDKgw0opAxIRL49zJBbdVE3yuLdeg5JGWWNr5kyChhRK6ovGHm8W8ooxbs3dasuBRl0pITUEYuoN9FwB1MGJeDEzDvez6ghrD0gV2/7BCEA42oIxaO3AQ13o3VljxRBxNu8j48dsm0dt094u7ipVAckGl5vnnWO3Tl3mg9JZdAmFs7L993is89StPsppcVUM1KajA30/6i+glX3jUCKXqRf1TStIVNIVZJ2FRBaozrKFFKoI/0stwm/+ub6UbLrIuodfUeRrMuaYD+pgJGScgCZ6+Bjg6ghvZtSdmVAEhiAEgEHwgqMDgpVWQ4k9THp6wk+5Am7rIbkKTvUUdmqJgaOSopgg35mOZAe8RsKgMTJsSn6vUIH9d3hJ8dGLxLTGh5ZNNfuunKG9W11RNnvTfF3KEAUj0WVVNW6S8dUEPluphg4UNLcxHbr+t5X+/q+hVcAGEVNiNrR4bts6nHl/jpADruub5Oqdh21I2opceYRYYaw63J1JHAwDqho1SUYtXAQndarlR5ZGZgAkupJHnAQtKKOVFRHMbeOnxF1IyB4HL1GoYz0vLDZAEu1MJJKImEHTJjgTe3I7ToFGbD2WAEmwMPbKKDme39Pn7u5fx1gAyJAB5XjthsQ0kIh4dEfglevhkRf/FsLELHqC2LpMdWvgCUfDzBVB6TbLpmcJi9cP9dokExJutt8HBDK6NNXntF8ujQSyJWRCvIk6v4hIMlCW2Nz7P8vIGVhiQog1Rho+Ca7rqCOmFYORFwdfaRzjDIY+dHjOseIyDfKJ84ySkB61uFAkypqhQAC/Ul8bg6kLDCBYgJqfH2aFF4azIr1B5BilUGJCLivUi0p6kif5ECKpJ3qSPr/SC/ST56o/qA++sqeWp5Ojr1n/mw7voZeJMAUICo+hkoi5cnvGtZdpO6oJaUjKlRrFZQa7b5FLZC+hfv1Ov2UeqKOVIgPdZSSdTu7Vccm74GGLO7dKwsz0HvE53GCadh1HKHARASCDKW6EYNSI1EXyiiDUe9Wdnq2TtNjsu4KQMrqSCgqgBRWnQcZBKMhDE2VNTiw9SEepHCbTpYjkEwwUnF2n2TTsdlj00W824+TULCBY8gTkDa3ZpofB5SKC9VUPIoCsBBOCADlEMqUEABC/TiMCvBxCMnKq8cSiHgupPqAGt+/qX42tuERu3D20kaexKsE0i0XTdId8XQd0Dbfo7/MpaNxkiQdg1LZBPMpA9qMSYf53f1aA0mz7KRU1twcu5YqKbfqpJ6+5mtQRpk6KibsBD8PNNRQP1qzXVehjspglIIMCUbJriNhR20oHR2RWXa6Zlh1qBQWdR4mOORAAkYBJEHOgZQPZq0AElCqCUwBJX1/DzYU0nbAMI0QYlpDBiR6kUjaVUa/71nmNyE+rWHJld4ce2LXtjUqpOqgVJ1KitQdMfDUl7SVW3ZH7L7ZtHV686t9cd++K5CrIxXoUUfEnmnmBEbYdV4/yu06RZx1zAKfx4F2btdpFhvWHnYdgEC5lFt1qdcItUN4AUUUIIrHMiC5SlIEHIWUwYhUHsm6SNUBPcYCuTISCGl8jQBDDiMFC4o1I2DkVp3UEc2vJO1ogG20+6YOpfT2Jv41WHkAA3C4CtLdZhFC/KET3y7acMAqwEMdKeADgFBDySpMQQrUGT+X5wcAU+0q1bkaCUz92zWu0of0wDWXeroqt+gevds48voj3dlTx0hx5Te9fyalw2oGkgcbSNlpEgLBhohbVw8kVE0GFYcLkKnGpiuDUCWIijCqqXaU0nWlMEN2CF+1YYYMRlJFVUMMAaNk1VE7yu062ZgJSMlyQ9EkID3mUAAW5UBSf5OATi2JviRARWIRW4+EXbGG5DAKKPljUkyulopAWl1ZRwogxZDV7CjzQvT7jYfv9J4yTvhFFXNy7KobNK1Bycrzhvb/RiBVgilXSfodLrPudtCkEqkkaklYd4332Ko2afft27LX3WdEkCFFuFODaxr/s4d6iVJAAbvuWMW5i+m6rvVphN3BD4/j3B4GqWLXDVSooGjVxXw61E1VGLUWlLT68Jgsu1whCUgRakjqKB0/4VadAhLRb5Smd+soCWAk5dZRiUBg1LLCpgtllKujDEiokQQeNcfunI6aqL9DUjck4LA5gBB/zG69oXwyBXQwVgf/ziAEfICO/6xMiQUAUWcsfob3Ogl2SRWlEEWaBrG116yoVxHAqAQSPUZPqpD9rOwaZtJxgBv1Iu7o2RjZJNl4vZlTSuFPqqWwUZcU0rtlNaQAEpt/EUjlvUgV0e8yKAGoDExljwVwuSIqgkhg+1XAKEXM/1aDMvrrz8th5BMZCDMQZKjWpsOiq7TpMmXkVl1SR9R/fMqCakBYm8CCtBsKhZWAlFl2uobAKAFJjbH6/tSWCERg6zmQ3lCooQxCmUpaE5CoIWUKibpVqiFVWHYVCgkgRS/S8yvUHKsQC0eZP7DwErvi7FNrBFLeSqDf4Sq2nX7HuanCugNK/vus1B0x8OhLarxXLZDW3d3/W/bK6Dny017VT4Rdl9TRFm7B0UuEQvL6UYVdxzET2GLYdYzEQR0NkFVHPWdYh/KId00wGi8QxSoHUktXUQ6kojpSHYo+pqgbMaOOA/+AEX1TebS7ACOAkEOCsUCZQnL7Lnu7wY6agBwqSH+goXy85iPYFBWQ/8FWByF9DweOQEecnMP8UGCooFiuxrAHGUm0lxpvpYoIRHitSuGJUpovTXIoAolE3aOyZ15Uiu71lXcofXW/W3TAiGkDPndNKTKmEQSQYsJA9UDKot9SSHkvUtaQCiBqVkmZUqoCpgKEUFA1gMhhFBadrMFQZaWYd/kQ1eg5chhlYCiHUUWAQeGFCDBEiCHVjTIYoY6UOmTKQpyFlAPp+QQkIuBlNaQAoODO946EXZVAQxFKglxZLSnU0auF6DehBnqRCim7D3QkSAxYLdaQqk5rWJpNa+Ao80tt/qTqz0VyVUS4JltrVElRT5LNzAQHRgrRl0Q96Vu2bdU+nXX1CnBaKjFvwgzUhOgnQmn4UFRt9th13n+U2XU+mUHgIszQQ18LkJhcDbzo/ylZdelMo2phlIOojQMJlYRdF8EGj30XakcxJgirrgqMmiQYAUfvM5KyoBZDnxEwKrPKBB3Aw/uw03wRINAdIvUeFE68z2Ek8OQAKtSCciWUQehwqZ4Ujkhqqwge4NOEpdBEUxpuBaIWqmm1KoQmSPKR3EPZseh1Yrp4EUgM0Xzl/lu8XkSzKwVxLLp0TMKbroyolbBh1ggkbax5yi56kYpAKth2VVSSBxCyMEL0EOXQCQBVfLwstJDViaqBEOqsrPn1i+wU2DVEu4GtBxeyWHd5eCFUUYQYCjBSGAF1lHqIkuVGLBuFxJlELK5tdUDi5wG5CDTkdt3raUpDsusqQCQwfaEYeR791g1EZf2o2sbYZwqx78fSgFVuRFY/cKuFZffMrSgkgHSJXT35dL+RorZJoAbwxAoY8VgtkPgaVJJWbt2h9jXnLg1e3bI22LCuAuDb9Lqw6mL8T66OtJkT30Z5RP3IpzNko4IYJ4Q6Qo0wGod0HeqIAaoRZAAcEe92m06JORJ0gCcU0fg+beyMowJIqZ6UoFS9OooQAwqMXiOeH88LZZTDSJt8JYyAT3EFcA7CotAfoNd7gA0w0mMxiBDgwcJjYcUdKggdJustINRI4AM6TVXzabJHCTxJAcmOUyCihZRQS4fQVtZawGznMXLFyQuqKBpuvelWtTmAFFO+OfOGmgHxXyw67qjZDNkYsY+ojWDVrRlIin0LSJ60A0YBJNlirpAy2w6lklRLqKQUcCDkkIIHhB6S5ZZSeCmNxxlK6XPS5xVDCny/UEBV4JPZcmVKSLPp3CYr2HJVa0RJCZUCCwUIEVzw9YYrRxQN18qVETCS3RbHRlD/If3GNf3g+Ud9VQFS9jwAPdc66keMYor+o2KQwetFDqIs/o06Wl1VGQHBUpiB2lHWFCsY5eooO8b8TfWWxcTvl+5Z5rYtfWec/nufFNKKK6Yn602/00ApYOQAKiikSihRRyoGHIqpOyaC++BVzV2sTdp9m3budfC5YNVxuB6Kh0U/ESOCmNIAiBi7E3YdlljqPUqDVKkddc/UEbWj4xRkiCZYGlXXDCMgFDCqCiRqSIwNiqg36oi60TCFJCphRN3L03QHZBMYtPmjTkIZAZRc9ehtVA9R7NwrL4AIIAWAEnj0x5iBB/vtCIUbXAURgnAIad6dVE+zvRgzlMDDY4KP+piYEM4cPK02glBbHd3RTtf3SF07rh+jiJIqSpMfmI9XXEx5AEjUB16+d7mnrT7QEQUeSVYx3WGktFgCUnUKKZ1ymoINKSWWA4l+pAxIpTpSaYQQ0IhFIf/3Ul2//1AhASmE37z/lv3ix6/YLzTr7bPXX7APdJTFT2V1vfPcY/b+S5p08JrUwluqrbytTV/W2G/1+X+grkNNS9/rz1+kn41Si5pQ1GiSFVdDQKEsvl2AT9SGFOUmPYd1mQBUDiFqPqgieoew6rA5YwYd1xQwAASgBJCYcYfV542xsuqIk6M++RkcTYFdFzBC/eQKCPj4iibY6hSRakb6eT6dIT92ImbYZRMa1H/0Y92AYNVROwJGoY6eW7HUnr71ent82UJXSPfpd+SOy6fl1jI3WkUoeV9cAUpFWBWBVFUlUUvSmUm7Kniz+6a1wYZ1kAPfmpfUSzAivp0sOGbR7aAaxvZJHbXUceOukEjXpYkHvbMeJWpMBAd6SB0R9fYgg/p/hggYZTDqpjRdFWWUQJSUUcAoBRqihkQCj2QdQQZP1QGjIxOMYiQQgCQVmJRRNptOMCKcQD2oCCFUD7ZbNKfydqTgPPXmIQSpnzLls4FDJ8CD8nH40KdE7SdXPSXwlMFH4AHuAAg11F4n6BKP76Rrx0GHnKWUJj2kEUS8juJCfaKQ5kwcY6/JpuHYCCZ1R4qOO30K82y+RSBhJ4Vlx0aKxZSAVEOwoQCliFb/6dN37dfvvSmovGQfvvyM/VSgefbeW+2+GxbY9Redb1dfeK4tvvRCW3blRbbokml2xZQJdvmk8Xo80z92zczJ/nlL9DlLL5uhz5ttty+4zO5drEGgN6pvZrlmsN2mhNhdy+zFB+6wVx+913789Ep7/4XH7dNXdRaRfu7Xqu/8huCB22vJYmPahKscvZ+PheLh0T9GXUjqx5e+HhXkCwA5hDRVQSDCigM2YbdR58FC+1A/nyPEgRKTuAEO1zbsz1BHXHu+B8oKVeTwEdBiJFCy40qBhXyqt4ILpVpRzK0rRryTRed9R1JFP1qVbLoIMjx/1432xPLrbOWSeXaPBqrevXCOPXj9FXaf3l4xb7bdMfdC9SI1TT1s+h3HfuN3HvjwNo/8OxRSDiW9zz+PxwrrLh3mp5qoEneH1wLpW7N3r3NPBKsupi1QO2KTxEqinpROd03qKKYz+GRvwQu7jrv7bhoeWqodSR0RZFDyjUQdEClOYfBId6FmVA6jzKrLmmIDRsS8cxhlymiQoIdqI+kHRFETKAzSaU00KJW0HMomhxH2WxZI4A8yakHACAsPAKUQQh1XPw2JYBeUD/UeVz8V8OE6tdmPJej42sbVTwDI4aPn1UHTK1gdaRzOQERU3vu8GFqbQYiBtGkp4ai3idHzMU7yvHLyGW7dYO1gD3FnTjG+BKTXtWm+4XfyWHZrBaSw7VBJWlh3f5D6+fqnr9t7LzxpLz98lz1++1K745q5Nn/aOXb+qUNsoiLFEwYfq8fj7EydvTN+0NF2+gl9fJ12Qm87bUBa447vZWn1tLHHxeph4wb0sjNP7GtnDzvOJo0YaFNGD7YLxgy1C08bbjNOH2Ezzxhp0/U275s88kR/G8jNO3+iLZh+rl03e6rdNHemrdBzWnnTNQLaEnsGoN1/m7326D32oycftJ8++4h98KJG/7wiZSKw/Vx1Ha4ZKgj4BIAioh3qBqCgiEjX/UzfIwGJYzoEJAEfwBMU4dqGOuJ7BYxyAOl78P8pVhl8pIJQXt5f9IOVmsIgS04JOoIpbyq2/6puOl7R4Yk/uHOpPXzjArv7msts+RUzbdGsyXb1BWfp92C8zTl7jM3WdZp5+ik2fdzJdvGEUXb1+RNsgT6+fM4FdpsU0gkdmyfLWb/3tCl4TSizpnmbBXT8MQMRMHIQYfNlb/vn6uv4HkwDb7CT5j7uskltsGGdI8G34AXRAMv066gdda2nmLTu4KlnMBiVTX9AVj9iHlzRruOICdQRdl0MUuV4B0/WVQJJthtjgRxIqh0V60fpfYUQAyODXBmlYyaqgxGKDRhxgi0H5JFII6FGdJo0G2GFqAN5LUh3idhz3oWut4ETsCrWgBrumiDkCsgDB5vJcgvbjeBBUkCtvy/bTRBK0EmKh/AH8EkrwQeVCYB8HSwQSQl1Eey71d/V1Sgqk5oX5ycVV1e9Jpa/r95uxrHqbASMiGGDTMro5QxIqwWkV6WQpJJUG6keSDUFG7Du0rgd7LLfqR7ynjbxp1Yss1vmX2qomxnjRwgag3LgAB6gM37gUb74N2/7+wUiADT2+J425rjudmq/7jb62K42qm8XG3lMZxt5dCcbwTqqo53S58h8Ddfbw3t38MX7+Ty+bkz/7v69+N5nCHr8HL4/wOPtMwcfY+cIaueePEDgGuQAm6nne+nZY+3y88Y7vG66fKbdt3iePbPiJvsJ4Q+pny8EqCqW2urMShNIUv1olafbAkhAh+tLzYiFGkVxOYxeS8NYUa2luHYKRPD1PxVwXlez8osa5fTU7UvsoaVX212CzM1zZ9h1Myf5jcZFZ46y8045wa8jr5XXzHU83V8rr72Prmc3O0XX7qRurey4dg2tf9vDffVrkx5P7NJSoD/GFk47y5ZdPMUGdmrhdjV1UP4W/CYsgxNv87cQfxMBoRxIGayKUHJrW18fJ8setvMm7b4FW1jtU1iXrkBvwaj3ETqzB8XjMW8NHd3ne94Ey6YPkJJdl6YzRO9RNMJyLpIDSWGGvjqinKZUwgwnH6lpDEWFJCClUUACTzaJoQSiwuw6gQhlVKwZ8X2oGdH0ijJidFGCEQptR4cnTaRMNaC+g/XmECqoIh/boz9CV0T642ygUAI1IWpBRRA1cxAp+ebBgwKAMiWECsJ6S7abTs0tQqcIH0ESAHVmCUIkFrtJ8fQQaLjexwimvAY/mkIKj+MwurH0NsuhlIEKu47NgLoBd9xYRNQ9kkJKQMKqKgOSNs2SQqoKJOo3Kf6doASYfitL6u1nHrG7rr/SZunuG/WCaplzzmluw7HJXyWVMldKjU1/hu7OWbPPHG0XTRjtX3Oh7tZRNagowDHy6C52cq/2NqR7KzuxSwsb1Lm5DerUTJulVsemvk7IHuPfxUc+d1AnfY2+7kSWvsfgri19U2ZjTqu1vn8bG9qjrQ3r2c5/HmADfsAQgPJ8eB1PCghMsAAcgMePe9A1BSYlFQOM0rEPASSUFPZf1KMcRlJNHhFXVNsVleCTItol1YPieUzjnJZcfL5ddu44XauRNnXUYJs4pH+CznE9HL48X67T0B5t/PVxTfq1OcyOan6I9Wl6sNZB1rvJgdar8QH54t99mh1iRzeva31bNhCcVK8VsM7Wa1084xwb1KWV4MFREumwSa+Lamiq36gBKMGFvwf+HQrKJ84X1JODCqWUvY8jKpJKok+vFkjrEgv+7a+lZ6O9p6WD9agdpZg31hNDQvtKHTHyJ4BUtOuAFxssm3HXQ/W1hXRdOu8o1Y9O6dRIVlsanApkCCjEfLp4TI2v5VO9q4VR2zSBgefBc+6qzZokWis9X6YaMOqHJlPsN49o64+Nu0APLeiPqe62+kPEnhOI6D0qpuJQREUQef0nVFAWPsghJCXE63YQoXoy8JTDJwGIa4TiBPSAqNdhe3gYhDqcvw7sxkwlcZgf8XoUE9MlAkocY8HYIOw6UnUAiQJ8EUhslGsNpKgjqSgfUOKR+tIf3ap7zT5XOOHd51bZW088aG88fr+9vupeX69pc33tEdZdvl7h+AOtF+652Z5V6u/JW663RzXYdeWSq7yecS/1jPkX2a1SAjddcr4tmnmeLcRymnS6XXrWaJt52sl2wakn2WQpAzZRlMGY/j0cJEMFFu74j2/fyI5pWd+OblHPN91jWzWwY1sf5ps1CuG4dkeoVtJI9lSTHHAOrwxcDirB6uRe7VxJ3blgjh/jQFSeOX8ABPjEAkDR90OCMYD05Ztp6gUgogaFMoo0HrWmd/X9GOvjx0Po/xO1npcUPlk0e7Lszb4OVJ5jKJt+eg199Vp4XQEdANOz0f7Wo6Gauo+Q+j9cv+eH7Z0/prf39c85Sl/HtRnUuYWDGPgCNJTmqcd2s4VTz7BJuqYEenTKq0+c5+3kHjBMuDShpIFuzPjbyKGUwScsvVw96f38PaVakr6+9vTYf/sevs48Aaw6ho6SrAt1RKGd5kyPeUsZFYHkvUcKD3gST5srd/1YZV1VPyLuTaCBqPeJbXU0udQMgYYAEqEEBxJQ6gl8sknemRriY76kooARvUpFmy7NppMyKsJIz9WPj8jmvdF8igVXnJrgdoT+gHgff3BEtQFR1IdK1tzmeQy7mIDDusyVkH5eEUKhfJL6SQACPhxOiCUHhFCRCUR7GvYciojXgOLkEXXai+sPlLTytwNKUkzYdWwe8xQWoLCN5UQRnoJ8KKRqgVRWQyooJIGHhJiHG/RI2MFrIupZwor6nQIMbLrUWz5d/Yx9qPTXe9q039ZsvLf081954DY/0uJpwWfV0vm2ctEV3vdy97xZmjZ+od2i4y+WzT7Pbpx5ji2dMdFuuPAsWzztTFt0wRl2/fln2HVTx9u1U063a7QWTj7NFqiB82qthZOzf+t9HDC3QP+ed944u+KcMXaZ4HXxGaf4AmLTVVs6f9SJdt7wAXaWalnYeGzIp/TpmKmjjlJmnf39Z53Uz87V512g2tdy1Z2oy9C/w7y/t1bd7XPhONIBmDBNm1pOrPdU33Eg6SaAGhF1pEjTEVpAFQE1JmQQwy72BT2nn7PqpgWC73jVz3r480LZ9RdAj219qEOoV+MD5S7opqThfq5uBkoJApSxsipPV51touy384b1tynDj7fpo0+0i8YNsTlnDLcrJ46yhZPG2EKdDHvtZK7dOFt84QRbPH2izdO1u0Qq7PoLJ9pk2ZkJSAwM3tSh5C6CbnAa7sY4rDQSK3r0Akp+E6e/Gx4rocS/ARcqqd6OG0xbZzbE2hfy77sCutNqx4mv+bHjAgz1IAr0RXUUQCLuHaOCeh3OqbBpgkNnLCYHkk6P1QZbdsSEgETc2wMNAo2f/hrg4dHfVzoJNsYCASO+LppeHUZSamzgftKrNvr2Uih+sJ4CBsyaI4wQHjnje9wb1x8OCqmulBKgwp7DmmusyQihiKgPRT+Qg4gUHAm4LIRQqYQCQqF8EoBKEOpegFBPqRwUESDiOvcVzAGRX1M9HqOeKf4fcJQ6ICqDk64pagkbr5nsuqgfsfGlCPJLDiTu1Ikv11RDKvYhRcrOG0hpIs0W7081EaXYsmkFX8qeAnw0hVJoZzzNc3cs8TFFDy+aa/cCn8svsFsunqRjL862m2acpbOYJtjSaWfYkqmn2+Kp42zRlLHGMerXaV173ql2zbmjfS3Uo69z0uM12cf4nOtY2mivn6yvnTLOrptymq9rBSk23uv0va/Vuk5gu/6CM+2GGfrZOozw5osn222XXeBAvF1QvPVy1nS7ec40u0WPd86fbQ/fMM+eZBL6iqVG3w5NxasfuNVtUNTMW1J/P37sXikcLb1m4ARsCB9g51FzAkrJonvKrw2f86Zi2FyfH+p70hvGTMGn9HM4vRVYL5k1yS6beKpdKCV4LiEOwWXqyIE2Y8wQu+j0YTbnzFNs7lkjbc744TZ77BC7dLwCCqcN1Rpml/Jx/fsyQWiuPu/KCSO0TrGrJo60+WePtKt1DRecq2ur67VI1+UG/T/gRmCJ7LplGro7+WSAxPgrJscrGaq/F+xfevOwuJmbyJR63IWUSC0pJf6G/O+oCKUIOeh93jheC6R/3ya+Lv3kXo2+/zR365Gs426ejRhriI0Sm46NMzZPYMBRE/H5btdJHXVpoLqTLAWaYQkzMLeOQAPTE+gVGim4oHj82AgBKB6BUbztj/qcGJgKjFBXQztoUKpsOp5DOYxU46LhNTvuoQijAFFqcE0WHaEFepGqU0MAOPqBCCWQgiuqoEobrooCAkAVEEogkiISULheRwtGwBwYUf8aKBVJDYxBtQCpuICTT8oQxABSl/q7a6DlZv7H/7IGaHLnTo8Md+kM+wRIqJkEpGLsu4b6kdRRKCMsOqLLpMYCSDSHsul+rP4hlAGqgTt/frZvtup1eerma7TRKt12/eX24LVz/Pyle7XhcwbPMp3JdLMAcRPqSIu3OUadj9GoyefdPmeqMYNviTbP61BJ543xjXXumapVaQNGBbAuPX2ozT3jZG3Ew22+NmCAtUgb72KBivOfOJCQ03GX+iY80X/WcgFyOXCac37+8zjSm8MKVwlIQIIjGp7R6wCwL959o085AE6cqPu6wARgABOvPQFplQMp0nPUmbD3UFUoogCRQ+jG+f6z+JkcAXG7km43CQw3zjpX8Jxoi6USF0oNzj/nVAfJlQLRlWeNsCsEGqAzZ/wwQekkmzVGS4/pOgyzy/Wxq/R5V589yq7R9fLXD4D0+v0a6EaAmwFuDJbr/8Htc6boGky1q/RzHEg7M61bTdpKn5JC5cgUHgET0+wJAvlU+axnD9hwMxfBB0/Z6QYv6kn822277etMW5f2xdrX8m+4AkS8mYINkDzlpTv5jqqFtNQvKPWYUDoDMyCxkVb2HrFR0zcDkAg0kMY7vmUcUZ6OmWAK9yjFtQFSLA7XSwBK1ly8v9hjxERwQhHMpQNGqDM2dqBJgAGbLp09lBpesRlcFemuDRABJSw6VBGBBUDk43lcDX3PVWAJQvQDlUPIVZDUImm4khJKNlwRPlhx1N2InAeE6OPimvZRaAFVxDUGRscJQKhHJkoAe7+e+n8AlHxlYAqVFHUlTqM9XKfNXiHbh7twNsiwjlKwIQHJi+3vakrDe9GHVAQS/UepBylm2QElBxJ2HUCSvUePDf07fK/i1GqPS2tYKE2kJMv4+FeC4UdSDe9pY35T9ZInbl2U1i2L7KEbF6rHaJ4tVbpt6eWzbMmcGd6ntGD6JJs37Vy76oKz7Xpi25fPsFuumGUPLr7KlcsPbl9sHJ0BLFgcMvjwoisEFtmAF5+X1Nf54109XYeCAk7ZprxUc/1umq5k2cyz/fh2zocCfCuklu6ZN9Pu1/RrIMHsPyYZANUf3Ha9Q/ale27SQYbLXS0BGBpPARLqh1oSthyjfFBJH+pYcepK1IkImJB69Ocq0AE9AM3PQz3emqlHVAvP83rUntTfgnNGOVwAroNH8LlYAL5MMLpa4EVJAl4/AXj6BD94kddyt6D+0HWXOVSfvuVav1aAlMXNAqBdpdrdfQsu8ufAdZt/7lgPNBwGkPR7xN8NIOJvKKCEYgJK6UiVzXOlFBNKvA6rv6mw7jx1x98Z7sN269U2x/4b9vB15kfKqvO6EfaR23XchavwTnyZuySmLLBhsnk6kPR2Ukf7+eeXwgwq5iuOTKCBuHf/5krjCR6D2tQXTFL9KPqPgA3LlRJAUj3JQZS9n1Nf83qRwyiNAgplRM0qYNQqgxH2giuj7E4uvG5gBKCw5xrvvrGDKLfkFNPOgwkBIQHOe4IKSbiw4UjEeR2ooIACPgCop+w4LLkEoQKIMlXENabudryAijKKo9QBLDU6II4aZXGD4PW8Qk0JhdRK4ZJD1RlPoOH1lXe6aiHtlRQSwYYSkFKoQT1IAguKp5SwqwqjaI4tzX9LagnFxAJWpO6iOfbPn7/v4AJYH2sSw7valJ+8/QZbPu8Su3zq2TbihH7Wp1N7mzJupE04eZAN6NzazlVB/Zwh/bT6exLvtCGq94w4yfbcdSfbavNNbdONNrKNN9rQNtpoA+vUSmdbnaC+Jn38litm22M3LbRnblssFXOD0QCKkmHTTRvvtX4IIXB58JpL/SwowHO7alds3Hdcdr4DgTOi7p0/SzC6SNMtANJlfjQDp6oyYufZ2xclIAkqAAngo5Cw7lA/9AahEoFQRLm9liYYAa6AEdO1+d73SRHdJQhwhDwK8EYBcokUDPYltiUqD7vtcik+lN/VstyuPW+0Kz5Uzs2CKc+f5333VTOlsGb5VI4H9b2fFECfWKap7hm0gdDrD9/hC4C+tSpNb+B1cI0eF3SZ6LFA9SQSdgCJPrbGeyQgceNZgpIOmBSUsPAIBwEtnBLqltjgBIT4uyoCCSgxUkjQmrbObI61L+RffwVoXo1jx9noaYKlsZXhnq33287VEcc3JCCp8VTqKIUZMjWV1ZraH6RIs+wk1NHRCjOkQ/jqKpYdDbHpWPJRgk0lkICRv092XoQXfC6dpi8M0dezcQOjfrIJHUbefKs0nSZ2cxfXSNZDbtPpDyXUUcNd9X7Zc40EKxRRSsqFJRdKSD1BUnbJissUkIAMhAgihAKKMEKooEoAVUIIBXdUBiLi3NibXDeuHzCKEUeujvS6UKG+MihVB6TOur7NZa2wMTx7x2JP2DFeBiDR3FmKfq921VJK2dUEpFKQgUP6SNZFyg74RFNsDDXlkfcBNqzBj374lD16y2JbMGuqjRjYz3p1bGeNNaJp/PFdrUejLW1QRzVPt97aBrTdxo5vs431b7W1Hd1sKxXsv2cd621hrQ/c3Lo307Dd3p3s6tnTbOaks+2SiWNt6y03t/Xr1LE6Wjtvv63ttN221r19Kxvar7ddO2uKPSLFBZTYbF0RqJeHRwaKrtbjS3erIVYff06b9XOKdD8l4DwhxQIoVmULVfTEsgWuIlAXz+l6osaw2/heqJ03ZE0SGilZdY86iHy2nCLiwIl5cgCAr4maGsrofgHvLlmSAGX57HO8nnbDBamWdq0sNmpmKB9qaliOS2Q5AiEUHQAjjEAQ4fhu7a1towbW+oj6Nvr4o6xd48Osa+tm1kXA7t1BkB81xBbOmGT3LbrKnrlTz/++Wz2YsVrPH5hiO/KaOIYCS/XaqeO9fuRAkkLC/kUhUSfmxGOsb1ZSS8nG4+Oplw8ored2sQOJqQ0CERMdOLKCGHgtkP71e/g68xOx6o7RRslmGeqIjZk6Cv5xxLy9zqFNNOwyLKf4fBQDG/qRdXd1u66noqlsrMyuY4yP9x+p/oPioX4EcIpAOrV7AlSAKMILMZfORwFlqgy7K5peadLlmHCKr6SGom+CPxSARNSb9BzjfFBENK0W1RCWJK+1aMNVJuGw3xw8ufrZ09VPET7YcW7JuS1XghDP1UEkpcP1QlUCH64l1wQgAXnAHTDibCne5rqjmCoVUkdd4yayUk5RH8+LuotnoyTynYD0YlJJhaSdT2t4r9gYWxobhOLJ7TrBqHT8RGmGXQw5RRUBKKy8r/T9337mYbvz2itt4qhh1rhBPau35wbqITrUjm1zgLU4aBM7ZI8NbR9Bc58d1reDd9vQmh2wifVo/D2BaTsb1H57G9BmezummSBzxNbWoa4OR9xrU2t+RD27dfnN9pO337bHH7zfzlCf0FVTz7IN1q9D93++9ttrdxvQq6tvwo9pTA4gWP1ACiOgaABJ8ZG3XxGwABQLFfOCHoFPPKK2CDVUsekeTzYdlhxhDu9T0vVOVp2ShplV5+pIX4/lB+jY+KmNhU23bOZE1bUUuFC9aLHqXFhvsaLecxPpQwUyzh42wDo1a2h199zaJpzQy46Qrdyp0cHWtVUTmz93jq16+CG7+7Zb7IEVt9tty5fZhIFH2f66JocfouHFvbvZVbJAARPtADFsFSD9QJbnI4vmumJjGCqKB8sOIKGG2qheyt8UN3mcE4ZaylcGqDSUON388XdWhJEDSYA6pLaGtM7w4V/6QrDquAundsHGSWMmqoC5aj6HTb+EbI5hKxXtupjMEDPuOkgddayns5KUBEuTvQ8UvJI6GtrhcA8zjKgGSEkVpWPH3aJTjSmSdGzYKDM2cS/4y7pCvREr5w8Hj5s0XSWMaIJ1VaQRPyTmgGse05byA0TUhFItqDyKneo+Yb0l+PRWgjCgk2pBCmxI+cRCBfmiPqTFtSyCCFVEveiEDEaEO4YKSIQzCH1g03GdgREz/8qApP8/faRgSdz10LVtr9feUFOVZynmzEbM3TkJrzIgeT9SybZjnh11JIaAxrTvZMElGy5Zddl0BqmfGKjqk7X1bxQTvUi/VI3onR88ajdeeYldcOYYO+j7e9vYkcPt0w/fM/vr/7GXXnjO9ti2jm250Xq2UZ3/krr5L1tvvQSS9QSUzfX+gwSnnk22tsFH7mQndthJiklH2zeSUnUobWYD+h1jj63S8NIPPrAvvvjCnnjofhuvqPOYQf2sznrr5VACUAfss6eNH3qCrbxhvl+LXC0BKC1AlBaASpDi36TouHZAKsHsVn8fHwMsbOKuipSqC4sOEDFvjpQhi7cj3s3Gz9cCO1QIQQlqU3dfNcOtQqy6mxUqADg3qf5zoxZwKq5rp4y3Uf172V477WCND5Qyb7iVGls1pqvRVtaxvqaBHCRof1+Ddls0sfvuvcd++tN37KOPPrKPP/7Y12MP3ONW6IF77Wbbb72VDet3lGpz50hF3iTVuDx7bteq/iYgyf47XI4BgQZi3wEkFBKTTRxKgKkMTglS6X3b6sjyLV0pOZQydbSvHrHJ622/fm0N6V+6k68jPwyrjs0y1E5YdUxkoNbCx31Ct1QOMGIRZuBrIvyQZtztIotPkwcUR+6hpj02WL4upetKYQYHkqCEEnKVlD0CIlQRkxcqYcQmXi2M9AdRjHbzh3HI1uv5RIZQRYz0QRHlCblMDeVWHP1AmQKK4EGAp0+mdsJ2S8AReDLoAJ58ZQA6prFsOQEEtck15TqhirhmXDvADoxQftiQJ7SWBZkpooBRFSBxo6CfxWJ6Q5sDdvBR/5doRhkbK8kuAg2/0JlHv3wrU0h5g6xsOx9AmqY1UEcqAUk9SIQaPimdFhtTvhkXhBoCVCiir1Uj+lA1okdvXWJXTZ9sQ487xqZNGGd3LltsZn8x+9tf7K9/+bP9RevNN990CAEgoFHd2nrTOtau/vdsSKdd7OQuu9kJbXe2o5rINq2/rR2mu/V5V1xuP/6RLMH//m/75S9/6WB66uEH7MKxJ1f5fjtuu7X16djWbp93kasd1I8vKQLsO6DDdWIlOCUFBXjSutNtLSLeJOkAEeEEwguuijRfDjUEhGh4Bf4+107/diCp8fVH6lvi+6O4SNU9qhABtRoCB9SuCFMsv0gxdI/CC0pKvRG2YC1RL9al40+RIjpCwP0v23qzjWyP7epIZW4mIG1r/VtrkHHz7dQEq1mIB+uY8AN2sVHDh9lrr71qn332mf385z+3L7/80q8Tbz+18gEb3ber7bqjIN+8sV00cZzdetVsrzdxivDDUm7UtJhy0Ug3NrggjVUfoo2glex5V0lAycEkCy/AlD0CLIYrs3AnqCUBISw7gESoof5OG9QCaR1hxL/sZdAAG5MBUDv0EWFfUWPxM3tUlwEsWEpYTFh1Ndl19Cp1OGQXBxLNsDmQWtfz+tFQhRKIewOdEpRk3wlEASM/crxwymtu00kxYFsxsJXp120EGIqsDdU3FAEGYNRAh4Qx6JQoN6oIe84nZ9cEoTx4QPqtXOHkoAno6OeH/QZ0cvAAnwoAAaEAEUGFiHWjhoARaUEegRMDalFDSR3pxF19vgNK3yNCDd6TpOeBQiIw0mLfbVSQ3tBWKllFoTqAxBy78mBDqUG2ZNulOhJ9SBxUVwRSXjfyGlI6gpsQBOm511bd5zCaPvE0a9FQE9V7trPhfZqUwejPf/6zxdp9992rgKMSTJtJLbWtpzv5LnvYKV33tIHtdrOjmurgx0O2sy5tmtuTjz/mQPr9739vv/nNb/ztt998w667YIIdImVW/H6EIJodWtfuWnBpHt1+7s4l3lvkFp3g5FZcpppeewgY3en1oVT8v9vtLQeRGn2TKnrE7bkAEdDnGn+pYaxAifcDJCL3UT/i/wfhCK8fLbjYgYRlF4EGgLRMKinWItVyzlHIY9/ddpZ63NCBBJQ2kLJEZR62zyZ2TIvtdW12tn6tdpJaUhN2g52tSd19bemSxQL15/brX//avv76a38MeL+++hW7cMQAG3p0d2txeH07Z8RgW3LRFKX9LvOgBUBi2gXKiMh36j9SDUlAYhBxAMfVUganABEfT2uHNLR4n60dSth1BBw8PLTLhrVA+pft5OvAD8KqY8Njw2Tz5K4f1UCqjmMT2NQJJrBhErMGSsDIrTNtoGzCbOKk65hAcKQssA6HpPqRByQ0u84VUgakYZpfB3CIfCcoAab09imdpYr0sdiok01HgCFNEgeW1IwSjLbLYFRK0yVllBJ0RLlRRdhzwLVMCel7pARcJN9KaicstvwxlE4AJ3tE9VSugA9K6DiWFA/XleBCWHS8JlQR6o/Xyb9JH3KCbjmMKuw6gRC7LqmjPa3tgTu6XTdFEwZIk3HHT/9LbJa5bSeFRES7rB/pvagjpQP6ciAV6kioJSAFsIh7f6HN99l7b7NbFlxunVq3sB4KLByxtzbJ5t+zWUqD2d+TMgoQxWPz5s3LgFGER/HtbTerY0e12NlG99zXRnTbRxuv/t803sWafn9rW3L9dfbBzzRh/A9/MKD0u9/9zjddVNPKmxfZsL4985+BGttoww1ssDbgR73RVT1Fss6o5xAyeOGuFFQASlwzgPTGwys8OYfdlhTRgw6iiHRTl/t8dWp6TdeVaeAvOfS53ukoinIgAUFXIbLFiJRj2d15+TQH0nL1XhFWiIUymjriBNt/z91sw4oaGdcoLM6G39/Mjmu7i53UcXc7vvWumlu3q7VXzfbYPj3sZ++/56DmmvzqV7+yr776ytUkyumNV1fbVROG25Cjulrnlk189uASjWiirrVi7jQbnAEJ640ztQjKoIraavKIQwkwZSsAFCcV+6OSqEwLofZ06E7rey2JRm2AxM3iOrBN1r6Ef8UV6HjY7u2ABnfubJ7AhTpQStWpS1u/TEj4fs1SDYgajqsjWWdV7bo9rAs1J/0SB5B6qxmWYaoJSFnCjr3SxtsAABbNSURBVI1YC0sOAOX2nP4dmzQNryUYqelVzw0lgiWIAuMOjTSdjzMh5SNrABgxi46RPyTo6CNigjYg8kSc7Lg0FSFBKK/zaKMPlVMJmOr+HaonHvsL4gDIIYQKYul6sgJEYdFhzQGjsCN5e6CuaVVlpJsDYO/qSJao/r+EOqL/iDBDM92N0tBILwtpMeofP9PEgCpAykYIfSOQiHMLQL54W4v0HJPB33v+cXvqruV2w9zZdpLqER1aKtXV6CDr2XBLbYxb20md97G///Uv9peCMgJIf/rTn3JQsLGuabHpHqK79GFd9rExvfe34V3USN16byntne2MMSPtheeetf/5n/+xP/7xjw4koMRi83320ZV2+knH598fIG2/1ZZ2xpDjvScHMGCf5c2uqu8EkPIJDAosEAphfh3RbQ8tCPCony80qTspzjQfkBmBNB3HYX0xIqiokIDfExoLRJ2GSPk9imkDpNR7pCkJAhK1JHqQZpw62JrWP8g20fOu6RolC6+OdT5iezu56942rPPeCoOortlIDeuN6tpD99/ndh0g4pqwqLt9/vnnbue9KSihlPbcWWdsNW/oib3lmvaNajtRs+6w65rJdos0XWvZcPS4JSglMLWVRcwKGPmJxbLn45wuPp+/ywO2XM+DRPQpHaYarqy7dnpdtf/VXoE1XwFqPGx8AReCDGz49PKE5YX9Rg9Rro4EI+72ufNnw/Z0nY8KSoNX2+kXNhJ2BBoCSCdIWZ2k4j2WHUBCCaWVAHWyLDrORwoYRbQbGB0tGAFK0nvAKGw6IqfeKS7fusEOdayJQg3UvBjrw/w4ItkoIYIIeSOqFGCEDLy+07RU3wmwFCHTX8dpxPtD8fDai+t4eqwyFcS1SSvV2bA43aLTa0cROYClDrkGROBzq06vM9l0ya4DUnm6TkBKDbFSr7oO1I4oQp896Ci3gogrE+llEy0HkuaqVVFIMfFbNSTZcGWjgzIQUSv6g5QRTa7v6RC6H6682+5beo1NGT/a+nbvZC0PP0TBg81kq33PBnfQESQttrLHZauFKorHa665psYNVr+ZVT62xUZ1rHeL3WxMn4Ps1F4H2dCOgnGzPa394QfYygfus/8RjH7729/mSgCLig0Ye+ruRVeXKaVtttQR2nUPVGx8jCfduEbEuenTwboDSCTwPLQgZfQTt+fSXDpCC4xf4ggKRiQxF5B+LmpwsQA8sXo+zmQMvobhqfQocXNQCST6hqghoY7oJ2JaAsGGuRNGWt9ObdVzVTOM4loBpQN23dRO7Li3je61v53cWdButbduDva3qZPOsV/+4hdu2QWQAkYRdlh+9eU2+9QTbZstNrPhx3S3WacPdyAN1sTvIpCoFaGIaN0AMgCoCCLe5zAiTSv3gT2DwyI5m6v1/vQrbpGaz1VTImR00Pa1QFrzTlz70f9yq0534AEXVAKRbU/VSboTZGCOFSonNbSmMANWXZldpw0euw71QlKtzQE7Ckg6VC5L2AWQBsqyI97shfyAkjZlNmlAxAmvfIxNuggjbDqmW3NcesCIPiMO1ovRJYftlGpGzJojNUdcuwQh9UFVqKBQN9hqrmhc2UjVCCylfye1A3h4H8CJ1z5AIQ1fFfCJsAejfwDRiXrNKL1UL0pz+0IR8j4gTZy70qqjdtRXz40m5HJ1tLc2ANlYe31PtaMNPKFF1z9NkfTIYC19SahBm2TVUEPMtCsASdMXgA9qqKiMeB+TGb7UseIfvfKMvfjgClsw+wI7dfDxNnb0SGvf8EApl82tf8utBI3t7MhDN7NNN1zPpk+fbu+884795Cc/sbFjx1YBTmysNT2iklrV3cFG9z7YTj+6no3srjBM2/2sXd2d7NZlN9ovvvx5XiMBRgGkEpTm27Bje+U/dxf1LA3VxnvHlTPzkUDMkSPeDTSAODZdCi1oJl0WWkDx/JxgiMYvOYhUO/NjOwRoIM3b1NP4GNeZGXYfSU0xJSNCDc/LsgOCRKsj1ED9CFUUiyGyo47tbudPnZo/55quDe8HSEC7V7PdbOxRBzu0hxypGmNLHTmhpuPPPv3E4fwLgYlwA3Yd65NPPvH03eqXXrB5Z51iA7u2s+O6tNXsvCE+oJaBrgGklvtu43YdNz0oH8CToJQe+XcRRhx6yd8mk/U5GgUwYfcdpJtEnAtqu7UKSf/3av+r+Qp0brD7NKy6Yi0IqBypXzYPMmSBAPzk47TpEioo1o5CUbHR5/UjQYA7JWobACmOm0hAUvOnvgcKiSnfQwWfBKESiKIXxwMMqqn0FwQCRp2kdhxGinbjSdNTRG8RSboILlDzIr5NVJvnFJFrVJzXdgRft9W00TtkAIzAUlI05W87fDLw8Dkl2CTlU/p3gg8AcgjpdQLUwW00kUIwinoRIIrQBq8dxVnVqlOoQTCqVEfYdb0UEOmiP/hWslJQR2epL4eNjc2Ou342Qs7tiUBDOZAU+9ZYHzZRmmNT7DvqRwlG3odEDamwPuME1R+9bI/feZNdOPF0e/KJx+20U0fbkY0O1A3HFrKMttFd+vbWeL+Nvfiu37i12ljX9Hn19Ts3ouchNqHfYTa2d30b1kk9N4fvYctuWGQf/uxnDiGCDZVAiprJoinjZH0pFFBnPT2nOtamYQMNUL1A9aSrvOmVa0XyjiQc07wZksrEbkIJyZ571iGDLcf1AkApIv8jtzCxMfk3UGJGIOoJVcrNAEk8RgpRmyqGGvh/RHggBs2ikm6UOjpz0NF28D57rPU1Iza/gV5XS0F73NF1Be36NrKbpp90qGsdmjawN5S2+1LpugASll0RSD/T9bttwVybPeZEG9Sjo09GZ1r64K4oJKXrZNklIBFWAEg7u0oKCKXHkkUHjABQFykjjkPxifTaR0jZorCAEjeNtc2xNe/FtR/RFcCqwypiUwUu2G6uQFR3IcjQWNYXjXIMRaU3BstpoGLJbMxs1CiGY2V1RdwbW6yrgMQcubYH0hS7mx83EZadz7DT90D9lFRSUkRYdLxvTcqonX65ffKwYMQx4j47SykeDsjzepHDaGe35wJE1MMiORgqh9fK4jWUIJNGIKFq0lozcAI8SQGlcT8BIK7TSSxUEeORBJ7hHVOdLFKE1Mn4eN4Ay7X0lUDkMEIdCaCV6qi9NohQRwzPpB7BSBo2P6Z8c2dfDqRqAg30IeWR7x87gIh0lxphdTqsot4p7v2e/eb9t+zFlffYyocestdWv2JjRp5iRzbUeTxHaPJCu20FpB2srhpfuXtH4awJNmvzsf132dyG9zjEJh7f0M445nCppPoq3u9tS6+/xn723ns5kCJNhj0FjFhEnX/8xmt2qSZhb6Kk2saywRrsv68OvBvl8WvqSFhpDIIlWcc1Q9UAI4IJXDsszq9lzTmICgoyQJ2CHmnY7G90LVFJKFJg5sNmNVIIKxBbMMW+r/RQA+GB6EHiRuLqc8dYwwP3/YevF0BqIGiPOaqendXvcEFbNz1dGliXpvXs2aefUs3oM1dJKCSuRxFI9HO9rP6wBQqh9Ovc1mbr5NzF08+2k7q29nFA3IDSBEuyDlV0pICTVBJKKa2oF9H/lwNJ6gggcaI00/Y5xRh4Ndo9WXeaJP507cZbewWqvQIpVbd/bosBFuw2JlkzHihqR0wAYHP0qHcWZgjLiroO44VS/UhTp7HrCDToewCkzvV1t6Q7+j5AQd8jZtgBHTbjgFKoosGc8ipVgWILZRQz8fjFZnSJH66nBE/MzaLhtbki3fQWUS/i8wGkg0jPjToQNR8HUEHpnKABr4C4CJaisjkxUzrx8Rw2mfJJ/5YCArAFAOWvS3AdRvOvwDOCwwc7p14rgESYgdfM6+S6VLew6oq1o1BHHMJHb8gRu21qEwb0sBumneEJqVW682eqAHfnP1cEmU21XB0R+S6po7jjT3Hvt72/CBgBIJpf//rzD4yRQH/75Uf2t68+Nvvvz+yvX31iX3/2ob3y8g9t5PCh1mL/LR1IJ7bfTr1DO/r0BYC0NsD5ps/Zf5ctbESv+nbewCZ2dv/GNq734XZsy/1syTVXC0jvqlj/VVmdhPpRbL6ffvqpsZ5aeb9NOvl423xjNXwevJ/PyXvo+rkKNVznoEAdUeshhMDJsMAEqFAXQvmggrAxy0CtXizvx9K1Ak7YmmnYrAbJytqjHwmwYf8RlPDxPPp5/P9BIREe8PqRYESgYUCXNv/U9UL5HbzHljbm6EPtnAGNBG1NPel+uHVvXteeWPWIfaLmWK4H6gggcT2oIaGO3n//fbdTGeA6ZsDRtlgHAy6/9PxcIZGSa6lxQagbUnMoJAeS4BMgikdg1VH2sSskt+tUrxWQaMsgDcppxnx9gx03UqR881ogVbsbf8ffqekJ0xjl45utIMNmTZCBsAATDJI62lgTsDf0SQveCKtNt2jXUUvB+mLjdyAJBKTY0gBWAUl3Ul1VPwogUahnSgPA4aRYh1L7BCU2cTb1SO+hZAAd8+nwpGMKQ1OpNk6xjHFApMuYHhEwom8qQOT2nJ5fChpkNpwAEBabw4f6TgYYrLWAiz/q3zmEAE4G0eoeseQcroKM18YEojiWHYtuVBeNReqaJk/wb+pkxVRdtUASSF0d6TpEso4m2Ha6rk1lqVA7umTcSW7X3TNvlk+8Xv3AbX53Xm39SJts8fgJUnOpITZTRxmM/gKMBCLGA/0dEP3qUxOFzH79udlvvvD1xy8+sDmTz8yBNKjddkrD7WSH7b2xZs397wCp7t5b2+g+h9mUE1vYeQOa2fijG2n+3QF2w7UL7OMPP7CvBCDUURTuARIbb2y+AaXrJ51qJ/XuYu01623elDM9Ao5d90OdXEuQAXAQAkFVAnDCClhxDqJP3zEag2NKRQyQ5ZHZfYAJKKXgByrpZbftiN2juDjUjxoVP4+J5Ax4TUBK9aPFOqfpn1WT6wtIdffa2k7re4RNGtjMJvZvIpXU0HrpdNgnVj1sH2tiA5Yd1wMocT0+/PDDMiDx2t/X3D2i6Q/ouZ03pK/XkAAS8+si0JAUUoJSgCgeHUiy68Kyox2DWi9AcucE10V/w3x+c/Uzfse33tqXX90VwIJDgTgEtCmziRNkoP6C/UUTLDUZCpwU2ym6AxE286g3ATE2feo7UT/ie6BSWuiXub3umrrr5wAkemt8qKq+D5MaBul75VCqhJG+LxYbkr+HLEDsgLYqjnI6LXWj+rLqUEcOIykjnjNz5wJGASKglmpDQKiG+o6eB9fgpLZJsa0JNgBnSLts8Xa2GPeDLecgkjUHiFBF6QTcpIo4vymd4dTYU3W89pjG8E0wirOQeul60ARbVEcM3sT24SgDNj3uyJk4XWbXyXoqHWFeOr486iG5AmDj1SbLZguMUEb2q0+kjApA+rWA5EtwEqCIgHc7bEtNVdhOjaw6tLHuFiq2r/dPb7L6Xc3VQkvVI8b3a2LThrS2KQNb2oS+OtK7zUF20+JrVR/5wq25bwISRfwnH7zXT00d2FODWs8/y4MfKEkmMjCpO2CEuqGuhuKhIRilyLUIOP/fX3yk68L60JcPlBW8UZVcQ66nn577pmw7JfM4qpwD/Kgj+bSGm6/xiQhYdpGsG9qzg1ucxde9tm9vpD6lZtrkzzyuiU0d3FLQbq5aUhPr1fJQe+6ZpxRs+DRXjACJaxFAevfdd10hUTP7oVKGXA/m7E0e1k8qZlOvIZGwo36ERQd0EpTKFRI3ig6kTCGRrkMRMX2ev1+sZnobObuLAyT53d2vNvpd3Zb83X0f6qi37l7YfFEAbNyMxmGUDkEG1BF9R6gjZHsk61AUDqSsfsTXAQ6/C4qGWA807KSvU+IqS9gRmogpDQOoz+j7lFRSAkLYdCn6rKZcPT+sN+pZRE05fwk4ktSphBEABEaEFvK0nKAWtSFXQpkKcsVTAaBQN7nCqYQN4YsaFkEFggnUiEogKtWKUEWndkvHaDCfL6w6AiJuyVVj13nPEddVrydgRNS7m47vYGZd0723cnU04fgePveMs2wo1HOXyx05d+cBpNLREyW7zmfYSR0xccGTdeo5wpIKJRAb8N9++bH9vQikrxOEXCmhlljZ+56992abMqSL9Wm2ne269fr/9CYbm/FmSpD1aXWAnTeolc04ub1dMLiNgNRUkwSa2KKF8+y3CjOEMqJmxNuhBooKiU2YegkDSy8cO8wWazIBE7+5TvQZffji426xUS/CogMsXIcilFGJf5dV6UvXg39zbQATnwe4uH7Ye0y/cNtOautDJfWKth0NuUwUZ2YcQDprYG/bapM6/7Si3GLj9a1b033tHMF6+tC2NlXXavwxzazvkc28AfYXsuvCwiT2jV1XBNILj62UKnzaRykxkJfzkabo1FhGB9FOwd9+VSCVq6QAVcdMISUgpToS7gZAYo8ASmmqyK6C0vbTvru7b+0rr3IFmLYAZAAScCDmTd2nje6IqB010R0SjabUZjrVUye4Nk9XR4QZ9HVRP3Ig6RctAg30ByWAaDrw/mq6q5eOLPdAgzZeNmF+LmqrCKUijOiF4peYomi5VbeFrLoN/CC9eprphU2X0nSCkcAFjCKSXQmisOEiZBAASsomWWzJZmOenNJ+GXz87Rw2AZ3iY+qbQg0RWEARRYIuJpdzfAYn3vLIx/g5XAMShwGkskf+eDMYASSuHWdIkayrVEeLp45zdcRstMeWzvd+GjZZrKcqM+xk16Xjyyui3hoVhOWUakfJmvprQSGxCecqSTUkt+6w73yVgJQg9YU9rxlxV04ebxttUD7wVL+EufL5prexsA7aYxsb3quhzRrRyS7WmjG0vZ15TFObfNoIu0/TrEnXBYQAEQsVEAt7ChgFkO5bssBuFIw4noI+Iw7RSxadVJEgAkyACtZcyarM1CEKkdfui7c/dVAHlPgaV0lSVkCNRllqeBxFwbihsO0InHDYH2cuoWp7NN7Wvr/TRrbJP3mt9tpxCwH6ULvw5A42+5Qj7cKT2tppRzW1C88Zb2++tto+V8yb6wGMuA4MXQXO1JBQSO88r2keep5Yis+vuEG/Q1fZ+acMcCAxNohQA9MYqN1SAwr4RD0p3kf9KAFpV/Uf6dwzuSTdsqQdN5YACReAmyudIqDvswtQaldlY6p9x3fvChDzZsNjU2ajpgZEMq6DpHmlOmq42yY+SNWnc+tzi3YdUAJIlYEGgOTe84ExVDUdWc6mSx2KlF0llICT23/6nCTvdcieZD9jgfiDwM/mkL36Oyg2KqvOYSR4MgYoh1E1isitOL3OMgChaGIJNiV1I9AILL6AkEMmWW8JOJVvA6AShMpAhCoSgDhccGyPFn7qLYCi4dfrRllvUQ4l4OSrACOdG1VSR+oLq0YdYdcxnBO7DnWEBcWIG6LHZf1Hqmt87UAKu64UX0YRMBqoGGYoqgM23VRHqticqwAps/KyGhPK6dHbbrTBfbquNYj01+ifu9VmG1rfdvXs/GGdbO64nnb5qd1s9skdFWpobPMvnWVvva6ItepFKKOAEY/FXhuUABswqoANGDVAz9FnanBFIbLiYELSctSCeN0lm7ICuihBXyUwcV2w8Fwl6ev5PoQbCESgUD95+UmfKZifGHvPMk/2EW5YOHmcnaBZdB0P29a227zOP2RxAuyNN6hjnbTBTzyhrc0Z090uG93VZg7tYKN6NrFbly6yt3/0pteM4prEdYhAw+pnHncYYSm+IsvueSUOmfKxcPJp7kQ4kBQg8lDDgQCpZNsFmOIx1BE1JBQSyTpsO+pIqCT2CMoD3GwepRssDuok8PTd233/ta/4/wMAAP//wNrTVQAAQABJREFU7L0HtJXVFbVtbFETo7H3GksUUJqAKCIoithL7C2JSeyx94i9F+yACAgqXXrvvffeO1xAmnTL+uez9rvf855zLyb/+MY3xqfCGHucey/3nn72s+dcc6+9007/j/+rfsohdeuUPdZuqlbKbq1exm6o+me7osJxdv4pB1u1P/3RzjxmbzvjyD2t/OG7W9lDd7WKR/7Orqlyot149ql28zml7MazTrEbGPq76zX+ov+76ow/2eXlj7VLyh5lF5U53Gqdeoid9af97JyTDrYLyhxldcoeY5dVON6uqnSi/eXMk+1a/d11VU+x67keXS/XfZ1+xu1wXZfpuuqcfpSu51A796QDrepx++p+7GmnHbyLnbrfTlbxiD11X/fz+3yxfu9q/Q33hft2E/dTj+2Wc0r747vt3NPsdkaN0+2vGn+rWTYZ5ezv5+XGHeeXt5JHhYKfV7B/1MqNf15Q0Rj/uuAM+9eFZ9idtSvZXRp3X1TF7qnDONMHP//7+eX0HJb254DnonBcWekEY1yhx3NFRT2nFY/X83acXVr+OH8Ozzv1MD2v++u12dMeur6O1X/iTmvy/EPW9t0XrMdn9Wxwq89sQvc2NndoL1s6bpAtGz/Elk8YakWThtvKySNs1ZRR9s200bZm+hhbO3OcrZs1wb6dM9E2zJ1sm+ZPtc0Lp9mWRTNs6+KZtm3JLPtu6Wz7ftkc+2H5XPtx+Tz7sWi+2QqNlQuSsdBsVRyLzL5hLA5jtS7j4OcrFli3rxrbO08/ZPqI/OTYa/dd7Nxyx9sTt9ay9x+62j5++Cr74P5L7ZW/nW/3/+U8++id123N6tW2dOlSKyoqsuXLl/tYsmSJLVy40Mf8+fNtzpw5NnfuXB/Tpk2zScPDc7Jx3hR/jDw+Huc2Hq8G3/NY/THyuLKPJz4uv9TjWaWxUr+j54O/4W957rhuntdvpo7y537hqH42e3APm9q3o43v1tpGdfzChrVtav2/bGCfvfiY3VD9ULupxuFW/vi9bd+9dradd/7NTz43PHe/0eA5KnvCoXb3VWfZ2/dfbh8+eIW9d98l9uJfz7d7r7/IunVoZ/P12OPzweWsWbP8uZg+fbqNHtDblo4dZJN6tvP3zIj2zW1Qi0+tp95Hnzzzb6t41O/sjKN+b2fqs1fthAOsuj6H5558sNU85ZASx3n6rJ7v4zCrVeowu6D04XZhmSOsdpkj7eKyR+v9fLxdU/lEu7bKyXa13uO8p8879XC9nw+o+//4lLnj7v3ffAYABG+M2wQjJu1r9OYAItVP3N/OOm4fq3TUXprw97DyhwlIh+xi1U8+xOEBwBg/BSTgUFvXdZ7gVuWYfazaiQc5kC4SkC4VkK7W7V6jN+S1Z/45gZKgJogEsJ2kCfoEu1wTMG9g3tA1/nywnS3wVNKH4/RDdrXSB+yk+7S7g/M8/d/Fpx3pAOPvAdFN1U7NAxEACiNAKAAoC54CsNSqmMLmn/o6wsYv874P8HEAXVjJ7mQAoosq50B08Zl2r4+q/nMgdluN0/zxAh1gdGXe2A6M9HxcIkBfoA/2OScdpElibytz0C720HV17NNn7rNmLz1mbeu9YL2bfqjJ7kub3r+zLRzZT0AanAJpxXaAtD4B0sYIpAUFQFoiIGWg9INDaV6YsAWYAKZCIGWgtJ1JHLDNGt7P2jX60J658/a8CXifvXa3GuVPsMduvsDqP3mTNXv2Fvv86RuswUNXWt1batirTz1kg/v1thVFAULLli0zBlDKAgkYRSAxEU8d1MuKJg5zGG+cN9m2Ch7fJdAFJg6jZQJvkR4foIkwilDNXqZQAkgL7Af9DX+/dfEMB/v62RNt9bQxfnuLRw+wucN62Yz+XTT5f21ju7S0UR0EpXaf+yJiXNdW9vUnr9tTt19qZbQY3Pu3OztwNAfkPS/Z74HWn48+0G6rU9neeeAaa/LMzdbkyeutvqBU99bz7cPXX7DhgwbY/PnzUiBFQE8aO9oWjBtmRVqozNP94v3CIgYgDWzR0O9T/f88qPcZQPqdA+nsE/bXew8gHeSfyUIoAaMUSIKRA6mUgKTPcG1BicUln+urK5+guYTP/8m+8LrwtKM0vxzM49zx79f4DNQ45bC6F5c7NlEOZex6vTEuK3eM1fzzQT7JV0nUUYXDf2vlDt1NENjNzi99pIBxSlBHqBlUDUMQuE5//xdB5ipW8po0ARJvQtRW5QRItfT3F50egHSVA+mkoJL0t6giBm9QVk2soi7V/akt0NREsemDwH0qJziWOfA3gtFudvbx++r+Hmx1TjvCrtTv8xiyqsgVESAqUEKon59SNsDFR6J00u/jz1E/GfgEJVTZYVMcRFXt3kuq2n0ad0slATTuD0rw6sonZUAUIJRTRgJyVhkl6qi2ntcafz7Eqhy7r51+6O6pOmr0n/vty1eftC4N3nJ1NLZLK59gFo8Z4KtfFBITTxZIq10hjbV1UkjrZ0+wDXMm+ao+p5CmB4WUVUkZKKGUjEnb1VIJUEI5+GReCCZ9z/+hPJjwUVlSFwAAFfbdkpk2c2gfa1v/bfv641et1ZsPW/s37raOr/3T2rxwmybbK+3Zf1xtn77/lhUtW2qLFy9yCKGSABFjwYIFPgFzGZXR1FFDXS3yuFGFPGZUDGowVYIJmFwJogCjOnIILZHSiyNRfVkg6XHEx4DK2iyof6vndM2Msa5Kl44dbAtG9LVZg7rblD4dbEKPNg6l0Z2+sqFtmuh1a+TAWjZ+sKvVrxu9b3Xv/qvU0i722113tt0En100dt9lZ9tjt51t/713tyqljrH7rq1hHz9+i7V59U5r/+o/rfXztwnaV9lL995sbZs3ttkzZ9iiRYts0tgxNm/GNFs0YYSrNqCMMuI+zZFymyblNqFbGxuZKCSUdvv3X3Z1BJCqHLuPOZBOPFDw2D6QsuoIINVKgIRKukif50s1P7Dg5LPOZ/4vVU7SQus4q4nqP+GAfr/G+fhX/5hZkfCGYNJG7WB1XajVDeqoalRHssYqyK4DSBVkjWG13XAWdl1pB1FJQAIMgK3O6UfahXozArhKR//BzpZCCkA62iU6qoAJ+Rq9Gd26031xGAlUVxZYdVgEZ+o+cR9Ol1V3iqy6M4/9g5174gGC3mFuEQLECCPsRx5XtOVcDSU2HCCKiieCJlU1KJvaAosGkElBk/ws/h/QiQM7Lh2JLedqyCF0lt1/6VmC0VmukO4UyP6u+xGtupwqEoD1AXWLDhifkYWRwOwwkg2qBcT5+nDL2rDyR+xlpQ7c2a26+k/eZU1feFjq6MXUrpvYQzbN8D62ZMxAV0jLC4CEjRSB5JOzFFIekFBICwUkqQe3sJiok8kapfRDnn23PaUk2Dh4IoAKLyOQ8qEEDBxMS4ETNtoMWWDTbZPgsXhkH9le3W1IxxY2d9xwWzh1gs2dONYmDhtk82ZOt7macOdOn2qzp062KSOH+OS7dMoYWZQjfRKOFqUDeG4AMODgcUYouTXp6kigdKhGyzHCKF7q5ymQ9NgcSPP9vmP/bdbzhwXK84tFymuwaFR/mzOkpy8WJvduL0XS1u071NJwKaVJvb42lNTKycNdWUUbdfqQXtaxaX1rXb+eNXjlGXvg1mvs6X/daO88+ndr8frD1qv+szaw0XM28NPn9PVL1qX+aza5bydbMnGkrZkz1dYKigyeByxb7FuUM/dn3rDegmS3FEijEiD1bFwcSG6/63NXXQod1yKrkM47JaOOsOwShZS17QDSJYltB4hwRYAS73kcm3Okkir/6YDqv/oJ+tf0BJxX6oi6rEhu8Ym7jKsbFE2Nkw9M1VG+XberVTluP61kTg71IwEMZVQIpGskw1Mg6Y0HkLDsKh29t1Y+B0phyUc+XUAS2JiMUUlZKHndSBMy9RKsOhQW1sBZx/9Rq7S9BMZEHemSGhfXzf3GagRG2VqRqyLVhWItyEEUazxR4TiAcvYaCsZHhEz8voTLWA/yy4wlF9RQANH9l56dACln1d0qUMYPYFYN8YGMI6eMAoyw6VhVpladns/TDt7NrTpqR6ijYNe9aH2afWRjtOKOdt32gMQEGYFUokIqANK2xQmQNNG6dSdYAKUfsba2p5RQPyiMYlDKgijCKKgk1BYqAyhx/dxWgNJMhwaQBCCoONTNBkGFSRvArJs53ifdNdPH+mTO41s9VYNLV4OhXpbak7LrcmowAa8rwGjX/Q9AQjmhAnmMerw/SlV5HUnPU6wjcd+4/aKJw23J2IG+UIgAAErUbib2CGDCtpstBQUsgMfaGePsW9l+WIt+Xx2e0x3QQJTnY4sUHs/J5gVT/XcAN9YrC4z4vKDSuA9c5wopIxQz742FUkdzh/a0WQO72rQ+QSFhIw5u2Ug1pPdcId1+UTW37Cof8wcthlQPdiAdmAHSoQ6m/wVI1JHybbtg1bMwxbGRc8OCa4dK+rUAqdrJh9S9UFAAKLerjoF1dGVFggyHpOqo8tHyjF0dJXadVEkNrX6uA0KqzTD554D059SyAwxcF1ZbHQHpAgEJyAEkQg3nlwpAQmnF2kmoJQWllFp1mnxZSSH9efOfKaugwuF7yDbcxUqpdsT31VFHun4CFKijfBid7iGFrDWHVZanhJIaDwDKQiV+fU8KmVj/yV7Khrs4WHEAKFpyKCEGIPr3ZWGgkNyqu7Ci3V7zdA9uAOKsGoog4jIPRlo0ACOU0UV6zXgNzjzuj1b2sN/aqQf8JqijBEhfvfaUdWv4TmLXtbQZA7raIq20HUiyZX7ashtvTNJRIW3WZL+FiS8qpKiSEih9n9STfshAyQqhRF3Ja0uF8Cn8Pvk9TeRu/QlGAOnHCCQsvO1CSROvJmruN5P2+lnj3X5ECQAl1FBuoBBk0+l3ourYNF92nR6nK0GCDA7bENwoFmZwyy4qpcxlnkLSY4tA0n0GGJsECW4v2HYj/XVYKFWCSuI1miYVg303pXcHm9yrvcbXvpjARls+YYhDhAVD+tro+gBQVK9bpRwDlEoAdfKc8LipY32DOlINcfl4qSO9JxbrfiyQip47pIfN1H2ZqvsxUZbd6ARIvRu/bx0+eMX+Wqe623aVZZlX1eKwmj57oY4UFRJAkjpioIziKFRIsY6kzzZzBKElXBHqvswtl+v7Wkl9dIdK+pUQqWapI/oBBCwtJnGScRfJ2wUc1GSqHPP7EGY4co/UrqNuc4EsPtJwHmbIA1KoIV175kle+8kCiWRcDSmcMwQkCpYRSEy6TL5ZKAEmt+pkT0V1FIMMlfX33IfTDt5Zab/dFW6QOqJ2JFsQCJKku+3cMg7Yv2rSx6KLMAJEWHO5oEEIGziIInTcXssBhnpPbgTIRNjkXQo2ACd/ZGAkKGHfcduk6m5SMpEgR3EYKUWnDyPPy2VYnnp9SB4BI1aNF+vDi1V3thJOFZR0LJ0EGVBHDWTXff7CI9auXkjXDWnd2Cc2JjTsmGJA0iody+abAoX0bQIkVtd5QBKUti2UelikCZtJW1D6nolbUPqBISj9yJBSMoaDKcIlwua/XBbp/6lD+QBGGSChWHR7/1Ul+eQrlSTgYJE5lAQmLhmuAoGRfg9V5bWjDIxCkjBJEXI/qGtFdfc/hRqCQgpACrUwryMJHth23K+gkoZJJQ2y+SOC9QiUULPT+nVKB6EHgIV1R81vtcAKSLnfWYhGEHGZU0gZdaTXlMcNlLFoV+l1XyGrbpnU1xJd96KR/Wy+7Lq5g3rYLN3mNEERII0RkIa0/Mz6NPnAOn30mtX9xw0OJBaWpFxJ2p1zYgg2YNlFEOUFGlQPOl8j1JCUtNP7NwYbUttOn3VCVdefpUWtgHS1VBIp3HMFth21pF8JkPBpSbYRfcZyQ2EQPPDakeoyQR1l03W7ahLcyydR/F6PexcAiRXOtXozucKh3pEoJCLfNQWk8ofvZdVViD9Pb0pCDZdRrNcEDJQobgIjLj3IoPtzkWw43sjUjvgAYNeVVR2rtMIM5aQOUEeoL+DHbQNW1B423U/CqE4Sv05AFKAj4FDnYbi6iYDBbvvfR1RE4bKaKyQPMkiJYRdijxJxdzXEY9VjZ0QQbQ9GfECx6gB6pWP2kUpUkEGpOmAU7brmSte1e+8l69f8Ey+SM6H9r0BaKyURJmsppNma8DR5bp6nVTgqab5U0gKAFKD0XQKl74GShgNJUMoDkoNJNSXA5COCJl4mcMqDkP4v/j4WoA/BQaBzNQaQdHtAcavgiHoDmkzOrpA0UW+QCvlW1lhQSSilACYeG1+7TZfAyKHrSiMJbWSUEerM1VExIAk4EUyuijL1I7fsovUYLDvqUEAOWAA/QIhKwjLzWtLoULvBnpspu2zGgC7p4Ps5Ui28hsADkKD4sN9CChJlp2g+z0Mc/nxgY0bFGGDE64tt+c3koI6KpI6WCYhLRg2whcP72vyhvWwO96GfgNQrAulLGyog9Wv6kXX5+A37+Kn7UyCF6LeSdvoMhmAD0e+gjLanjgg1ePQ7UUgACdsuhhtwOGIticUY4alqJ1FL2rf6r2Ra/nU+TMW26xK7RuWgkHgjUIPJJuuoHRXadbw5gBj7hFAjrGZyll2IajuQgEwekCTlFWoolwWSbp83Xb5KklrS37LPBjWAz3yeVl686Un2sNeIqDd7j86WZUCyjn1OpPq4P4QYCDAAo8JaUW4fkPYA5SmiCJ78y+JgAS4/NaIiqmYPXB4Gv49q4vZQZ7fpvvGBo24WQVQSjEJ4IaeMgNFFqqXxga96/H6+54ggwyt33ZQHpBZvPGM9GmnvUeuw94iiP3HvPIWkic1TdqofrJqEQhrpK3YHEnWKmQBpom2aIyDN1YTnUAJICZQEpu8EA6D0PaMQSoBpyRwzQcSWJmopwmmZJnnGcsCTgU+EUObSYaTr+EHKCOC5OtJtcbsoNWzEFEia6JmgN8qyC0DCtkugJEURQcREHpVRHoywIoEdKkwA+UH3I39/lSATVZKHGxIoba8mJrsupuxC9FtJOykkB5KAiXWGUqGGE9Nt1G94vagp+RjIZXel3nraPNlpqCReN/4OpZd9HNSU0pE8F8G+1HMAkLEtVTdCDfOar5gwzJbrfbB09ECFQ/oLSH1svpTYHN3mzH5SabIMJ3VV8q/Dlza8VWPr//nH1l1JxwZEv4+WcyKFBJBI2sX9SCHYsH2rLgYaCoGUqiQ5AoQbfE7R/MJnpLYWrWwx2WHb/cI5VVObz4DBLdVLu9JB0VCHqSElwr6j1K5j71GyGRabjL/DrqPexP6ekoGkgEIKpKPdTkN5YQWW0+bN6n8mdaN9CJpkCTUEIP1JIArWHUEGVkx1VCu5QOEH3ugUUCvpg8B94X6UP3yPPHXE/eCxoI7Y5IpNFy26aNOFTamx/pNYcanNJgUkWy0qoahuIlhKvjxH4IkjgOoBASj7uwAJdQQM/yZI3ihoYkeUBCPUIjZdCqPEouN5YmDVVZM94nuODt41Tx01ePJua/bio66O2HtESmuqCtOk6xaOTCw7TWhMfqy0WR0zGUYgrdHKea1qC+umAyRZQrMA0qQAJEFpiya5rQLTVimlbfOlkiKUBAaH0iKpJJTSYsGIIYAYUErBlAFUHqSywNLX/J+GKy39bVReEXoRRtw+gES9AcxNuo8bBVAmYWCKQsJ6DFACQskQDKJNF0MM2fTg9wBQ8PSod1YhoZLSYEaEU8Elv+P1Mikj/W1IB7IPCRgpGSgVx21zn1BIDiTZcES7Y8INNcSG2QCl7v41lh12mu8j0+uHdReglIvo+2MCyBrpc8Dj12u5TvBbo9d2tWD0jWC0UlZt0XhtjtZ1LdV7YvGIfrZwaG+bL7tuzgBBsK+A1FM1LAFpXIevbESrJjaw2SfWs+G71r7eS/45BEgsEAFSjH/HDbI5dZSz6VK7TsoIuy5r2QEkrHnfk6R5iKAPC14s7RABP9yq/mlHuOEXi6QztQsau46INeqIydztOtlq2HXEqCtr8j/jyKxdt4uDgHQcdhNAYmCT8fcxZcf3sUuDKyS90S467QjZakEhRcuO2HcdTbgAKaeSsO6COrpE6ugi1aoK7Tpi5+w9AlDsSSI2iiLDPvR4N1ZdsrcogihVRnmqKAAJ9ZKvhIqrnACYCJ7c5YOC0YNXaOgyB6b4dQAT10+NqphVV2DTZWHEh5DwAgoxKqMLpRT5wFfRniMPMuyfCzLUf/xO+0zpOsIMHT581QZ81dDGae/RLK12HUixhgSQxmSApFWyA0kWDpPV2qkASStvB5IsIWw7VJLGFk34W+cKSJr8tzmUptl3QEnje6C0cKb9IOXyg8D0YxwCFHAyHwmcIqT+yyVA428dcro+oOeqTLflMNJ9cCtR9wcVx/10dYQVJ5gCo3QIRkDKwwCasFFGwAh1lY1459QRacEkXUcNyQMZACkOLLk44s+AEaoo16EBxcX1Y6XFFCAKLQQLQsqN/T8sEFA/RK4jkFBKYfTw5Bv/RwpuifaSATACCdhvKKVgQQJcQBweOz9DFQIjFhq8vqv1OvN6r9TrXjROQNJ7YanU0WLZdRFIc/t3tVl9Otn0BEjjBaRRrZva4OYNrE+j96zT+6/YrRec6QoJIPE5ZJO6qyRZ8tSRStp75OooY9ddqI3ybI4FRg4kuTPsWcSuB0jMLVyyWMW2O/uEg3aopF8qkUjXYdcBEiwuQggXacLD/optgkpK150uGACy+Ibh74sBSZArBiS98Qg1ED6gBkUNCbBxH5h8HUpSBrz5gjoizHCMWozIrtPfxXQdbYJoW0TKjp/xhr7yjOP9zcvjoBaGCmHyT2F0kdr1UC8CRlIquYBC1SSAEAEULwUSqZqSIOTwAUCFI4Ip+XmAU6gdEWTgvnDfrteHjFRdVEexZvTfYESqjueB9kA8f6UP2jlPHTV8+h5r8tyD1vrt57T36D1vQTOpZzubp5qAr6wBkmw7Jr2livcu06ZMJiRsm1VaLVNTyAOSJrENmsw2opIEJQdSIZQA0zxBSWqJ8f2CGfYDAzBppFASTCxvREBt//JHQKa/AW5cF7ADehGAABEwbklgxP1DzQHQjYBH9zsdfK8BrFAPm1RXiUENajpRHXmUHbuOWpVbdgFIXkdyKJUApkQNRRDxu3HfVDEY6fYdRplgAUon7AEapBSk6kjDexeoI9l1UkxYeXRPWKDwA0oKlYt1RyDFoaRFBOBBDVE380tgpJ+vnaYhcK2ZEmpH3xBkGT/MVowVkEZrcSIgLRGQFmlv0/yBui0BaXafzjZDQJoihTRRe7xGt/nchn75qfVr/IF1/egN+/vF52qDuxQS0W/Zxw4lKSXqvLgZrpAyqbqgjkLtKNp1AClujiWFS7kAIOHUMKfEwBR7FC/U+7/aiWwZ2WdHBPyXCCXy/aiSaLsxqaNgQn847Lq9c62CMnYdqTaCCP+/gSSFBJCw7bDs2PAWUnbH2MUOpOMSlRTUEomyrF2HJcAHgE4RbIblA0BdicAEta9CdRRi3SFNd7eCBPSOAwxZGPF1cXUUQcRlUD758KmewKi6PXQFX8fv8yEVgUQ4gk2zIVWndkyyIHIwirHuktN0URkBo1qCN+2BKmkCIMjAZuAYZEAdxb1H7RXL7dv8Y2O3P2mtCCTivA4kFa+pGVDIXg6QZNth32DjrJ4shaRJa51W09/KttswQ0BSLWmTJvfNmui3zJZK0sS/dY6UksY2qaVtAsJ3QEnje6Ck8QMjgdOPCwQmBoDSMB8C1MJCSIXvHWLJ7/L7EW7AjusGfECQ20Wtodq4T5t13wAnA4gCpbwhGKCgsPW8HqYQgKujCCRqUoJgiHonNaQCKKUBB6kgDzpkLtlvlIURSotUHcBDiblNJ2WEYsnuAXJ1JLVD+nHRqH6ukDzUoCAK0WvqR9h3WHYOJLdfw8LCbVdBiZADiwnqQ14DBE6ZgToKQJJCmqQNwXq9V2khslJAKnIg6T0hIC0eIgUmy26eA6mTzRSQpnVta5M6trSxbZvbiK8a2cAmH1nPT962unfckAKJ6HdUSSwSSwaSYJSooxyQ6GcXFBKhBgeSPs9BIWljO1tKZG/j4uCkUEeq+qf9dwDplwakysftV7eWVA6bUJnIWY0wsbP36BxN/MGuY+/RXg4AItbs+SmjVTmpNkAWgcTfMrDrUssuUUhpDamsakhaAQE8oFRRQQl62dFAkZUPb7agkgKUqJ9gVYV0nXrpaSJmM2wl7YfivqCSojpi7wJQzaqjO2qVlyLRPiPVbLx1TwKjVB0JEg4mXeYDKQejfAgBmwifcAmMHroyC6V8MKGuqEXdc7GsugsqWtgAmwsyXE6iztXg9mFUR88bMKot27IwyJBN1gGkxnUfsJYKM3Rt+LbvPUId0f6lOJC0upZKWiarZrlUkgNJkxOTFJOVA0m23XpNaBu04t44Q0CKUJqVQEmTvwMJKGl8JzD4AErpEJTmBTj9OH+G5Q0BypKRAgtopSNRWvq7HzQi6Bx8QNBHgCIwApQAc5MgBDzjyIEpwki/F4GE3YddB5A0tsW9VYQaNLKbfX1TbmLfAZ0wBCCHULDoAoxy6ojroG6UByRZaG7VJbFrui+gcmh2i3JdoDof0AFE7EWi6SppO2pJvJY0xsW2i4lJlC6hBKLbq6gpSeWuAUxJLdDrgQmMeF3XaMGxRq/xahYgUkgAaYWAtHxkBkgDVavq383mSiHN6tnBpgtIkwWk8e2+sFEtGtuQzz+xPg3eVa/EBwOQZO1XPX7fVCWxJwlbGYUUa0ZZqy4Ho2DXZYGE9e6WnT7T7Efic00XEwJAOCjUrlVH0t7DXav/0ubkX/XjOevEg9yu40VnFUL2H/nMHqGz9ObanjqiblPxqL09mhyBFC073jw+9OahhxyWXTb2zeoHINFNobxUDp0a6FVFyyI6jLtKSpRS7GB9oSCW2nUKWQBI4t6sxvCos+rIO3Z77SjfrsuqIwcSMCoAUty4mgsi5KsdYJQCCAgVjhRW4e9QR9SkgB5QJH4eC7Q5dVSwz0gQBsrsMwoBhgRGet5qqQDs6khFZDoy5KmjJ+60T5++15q//Lj2Hr1ofZt9bCO+buYbLOeyqtaYj9XDylq23WLZdkR8UUkOJKmklVJJ30wASIoTa9Jap8lrvWyeb6dJJU0fb5sSKG3WZL/FxyTbOktQEgi2zU6gBJjUkobxvYDx/VzBSeOHwiFI/ZiOAlBJ/QAuV1jATMMB59eVQE/XDwQZ3P4WV26yFAXLCKJil4lywtYLQCKgIYVEDQnrj3AEdakIJfZXRSihknwkIQdP3kUoxcuojgqBFDonZIMM1HvSDgmTlHKbMMTtN2w4an0oIRQSCwo6gBNKYW8ScXB/PZPXErXL3qGgdJOFRap0BSbgA5x0uTYd+vlEqSm91gBplYC0UkAqEpCWDetnS6WQFglIC/p1s3kC0uweHWxG13Y2tVMrm/j1lzamZRMb3qyh9VdPvW4fvKEa896CkoCkpF2AkjbJakFLNxU+n8S7w4gdvoNFF606YMSIdt2leUA6yecTtnCgkmilRR2pquaNCkfuvUMl/ZIIxkYzVudABaCQbDnfwwx0QUjCDFIxFY5QZwbUkSyyMgf9JnRFOH5/SeoTU4UEhLiOPCDpeuM+pLgxFiClrYMEtTN1PXQaoB5FHSlVSZqU3a7Tm/MCvVkpkGLXVdH9quBpP+070hueKHhxdZSfrAtBhsSuuySx6yKQkksUUlRJEUglqaMckM5NgMRl8rUDKQcxrgfo3V0Hqy70qiME4htgUUZaAfL8e91IKz8UYQqjckmIAWWk5wx1xPNEzBurs9QB+bUjbLvPnv23EfXu9PHrfkxAbDfjtQegpJX1Agri1AmUplqiyc+BJJVUJJW0cpxW2FJJqzVZsYJmAluvfm/fCkobBKWNCZQ2C0ybZwpKMwFSGNsEJh+Cw3eCUxzf62sfAsgPs5PB1z4EqjnT7MdCWKXfh9/7Xr8bRu56twFBYJjcPveF+xRGouZQdOlIFJPUEyrKoYSqwupLoERq0KEkMDmUCE9koURdKQOlHwqhlNh1eZZdopCIeRcCiWM+qP14yx6AFBWSFgwACQChjobrKAp62gEl34uUqKRYE1wsi8+hlLyOUe3yWrriBT4sMvSaAqI4VgtGq3nNxwhIo5TYGzHAlgOkwb1t8YAetrBfV5vXu7PNEZBmCkjTOraySe2+tHGtPreRX3xqgz770Hp+9KbdfuHZrpLoKxmg9Ef/rEYgoYbi8FRdAqAIolQdaeHJtg0WmASrvGODQkrMKbdqgzt79kil4qacfaJCPcfvsO1+MTyqfMx+dVlpABWkMCoJ/5YwAx0PXB3JGsuee0TEmuMdOG8IZYPVFxXS/wIkmqsCpNp6g2ILnqUVVSUlxfCESdrVxrYTlFAHcWJ2u06/j/xHEVE/QlnRZRhIkcDz2pFWTxzdEDfBxn1HNC7N2nVp7ehShRoSCMWf/TSQsoroXHtYEPJxVSGQgmUHjFBHBCioY3HfUEcx5p1n1SUw8i4Meuxpoi4DI1aY7IKnu0UxdUTt6Jn7kkaqoTPDcKmjKeqHNkcJLbd5ABLFakV6FwxTHclVkoAklbRMKqloDEAaYquYpLRyZtJaOylRSUBJ9h1Q2iQoOZAEpS0zgNJE2+pDYBIUtiXju5kCk4ARx/f6Ojem2A+zNAQrv+Tr5PsUYPr+ex/8nUDEdXGdGuE2dLu6fYbfDyA5naH7BzizQzUwV3eJwtsEuIBSCiZBKQFTgJJqU0CJ8IRDiQ4UjAgk9iahlKSMUiipnqTAQ7TyYqDBLbtMuo52Qd41IqOQIpQINZCaI6hAsAGlhE1H66BBLRu5UprWt1Ow7ng9sypJgYRowbK4WBEXGKhevaYMB1C81PESq8fq/wSjVaP12o8caCuG97flQ7XpdlBvW9JfQOrb1eb36mxzu3ewWV3a2XQBaYqANKF1Mxv9xWc2tIlsu0/esefvuNFi9DtCibQdwQa6NaT2nD7H4fyjoIgikGK6jvkHu64kIJGaZd8eC7pYR2Ixq5Zh1X8xk/Kv+YEIKP0AAN0QABKrEeo65550gFY5+WGGqI5KHxhgVGr/nb0HHYX5/wVIoZdd6PbtCqm0mqsKfFUFowpH/t6vi6TdhadhTwVlQNQZOKEM6A4c6kcCkiZkAg18APCk2TRL7SrsOwpHSnjU+wJ1787Uj/wgPMEhL9CQQKlkIOWUjlt1bs/lg+jhq2rYw1kg6XdiuMHVUWLV/e28su6B/+XM0JEhD0bZvUZaFUarjpoRMObxkzDkaAn61ZU7fA/v5l1YOyLM8MUrT1jHj16z/l80UCPVFn6+DhaPA4k6kjZVzheUFghKqCT2nCzRRLZMUKKozSS2SitmJq8ApJG2DpU0ebR9KyhtmDrWNgIlDSb9LQ4lgUkg2KqvgcO2gvHdjEmWHd/r+3QILt/PSAZfx+/96/y/8+uYruv3odviNqfpPiRjM/cpuW/cv01Tw/3k/qZDAQ0HlYMpKCYsPsDkNagUSgpKOJAKoCSF5BtzY8ghCyOpoxhwcIWkGhNqyrsyCEj0rqNVEFFsAg1u2U1XBJsNqrTvoZ+c1JLDSXWgEHIYYotVHwJM1JBo/0SzVUIqxMBd8SqNhwWbKl69lstZYPB6ssjgNZUlx/jGh15fLgWibwSiVVJGqwSjlSP62wqpo6LBfWzpwF4CUndb1KerLejZyYE0u0tbmyEgTW33lU1q3dzGfdXYRjStbwMavm+N//OIPo+/d/eCfpJAicQd9V0CRymQCpQRrclI9AKkaNd5/ahQIWl+ojYcF3XUkWokdaQKx+zo2vCL4BgbUrGI6NSNwmBVAiTwflO77sgQZiBeTZCh1P472Z/33UnW3W52rv7+Gv1dSUCiySrBBkCBZVcIJBQS8GPjLUmxs7XyJ9iAbQckse5ir7YckLRJ1wMNbIhV7UlveCZqOjlgFSLpQ9Q7t/fIE3a1cwophZJsuzTYIGg4kEqw7IAKtl206aIiAkJhCEjRrgNYV+TUEWqLuhXBCoIMDv0k5p2z6rDp2Pibser02OnCEEMM1M+ym2BP03lPhbWj+k+EYyZavfWsdfv0HZ+4qD2w92i2VthzgNIgFcOBklbWtIVZiEoSlJYISktVO/BJzCcwTVSCUqqSdEzBOimlbwWlDZPH2EaBaaPAxIQfIBCg4IAAEsnYpst0TJtg3zEEkzi+19f5Q6BK/j9e+u8mf7tNl9sEn21Tx9tWH+NsyxQN7ocuN08Z62OTLsPgvgqgcQDTBKhuPQqoqCa3+FQPy0Ip3V+VUUm+GVcKKW0cm8DI++w5jMLeowilqJAcSApLhK4MYSMsgQYSdvSSox9d3hCgspDyOPh4gUl1ImpHpCZRTAQeWGhQF6SzQlC8uQXGcl9kSPUITNSHGCihMAbZNwmIVsmmWzlcvfEEoxVD+gpIvW3ZgJ62pG93W9xbraYEpHnd2tvszm1tZodWNk1Amiwgjf+qiY36vKENafSR9fnorQAk1ZHYjwSUqCWlQJK6zyqjLIgijCKQvH6UAIkwFPMHn29fcNY83Rd2LOjSOtJRv6/7i5iQf80PosIRv68egKT2HIIKdh3yOS/MILuOFBunwlI7wqo75Y87qW/cLqrh7OVJF/42AumGs5O2QcCoEEiV6fadU0icGItlR7cGb4qqjW7UR+joS7iByTgU9MNBfDRjxK7iTR46NPzWLTwkPkEMOo0DJCS9W3bnq4kq5xvJKot7kIBD2IMUYt95QBI8on2HzQaI4nAgARuNLJAe2Y46ikEGt+qk0Lg/MbJKkCELI1KKxTsx5MMoXx3tqee/oHaU2HXety4JM4xUE8zpWDsAKQMlmmVmVdIiQWmxTmVlQ2RUSSsFJVdJsnTWjB9ua3Vo2zpBaT1QmgSURtvGBExM/JsBggZg2JLCIkADeIQhmOh8ou+yA9DwfbzM/p++5u++S/9e1zMljK2Cz9bJuq3JY31s1mUYY3Q5xjYxJglGuq8+uK+Z++yAAqioqDwoheSgR9lVU/INvwJS2hZpsfZBJUDKO1ojKiM2yq6IQ9adgEVCjxNi2QyLOmLvkTc1TWCUdhzX9zR+Df31wmXaCFbAil0cOHqCZB1nI1FP4rUFUqEuqNcSxesLDL2eLDI0ikYJShork4EaSodAtHJYf1s5NAej5VJHy2TXLenbzRb36mILe3S0eV1l/QpIszq0tuntWtgUAWliC9W1mjey4Y1l2330tv29dvU0bQeUQrPV/V0hxU4MsVaUWnQoIzVCjlHvaNdh7bORPgKJxS0KiQbJfM5pI0Q6mGBDxaN37Ef62bMMIKFwWJ0DFXpG/TSQcuqIyDVNTVmhUA9JgaQ3TQg1JMEGfX89RxGXoJA4Dp3wBACkHnKmzlRiP5LOY8qopAClbMKON3lsGUT8+VLZetx/Iut+hlNSQ2JDLMrkH7LtIpBCHSlCKWkZVKCOClN2MdQQ03Q5IAWrzlVSRiHx+2ykRXGFTt7l/X7RQp8P0XZh5FZdfoiBxw2MUnUkixI1eapUarrv6Ak1UgVISWeGzp+8mdYafO+KVtERSvQlQylFKC2QdceOfHbmM4mxKXI5kxcraewc1RdWF0DpW4Hp24mjbAOTvU/8ox0AACECgsutApWDQ/DYlo4AlO8SsHCZG+P0dW7k/ib5ewEICG3luhmTdHuCThybJ+p++BilyzA26jJv+H3mfmtI5W1KoIT1uFk2o4c0FJTYqqDDVll3vtE3ARKdIbxLhICUNowVcPLUEUCiY4NDKXf2EZttff+R9j+ltaOMKqI5qsNIm1i9s4JqTJwmS62J71OI6W+8AavqTCTxANL0fp38NUX1AqVFUkrx9VzKayobbrlGkVQQgYWVmbEqA6OVUkYrBvWxIsFoudTRsn4CUh+ApKPuBaT5AKkTQGplMwSkqW2+tMktPrfxXzS2kY1l231Szxo9+W8Hkm+SVfAI2w63hZo0QIrWXKqIBCLs+zgcRqTrBCMi3wApG2rA/WAPH0BiQzluCnVs1aB3JO1+7kTKA5IsOw7A403DZthicW8pJMIMTITAgzcZ9ZsL9YYoEUiafGPAASuwZCCxOTYACXlPauxsvbnYpEu4IauSigFJYQa6M1BXopMDQOT4hnCo4Gl+thBAii2DcnWk3F6k1LpTTSnYdfkbY7PqKE8hJVZdVEcOqARIDiMpK7fq6lR2dcaHCPVGrS3WjbKJuuxREihCt+n0IeXxAyPShefqA03jyvJ6jgq7MgCjaNcR9e7V5H3vzMD5NSmQgJJ6ks3WiFCaJ6U0X/UkoBRUUl9jAvMVteoPbu8IShS9gdJaKaV1UkrrNb6dMNI2ACWf8AUCTfQoks263JyBBNCI8ODrbekQZASXbZOSS76O3/MzH/w+Xwf4+HXpurcyJgpEgs+W5HLzBN3uBEGIMZ4x0jZmh+7vRkYEVISpoJmDkupgCjpsIbFHei8CaX7SCukngQSICgYtg9QDj0CD7z9SeyL65/lmWBQPdaPEmsO64+cACFuPWhOJPB9SVsCMTt0ehtDvxaMqgBLWnR9JoYUGzVBZYPjrKeVLx4WlUr/LNJYrrFCkQWhhZRyJMnIYqW60QkGGogECktTRMtl1S3p3tcU9BaTuAUhzBaTZHVrbTAFpWpsvbErLZg6k0U0b2JAGH1iz/zzqi0WAxOBzTbAhBZIWWDkYBRCRqLtE7/c8GAlIJOyuzCgkGiXjNNCTknDDVQpTUW92IB2zr/3c5+Nf/f0XkOpikcUaEsEGdk/H7gyxdx3hAT+NVVFv6hYcOV5d1lklQcEVkt4YpF5Ij6GOqJO4SkouI5DYh5S17PCQ/QgKdfymX97pqosgvzlKgaMovJaEdacVUw5IiWWn26545F7uSROfvlFHp2OJ3axmqtRqfB+SQgQAqdC2QyXFxF0KpUQlAZLtpezSGlJaO4o1pEzc+/Kw5wirztWRoHizbIYY807VUdamy+w3CnWjXIgBGGFVctYRC4DTDw3qqHiY4T778tUnrf0HL9uALxukx0zMVBE8DIAUxmzqDtg8A1UQF5QWCEqukpIJzFfUsnmweKg1UPgGSmuAksY6gWn9eEFJY0Oc6BMYoFIYWVgADQBSOLbpZ9sEF4eUf50Aq4Tfzf7tFsFn6wQBySGk2xOAwhjpIHIYjRthG+NwMOm+pvc3UU0ZKLnlOD0JaKiW5EBiL5U29sY2SKE3X9IsViopPd9pOcm6xKZDHfnQ9wo0sGcpCyRvoio1BIhQOpzMy9cACRUEjIAXNSfCEN8LaFzmp/SC7UfNiUQeG2Qn9fxai42uUr6CEq8niwyU71BBSWPpMKXmNIhzF1EnSgY23Uol6lYMZqCOAFJPWy51BJCWyq4DSIsEpAVd2ts8AWmOgDSrXUub3vpLB9LEL5rY2KYNbdinH1q/D9+2W2tWSaHE9gxqvhFI1Ijy7LkERBFG1LAvKx9ghDpivri60p98LyN2nTdJlg0PmGL0+yxZ/ZWO3U/zxx7Vf/WT+s/5CQhAOsyL6YQaaNFByIDzhEjYYct5/chbBXHeUAgzsO+HYyOYINktfY2AhGUGiHwITgQZgNINugRIbIxNQw1a+bAi4s3JuUXe9VuqjIj5GYJdtZPUBZxaUkYl5QMpdGlgBUazVUDqAARI5wCkXB3pbyXUkdKODWk9KWPdKXEXgZSrI8WkXS7yndp2SewbOy+qI9QWtSqsQupZMeadwsgTdbkQQ65pan7diHOO6GyOOvLjJVSz4/C9a6tXzLPr6OpNZwbCDN0/fdeGtmniKawZSmGxcp6ZGbP0NWCKSmmeepXNH5RMYNoIuURQYkXtFo+gxL6UPCgJTGvHCkrjBCUNh1JGiaBQUCooli26BBoBIEBEI8JGQPHvdbmtYISfJ7/P32RGuD5dryAUh8No3EjbrLFJEGKkMMp8vYGvBSVXSrpvrpZQdtiOsu4IZ5AU9Ai7VJJvuJVKStsg0f4oUUnpURocmyHwBNsOhVQIpJxCol0Q9SHUTUzScUltCCDR6BUY0WaIrg/haAuub4HHyL0WFa0/XRcWH39PRwesu4nd23hnbn9NFXRYOFhQEphoAbRkiF5XgWmZBpHuIgYWHTDiUjCKdl0KJNl1S3t1tSURSLLs5nVSx48ESDNk2U2VQpokII37/FMboWBDvw/esjtUR8JSJwnLZxq3BVse9yXWibDoXBlpsUmA4dJyiU2XKCOHEXadPivMG3y+UUWxLyWXAImjKLSx39RtZgeQfs4w4r5XUDIFe4y9PpxZT1KNHdWkYkjYcfYRm09jqyDSdagYIpx0WDhL8WP2DuHlxug3pztinzGAEqMQSEhxVkSslHwvUmLbnXPCfl6sp43QucmBfUzKbAiNQPJD+ZKUHZM07XSofQFCPz5dQCpWR5JKol0Ptl2sJaVQqpM5lE+pO2CSVUkcFRFTdm7bXZGDUqwpZWHE36KOuB0+NAAyjXn75tckUacPG897DkZZqy7UjYBRrB3Rs47gx6n7/yaviaofwqe9R5+/+Ih9/d5L1ufzj2xk++ZJbQEgJaNfZ5vpQ0ASlGbTn4wV9YCMSmLy0qp6Catph5JU0kgK4QmUpJZWSy2tGQOUhtp6gelbQYmJHvWBRYY6wTIDEimQxkcoAaEAom0ZyKTA0e9tLTZGJT/LAWgL15cAabNuDxA5jMbqtn0ISmN1fxhAKF5yP+N9dWUHlELoIQQzgFJQSb6XCttOm3G9DRK2HUCin54avPpRGmq6mqqkIuLeWSAJJPoZHcJRNx5oEHAAT2ygyl4jFM4KNqtKNWHJoYw8ofeNzlZarUP+GHyt60YpUYsKST2dn5QAiSMopuu1Hd3xK5uhrtxz1OpnnhQwjVEXarGxSIppseC0RMk5NrsuE6CWC1BFPjIwwq5T/aiovxQSll0JQJrfuZ3N7dDGFdKMNl8JSM1TII387GMb+LHaCD3GgX2/S1VSIZD47OcUUdhvFGpGGWWUqCPqR5xrRmIXIHGm2T+10MO2I91LEtc3xwKkw/ao+3Ofk3/V99+BJDuIiZHVBsc8+MF3dEJArQhI4dyj3ZSwU/1Idh1HRaCiGIQLzhY8SI2xORZbymGkNwoQilBKgaSU3VVq2hqBxCopRr+JmmPblTtsD6uShBtoJRRVUhZIWADYddhYTOikAwESSiTWkdy2k6zPqyM5lM5IoXTXRSXUk/Ksu9Dte3u1pAgk9hzFVJ2rI9WO/o/UUVI3wq5j3xHgpaN3GamjPyvhmBdmeCJshuWYiU6fvKFjJoJdx5HXFLuZqGZkRoCS+pI5lHQUtsA0l8krse58RR0tHtUZvBAeoSQwsWdlzeghtlZgWicwOZTGBigx+QcgCRACRYRGMZUkGGWB5F8XgCj9f34OvPz/A5T4Ol53FkgpmFBKglBQS6obAaVkOJAcSqqBxZpSVEmkBfNUEkCSQlLro6CSMkBaLMtuCec56aymNNiAbZcoJC4BEjUkJfOoAWHXYdMtGz/Em6cCknie0SqppA0CEtCxVQUwWrVQCmm+KydqSoQdCEYAsSLtVSJxx+tNF4fRSlbO6hde13mqFy6QLbtQYFokMC3WWDKoly3VWCYwLZcqCkMgAkYapOsINMQa0lKvIXWRZdfJFnbtYA6kjm1sdnsFGwSkaa2a2+Svmtr4Zo1slJJ2gxRsaPrkQz53YOlj+zNPoJAINGRB5BCSIooWHfMCyihYdUEdYfNfp7kpH0gV/fPFfHNR2WNTIJU/4nc7gg0/Z6JVPHKfflhuDiStQjginPOECCw4kDQJEvcumzRSJe59tpoZ0nvqAoBErFPf0/YGlRTj3wCC4VBKLt2y0++w4uENh1cMkHiT0kIo7kdC5pc5eFeptGDboRBcJcmao5aCXUg3YT9uQk1W2RDLabUcEAiQOOyOmk1JdSQgESPgUSl5LanAugsBh+Sk2MuyUCpu3WU3wGLx3SuVFZJ12dpRJlmXVzuSUhRQQ0cG7Lr82hEKiRQhrZIq6sPN83LduYV23V2ujlq/Xde6Nwp2HZ0Z2MnPIPbtQxPWDH0dB2CapTFbbWHmSCnN08QFlILNI5WEvaM6w3IppRRKAhMbKL8ZFaE0NEBpjJRSAZQcFKmtFhUScMmqpOJ23fbtu/h3QWEBKQedwykAqqRa0ibBKQ9G1JHiEJA2ROsO2y7G110lqY6EbTc7UUk0iZVK+kFdG1whASQUEkBy266gjhSBFBWSgISiQQ3RyZu6T+zczcmvKCVqSNh1bvsBJUa06xJ1BLQIP1A/inCjwSqW3ZjOLbxV1Ax9PauvWv1osTFPamm+VPACtQBaJDAtVm+6JQwHk9QSikkgWqbvlwMq4t4k7KSQlhJq0KZYYt+LPNggIMm2myvbjmCDJ+1af5Em7UY1qe9A6vH2K95nkgVtANI+DiQcEa8ROYSO9YVpgFAORHkw0lyBXUcvTIB0OwpJyojP8D/lQJBapVsDFj+L2PLaXP9zno9/9fed7H4EEkChh11oGRQ6IVA/Ct0ZQqsgNsOy25qUDHuISNBUPvaPHhsnzozthyqKEfIslLDV2CuUBZLXkfQmjUCqKdhUUyIHa6q86iVE0tkoy1ELKCTgFFsHoRj4GhhGEF6vYIMDyetIocUIxU9UEhKfcINbd3pDRyD9lHWX3ZNUWE/ygIOUUawb8f9u18kC5AOTTdbl7TsqAUhpsk7Q5XGijIARTVRzQPq9AykvzJCoo2YvPeZ2Xb/mn9gorZBJ1zFBTeubGw4l/Ww6B61pAKaZmrRYTWPfzdVqGigtSKDkdQeHkgrhQElqicgwe1e+GTnIVmu4UpJaWi+l9K3suw2CUpj8g3UXbLsCGBFeSIdCDBOTQfqOr9MUXu5rUnXhb8LvhLQdyTvBKalJpWk7QhWCTPG0HSASgHzkAhmuktJwQ6wl5dt2QSGpjx5ASmy7HwWk4rYdCimx7bhU0IF9SFEh0ZUB8ISOC+rgrYXDZO0lQt3ws5Xqzo0dB5Q4XTZsqpXC0vdbEqtunVRWqEGN1HUNU2uhAX4cBXuSRsiq5T3AUeMz9RrP7tvF5tKHDihpLBCYFmbBJMWEWkqHQLVUMGLQocE3xQpIi3prH5Ki32yOna/2QXO7KEDRqY3NbN/SprUl+t3MxjX/zEY1aWCDG7xvPeu9arfUqBxUkurQ1KNxQLKbXVMlpDmHJF06KgZlhJOCOsKuywKJz7F/dgUkFqAXlztOHV4OcSDR6PlXP6n/nJ+AM47ex0MJdNaml91luuTsEmKarGwqUj9SN+3Tku4M5WTXeWQTZaOJk4P7CCHwpkhtO61mgA/jvwJJcc9YR0Ih8aaNx13QNLTq8Qf4hBxVEn3c/P5JMfimXKkHuv5Sv0K+Z4EU6khhg2y07XxPUoRSpp70U9ZdPpTy60nAKJwMG/rV3adABNfFKo7bZwUXrNAT3A71BqoFQIrqKNbJPOadwIjHHYB0gD7cv1fcPv+I8lg/+ur1p61Lfe09avGpr5Kn9BaQGAKQgwk4xdEbKKljtCasmQmUZicWz1wmLocSdYdQDPdCeExnRSiNEJQ0VqOURsm6G63VvUMpWne5OhJw8FBDDDM4jHKwCQDS3qMk6v2dot8MIuDxa79M9jHF/Utxj1Lc55RukhWkiJ37fiTUTzIAT3ZkY+sbtNnXN/qyL0mWXbaOFNJ2oY4EkGIdqWQgJXUkYORAwrITkKghSSERaFg+fqj3nuM4ibE6wXeMOi6gbHjN5uuwPVQPm2epORFwCM1YQ7uhtVJG3+goCWpQ2H60E+IAP2zZcV1b+d6zvs0+sik91G+ulyL/DiUpJb2+nGnECFDKB1NUTYtRUALWYqmjRerwvUibYhcKSAv7qFND787qZ6duDdqPNJeODWohNLNj67Rjw7gvG9soRb8Hf/qBgEKqgyUAAEAASURBVPSa/bXW2a6SqEOzF4kN8KijaMs5gOTIEFooNqSM2AyLOro2CyQFhO44v4I7ECwkWXzi7rC5H4VU8ah9dgQbfu5AQoEAFKLTNCilM6+35pFFRKDB2wXpmAni3mdoBUJKJgwdIaz0jHxbq63CIvtrom2XAikDJd+HpDcXEU5WR/jHIdiAbcdx5uprJ7uQhB9FUM5ZOk0bQLPhhqAYDtHZSQe4gjpf9x2Q5oBEsKGU6ki5YMPtiULKQUkqKenegOyPSikvCq5QAr3uYheHvJDD5bnuDbG2xCUKKYYZYlcGIMn9A9bU59gvVdiVIaijfKuOxwmMsChDd/MckF6966ZMDSm0Cmr77gtK173j6TpW3OxLYfWdAxNw6mDTNOnFEaAUwIS9E6FE3SFXDM9ASWksjwwLSuxhodUMSmmNoLRWKilAKaeSqCV52s4j4FIyqJmofrSp1fccAZ10I2xmg2zSnSHt4OBtg9RuaFocobNDaCOkNkX6/a1JlwhvHaTrT7s06PbDfilN9BPVZUJg8uGbe3MbfCOQNup6YuPYdD9SEv/OA5KCDUb0u9C2izBKgER9iWasAAarLca0eX1Gd/zS2zuxkBje7nOboP50HL63VLAhDo4ttyZpL0Q0fIUSdRFE1J6w6ugEPrFnOz9ipGfj96xHo3dtcve2rpJmaPHB0eOzse+iWpJicrUkBRQVE6opDIFKP1+ImuL39DfzBaP5gtG83oIRDVZ7dlTXbwGp29c2s3Mbm9q+hU1qo552LdRCqJk6fzcUkN57zZ65+Wqv82LboZCw+AFStOTo+u8gkhLCNQFA2QGMUEfMGygk34MkIP2jVkXfssHnlS0ebOo/V8EsB5IW2DuarP6MiYRCCkDSBjS9AeqoVY+n2FSE9ECDtwvK2XVYZxd7Oi5Ets/SG63sob+VzaSjhmWdRdvO7TnFvLMqKQckTc56M7ILGyCldSRNwqgkLMNzFG4g5VfmoF39vCVUArcdLSzaB5U/Yk/d98M88h2BhCIJwYYApLSOlIYbwkbZYN1l6klabWWtu/R48+1BSfCJEAqXYSMsH5LYs477gZUYj5jIAom6F0dqpOoIq65MsOp4jChBYMTZT4Qaqim8ERVSNtDw6TP3WrOXHrW29V7wU2FZabMfJYVSCqb2UkyMRDlp9QyYpmvCYtJiJR2hxHHV86g5aLUcElqCEuksJbLSyLBqS/Q9A0pu3SVQSq07AgQCkkfAARIwit0VUD9TkhZADp5M6yAB53tG2t8u04B1hr5WB3HGdwx9Hxu4bhWwaK66WdfHfiJqQXSQADJ0k/jW2x0JRgLSetofpUPfJ/35vuX36c+XtBLyjg3pBtkYavgJhVRYR8oCCcttwXQPNaxUDWmhNh+jXElD9v+yvjYyf+BjYIuG/rOJUjgzBgoIdGLXBuUl3vWbA/sChMIZSd28RjhBUW/Ou0IZtXzzPza6/Rc2savOTdL7AJWUvr55YMLKk2pK7Lxo6c3j3CMG8BKIOJRvjmA0RzDyIYU0p5daFekYilndv7YZUknTOiZHUbRsaiObNbRBKKT337Bnb71GDsuePo/QzR9bPqqjVBFlIaSFKhYdIMrC6Dq5HyR1I5Cww73uK2uczzfzDg1WqxynOqvmsx17kX7GQKqk3c3nnaoDsVQYZMKsLRsuRL738f1H2HWce0R3htIH7OIbVFFRno5TDYmVj8fA9YZgpeK2nVY01JLo+uBASlTSTwGp0LZzlQQUVSeiZ1ulYwBngFJNXQJNul2zVwkFgi1GtDoFUibYwD4gVNJftUk2VUnZelLGuvvfoBRCDiiiMII6Qk2htujojV1H6s+j9PqAlaSQCDPk1BExb+pGCYz04c0BSRaqLErUKZZdPpDusy9efdJPhR3UMth1NFMFSsXABJySMVWXjACl3KTlK2lNVEDJC+EJlGJkeMkQIsPJPpYESm7dpUopEwUnBi414htlBaTQSiiBkcDhPe1QPil8BCKg4+AJHb+zR1KEIyjCURTfJcdQcPyEHzsxPRw3gd3mjVMFJOBCI9j1AhLQYdCLr9hI/i+vk/n00HDVFdIchRqSlJ1vkF0YQw1Ev2OoIQk2+AbZJNzARtkifS2FxOZY4trsQ/pGyofuCgROqPcBJBrhdv7kDY03rcdn9dSl/RMb1iacfcTryFlIU/X7XKKseI05rG9UorB6Nf3A2rzznB/IOEqQG9+5pU0W1PKglCw8ZkbVBKAEnLyBUtbPZglAswSemdh+PqS09H0cHGU+Q0Di9NipnVvbpPZf2dhWTW1484Y2sNEH1uP91+3DB//lDgsLW46xoeYMkLLKKFVEGRAVwohgFHsZb6lW2jfDRiDdU+dMr9PizLB1hX1I1JBK7dgc+/MlEictMqmT5ae+wSo9dvmmflT2kF3Tc4+IewMjBpYdK54qx4RCO+GDSwSk1LZLgJQHJX6m2Hfs1sCbk81wwA0gpbadFBJAimcxlZMCI+5cRUdUYNEBJo6gAEjc7hUASZFz9iRcq6Td9VImMdgQ60jetcGhVC4HJXrclVBPurOkKHgJSun+FEghzICq4voAIJYh4Q5gWVwhKWFYkjpKFCCtkCKMUIYhxCEgKX14fY38hF3j5x7URPS8p+sGt/rMWC1zLAEr7ACmACdXTJrYJidjii4ZDiVNONOlluJKmkI4NQevJ2WVkorfvo8FKCnsgH23grYzWHexnoR1p8TdehJ3DiSFCwgZSH14jzvZc9hrbrVNF4zUOw6l48dNcNSEn5WUnI80W5d+eF/+4XzfzVHRX//nh/IJSPSfw2JD2XAsBoPDBAEMR2as02F0jLWCURi5g+nCAXX6Of/vhxBKTU1NznuiA7gUEsdRbAVI89WxQYGG2K2BQENuc6yAFKPfQMhHFkhzbZsO+NukwMJaRbWX6bwpegsS0yam363h295hA6Xb7r2XdHTIq77BmT1lqCaOm2Cz85A2jf04+oGy+Po2/9h6yKLjEEYOY+RQxr76/RFt1VtOQJrUrY2/xtMED0IOqKVig//TmJ6MabLipvVQyEJjanIZv5+h3wlD7xV+n//v1s6mCEgTAFLrzx1IAwSk7gVAIqjEZzwAKakZRXUUFZEuseiiTUfUGxhh17EplpNi6dIAkO6+qIo3SObzzUKYGhLhKsoHP9/ZeMc936ns4Xv0O0eRydqy6qhtEDsGBhQh4/HgdGegflTusL3cYsoppCMUQNjPAw/4t3VUh0pVkt5YwIhUHSPWlPg6BZJsKzzlXB0pdm0Ive0IN1BLYoWFdYc1iFJwIKnOVVY1JloMEWqIG3PzVJLewAFIIW13e81cwCFVSgCpxHpSCfuTBKUQBw8H+uUUElHv0ESV62XzHht0iaKXBKT08D0tAkLMO6ijQqsOGFE/IubOgYQA6eHr66QKqeFT9yju/agDqbdWyKyWWTUDpQmqIQQwFcKpnaDECEDKg5ImLK85aCUeoKTkHSEHh5LqCkpg+V4WhR042npZUlPyvmiEHDx1p3qSwg3rlLijtZAn2AQkOiFQ26ETOGcXcTQFdpufbRRBJMikJ8oCorm5487j8eek3dKjygULbLVNMwSj6eMEkgAijlvnQMF4Kiqn3voR3RzTnQwOH4zDD63Tz1erP196Oi4n4+p6N0UgJV2/6fgdG6wGICU1JO01Kg6kBEwCVdwcu0V1JPYi0V2BVB3qB9D0bFzPgYTKwXaj40abd5/35CTnWgX19IbDp8OHrzq0Wr/9nBFmYUM0hzJ++uwDbttxquw4AWmigIRK8tdYAEEtxTGlu36uMblbW5vUVe+Xzq18jO/UUpctzS8VuMD64//5XQA1HVUNjBhAi+vo0trGt9dx5m0+t2FfhOPMu9R7xT5IFBKhhur63F4sIFE/KrTr8iw6zQ84KRFEWHWoI9+DVP00T8py6jO1WhaALDypf7MxFren3A4g/bypVuaQ3euyj4iecaRVLtYkWUOTvLcN0hup3KG7WxkCDdp/VPbQPbzuERUSioaYtu9TOmxP1XfUtVfXEWpJbJRFuYQRoBTg5EBSIZM3ZwRSUEkFm2RPCiqJ9kDEz0/Z7ze+OfScE3VEhVRUKVl5wBRVRu0q2HYlqCS1EcJrTq27/1ZPku0WrLsSoHRJCDoQcohAyka9o11H/Qi7rhBI1I4CkOjoHfYd5afqUEdE3QOMqB+hBtkYSw0pD0hPh/pRR62QWTFzPs44TSBAKQumfDhpApKCmqSJiskqnbCYaFhFZ+tJ1BFUYygOJWpKQImaktrPoJQIORAHj/uTktZCMcnmHcGTPT5bZNP5WUkCEpabnwALjKR8/HjyBETfs+8nM1IYSbFsmT1JR5KrCamg8a2U0XqpGgeRVM5qqZ1vBKFVggxHd68UfFboXKcVOoyuSGO5jtVYrk7mDE7IXR6P++aUXP0+f79O1/etILeR85FQSA6kcARFHpAINACjCCRUUqFSSoBEsIHU3Ma5kz0pR12Itk50VyCq3emj131xgdr58tWnvC8hvQnZ8Mwlhy42f/lxB1CT5x/yVlF0d2/w1N32/iP/sA4fvOJW33AppLE6lHECMNHChBFfay5RToBmgoAzVrc9RjAZqb8Z3rqJDRcch8sqRGWN+rq5//94wITa0t/yHvEhIAEmh5qANb7DVzZaQBoqIPX99D3rXO9l+/Dhu3yvIJtjz9Uil8i3AykqIy4z6og0XU4VJa3HHEin5NWPsOpYANKaC4uejbH0vzzjaJoz77VDIf2ckVTqgF2rI3XPLyWYqKZBXYNODeF4h985bIh8AyQSb9Q8vPYhJcWGVqKclY4OdR467qKSABs927y2UwClVCHp/3lzEmwASjEoUVvX6b3tTs2oJNWS6ItVQQXSU/cP9aRqCjWcqlg4CgmrkRpNVEneLUJv1BhuYJMsSikHpZxS8sar2XqS7ADqQCUm77QiY2WWthaSZccxFR711qqNoATntNAqiA8KMI5AulL3LyTskjBDgTpKa0dJkCGqI8B7jupldPlmY2w2YcdkxGqa+gNAwv5hEP9lBDChlnKDXmcTUU8FE1VcRTPZROsuhhzmJIXvtKakulJOKbF5VlASkLDuVkkleScHqaTQhFX7fWSV+TEVstHCYX7a4yOF5MeOS4H4xlMB6bvYoieBkHdG0NdcUsPBNtsiaG3RRlVghIIBGsBjrVQR6iaCKEBI8NEpqcsEHMaSUQP8nCAOI+SkXI5p8Et9zSGFnJgLsADZaoFtHSpJamYTAARICiVwjDkH9OXOQ5rjnRiKASkDJfYhxY7fW6Ww2Ge0dobi34IfKTnsVSy57o3qeTgFIDV/+bEceGTLYsfxersS0kIEdVxf/Qs/euxOq/fwHR5s6Srbj7TeiHbNbKzCLeMFHUASoTSJ9wELFkAkYBF+AD5DWn5m/Zt9Yr0JVjR+33pr9BcgB+u6Ruq6xgharrZQWABJ9i7vE9QWab5Jus5x+p2RrZva4C8aWO9P61mHd160p2+52mtIlbUPifPOsOtQRzHOXaiMsjBCFTE4/yioozJqGVTeXB0JSHwG+YziiNDtmyPMCTSUPXTPHUD6OQOJ+04hkKIgdSRgQg0j7kOiy3c8cgIY0Ik6KiTOTSIVR9KOg/sqHPl7V1oEJLLWHQ1bGVerfpQHJL052YgbVRJ1KfY20YAxpu1iLQkLkZUWG2YZlRVyoKcbQEKR5asknU6bqSVRz/mvUMrWk34CSvHY8xgDd3UkSPHhAG5eP5KNgF0XgIR60xCQgjoC+iWrI45hz9aOsOscSIKvA+nIvezVu0Pku8GT6s7wwiNGdwaARGSYo8pJ2WXBND4FU6KaNEFNSAZwipNVqpRY+SbWXbHkXda+8/5oqinJugv7lJKNs7GTA/3uaMKqruDrFGwg5eanzMpW830+AtIWKaQthBJUN9pGTUiw8fCAFBIQchABAmAEiDQ4zRXVsmHmeFufwGiNYLRaG0pXSRWt1CS/YvxQWy614xCSAlos0CwQcOapTx8H2dFGiU3CU/U4mWCJv9N8llNXFyvFBsRWTdSBhNOkknQ7G+fIGhRE/ChzBRO+Uy0ItcOJsfFMJNoDuTICRNlRFOy67/W7sVs3dSTi32yCXahwg/egk7qlJoQdB5CavfSINRGIgNCnsuMaPn2PKyEg9MkTd9nHj99pHz72T1dGnwpQ2HvUm6gjjhRofEHCa68BTHitgRFWHjAalcBogAAChLAEv37vRVdo9EPke1J7QwVK3lcTpLqpQ5LS5PkCSg4kwRS1NVYKCYU1qLmur+G71v7tF+yJm66UQvqtd3xhf6EfI6HPgocWdLndelGiiiKMqB39Nca9a1f27Rj3a78fC0COn+CAvhBo+IMCVrvvANLPHUiKT/fjULzaqiNxDAUdAkja0cKHNxQ97Ertv5P62O3s8e5CIFFHqnjEb70L9TlqtEr33WDdyZbTGy8CyaGk74NlJ1WTACnGvyOQAF3oAJ6oJEXAY8CButbJ++4s++p3XtcCSEAUKAWVRLovbJJFpaCS4r6k/wYlV0t6k+e1F6od7btwXAVtgVBEEUhhI2w48wi7ji7jHvfWfYhA4nGTYPSot2CNLZqtHbk6EoRDmCGx62TVASMCDaGZ7H5GZ/Uba1byGpLXjwSktvVetH5KZFE/YmDblQSmVDWxQo6Wni7DZJWzdVBKrH7z4sJ9wx4lknc5+y5EwomDhy7Sfb0ZKy2GVgKleGQFx1XEk2YnKzAglUToYOP03LHhca+Pn9Aq+ACgqIhcFc0ViKRSNiUw+lbKaL2CAesEjDXaJPoNMFKUeqWUTZFgtExAWaoNo0vUwWCRADOPFj0CEV0rCHqgHpiQRwji2FujO3zpkJ6m1BlQ4m+4Hq533QwFJbAHdR+o/2yTwnGVJCDReduhJBjFk2NRQ8WHjo9IgTTT9yNxphF96JZPGBo2ySo5x6KChF07gQFrLgeknCKqr4XIJ0/caZ8ISEAJxUQtif1Hg1o28noUj4/XG4jEAZjGoaD1f+x9os6EAuLcrA4fvmItBUFqUU1feNjtwa/ff8l6N/3Q1VbYSqAakkAU+yLS6QM4sZABdGMAXKvGNlBKq0f9t63tm8/Z4zddngDp91ZLiyvUUZqgk3vgtSLqRfqsxJpRUEbaS5goI6Le4cgJGqqGMEN0KEjNMr9wmKcO59OCWC3HdgDp546jnXY6/dA9+mG3xToS0W82x1K7KQQSLW2iZRcVEioGWU6Nh8IiEhpf1607gcIVQgZMAImNcFcmdaTUtksUUgok2XbsSTpXct8DDm7dsVl3Tzt+rxC0AEgUNVFkJaoktRK64exS24eSVl6xtVAu6JBN3+XsO85N8o2yyXlJdHDAwmNPBMEI7LpbtFGPuPfVCnREIPH4setI1oWot56fuO8oL1mXqx3VTIGkc6JUQyLMwXHQN5+XAxI1hS4N3vKUFvtZOK68RDBpEkpVk+ya3OpZE5YmExRTtHaYYELh+79AaWBsMaSgg1RSru+dbC+OrFB9xk+bVe0mPf6ceDVQSlJsKZSo0xAekBVHos1tOQCQAREw2qDfcxgJSCTVAoxGBRhJ0ayQOlo+fogtVW1msWBEw1FgNHtQd98gzIRMgIB6DZuIu+q5YxNp/y/q+2GGPBd0RidssExHhLNfiNvhtFbqPpuVstuqGhBpOdSOA0lxbiLdAUgC0/I48sGEZcfvR5WEbUcLIDa7chw51t0UTfgsKPrrLCsUCur3S9WPUMLAieNF4uBnLRRo6Fz/TY+ND2rRyIYJaNSj0gUHqkivLZYt9h2Pn64QvFeG6XngzCwePylNLEEOeOSS26SeNeCrhv5+IhxDRN2PMdEmXC5RmexrcyDpPYX9N0xA6i+V1vVj3ffXnrHHbrjM548zj93b60dYdSFBR60o1+eSFJ0n6QqUETBCHd1+rk6IlV33rwsVZnC77iy37G7TqdC+B0nuDvUj+tiVPni3fj//GflX/ghKHbJrXVJy52ulgd3GaaXYRdhkdGrAjgsK6Tf6He030sTKCp99M1hr+MOEIIhmU2eiN96Fuo5g3amelKgXbCsm56iYOOoiqiSPQVPkFwwBUrTtON4cKAXrbj/vnYd1R/Lu5H13csuO27mkvDogcDtcPxFwveH/ojc4KokY+E8ppcKwA+cnFaolQg7FgCQfm58Fu07pOn1AOCCQuDcJwwikqI6yUW9XSKqX5fYe5cIM1PCiXcfCACBRRzr7T/vref6jvSbbjomj5ZvPOpCoHw3/uplvjiwJTK6aBCW38wrg5JaeQylXb4hQcqWkVXCxmpJvnM21GKIZq/e9y56jpIP9VkolrVJN5huppDVSL0SuiWETySYRt0GWG3WgjYpXUxMi0QZ4NmORJYrIVVGEkWyu9VIs64CR1NHqKTrYTipmpdrorJgIjKSONLkvUb0IIAEWNpCysgfI1Gl6NKrn9laL15/xsEAbqQsm9YGafFEPKAD+bqlUVgQSqbg8IKmOFIGE8gFIACfAKAFRUQGQBCo/ZA8oaWwV1Ojc4PUkPa6VU+hLN9QtPL/PUnOABfttCPBQNBwlzAAUWHMxCk7NKL7G4wUgrLUY+Qcm+UBq4f3u+FssuS7a99RMqujde2916GHXodKG6PoJyACi2AB27tCe+rqbzRwIlABSBw/HUJMCSNSi+jb50Dp/qBj6K0/Z9dUrOJCqHvsHu0JzRgRSVEMk6OJwZaTPqh+yqc+rw6haaVdHbtepXRD1o3svDu4EC0NqtXzuOf7GAw1H/G4HkH4JLCPYwAtaM6kjEVwg6UXkOgKJjbGnKthAZwRSYimQSikNJmCwzwA1RV2HAuMFpx0drDvBItSTsNRQRUExAaUskLK2HcGG2E2c++EqSRMy+6NoaVRF5wJx9AShBqxG1BgW4aUVsrUkAUl1HGpJJUJJb+YYdCgMO+RtoE1qS7QYQg1FhYQ6wjogeoqVEOPeAIlQRexU4XadQBnrR7EzQzHLzutHQSGVBCRsOwYdG26tVcWaPv+wBxq8u7fsl2EaWD4RTDTZdMWUqCZsmmDnZSw9TcCsmsdpQgFMKIR8pRTqSb5HSRaN15Q0YYcWQzptNmkxtED1JIeS9iZxjtLSEf2TI9AH2UrVklZJJRGtJn4dYtXaqCqVtF6hAUIJQGnDTE36UkDpQJVQK/IxwWs52GcolrX6u9VYdQKSH3KXAknqSECiv1tsqzNTVh2bgXkusKBosfTFK4+70kB1EArhQEOePyZxJtuFqjnRnofWPYQPXCFJ0WDZ+UmuGYUEZBxIAg6NUN2uA0bFhnra6Wc/yNJztaS/49wjNst68m5+6FW3Tt2+6VXHkRI8Djoz0BWcdkIoKODi/e+ShQUAAlwkKbn/NGll0CaK9lH8DCjxeyhj3gN0dQBo1Jzav/+yNXn8buspmw1os/l21uDuNkfw4dA/VKbfD13y9VwBHkDN0CnEgJ7r5z00kuvEAmwsC1DX+dXLT3hClzmhxkkHeIAJuw6bLquGbtDn0w/WFIwILzCiMrr1HB2yqXSs7z2qFe26kG6llssikxBVNUW+CTSwT7LUwbvuUEi/BCixoQz7C7uNljbUNQAAEz+bY9Ufyuj07cedZxRS7D+HpcZ+A7oqlNUbA1/3AtlSBCWw1NjjFLsVOJQSOEWF5EBK0nYebEhUkkegUQyopARKJACpIZU+cDePfXMbnu7TbQSVpHRbViX9BJQK60pBLWVsvEQtAZ0ckNiHVDWNngYgUT/KKSRaBqGSsvWjYNnlAg1BDYYQB8fG1xLs8yPf2JVSSK6SApB4Dm674EwHEoXsvs0+TlfKQ9s2+d/AJFsnhRMTWwKmkqFETSnZOKsJaGaf2B1cIYCkO3g8RykcmS0oKcXmUJJKKpJ1R9x6JVAivQaUpJJIxZGOi1DCigNKPqRI3J7TJaGC9fq/CCOUEQMYrdJeHoBEo9EiWXYoJICEQqITAkc6AKQJPdq4VYc6AkgtBKEvXnzUmj3zoHc8987nsqHmDdPpqvo7YMT1UuPBVtsgxcZZRoADgATLjhpSUEbFQaT9RytKHpwCy7lGAU451eRwQjXpNrgtzjuijx33hfZBEUrAgKaswAB4TNMCYbrUCv3suOT/Z/I1lpp+Z7JsNaARVRIqGSBRb6Lu1LzuQ/b+zVd4Oo7roIcex2Os5nmeMdahzPfYoHQVj6ozAgnYcZ0shgZ+2dB66jn+up5qYC8+5k2Z2a7BadDUj7DrUEcxPYcaolaUqiJZ6xFGWHW3KRkb7Lpy7kJg11G75cBMFoIcN0O9+kxtW6lw1N4+75Q6cJcdQPolAIk60tleRwrxb6wkJj/i1jRXLZ0AKYQIcpZdDB/4ZlrVnGg1hHLBAqxVmqMUqCeF9N5lelNGKEW1lAVSjH8HOyvYdkzUEUoc8BWtuyqyAejgUEG+MW/KOknN6lKpkVwtKaqkkpVSSWGHVC2ptpRtN0TQgQ8BqggYRSDl6kcCkj5AbIilhkSX8yyQPE0okBMIiRH3FEh6rkPsOwApPl4gzJ6wYNvlgMTr8r7ivqxuAdLgVo1SCwd7hzoJK35qCnmKqUA1eQhCcKKukAclrbjzlJJW2gFKsUN4hBLnKEkpqZ4UoNTLFipCvVgqaYmOq1iqWtJyoCRAOJQEDCLVRLPXyGoDSmsFJeLVJOYADwByCCUgyoORAMGxCxz3HYAkuy4Fkiy7CbLsNKFit2HZUZfBYmJCJryA3UWLHWA8R0dsdHvjOXu+3CHW8pG7bErHFjZPP4u1I2DA2UXrpdTovL1pQQKkRB1hu7k6QhVJ+TC8O4ODKOn0rXOMOMsojHAMefo9YHI4oZoKwCToRTsPMAGG5bIkvS42sp9DgcdGl2+gC6z4nssALkFJSi8oJUFJrx/NV4O6kprR+2CA6mZtXnvaPrn+Euv88tMeSpivhcQKXhcWArJMN86f4o8dOAH9qJTmDOnhdSQa93KdxMKpSVGL697wbWv95rP29gN/97mARWodtQzCrgvqKES5I4RcESWqKMKIzxEDdfTXGmXT7t7Brgs9JLHJ6cyCE0MPOwINZQ/b00odtGvdX8J8/Kt/DBQDz4x1JAGEYAOTIYf0eT87Nsfuu5Pk8UG+XyladmHPUKgj0UCRtB22XZmDd5eddoidX1oKQG+afCgF+w4oOZAEqmhpXYLaUX2K20/rK7LtmKSzKgnrjhQgR1Rw/Z7sS8INl1VUqq1SRiW5dZeBkgcdVFeSvVYIpe3ZeDRMBT4pkAQmbAOOmgiBhtC/DssuB6ST0kQhQMqqwDRRmDxOamY8l9Tk8oAkKAGkHJRCTenDJ+4xklBMstSQWPEyYm1hiFrM5IEpwgkoJYM+aoycnYda0i59WXiksyKUpmhHvqfvNAF5M1bsu775UAqH+8nmUbR6kWpJizW5LZF151CSSirSZtQAJXVIAEqswjX5rcEWE5Sw4dYJSighH8nXa3XpAQYBIsAoWHXYaau8fpRTSEVJHSnadigLFAMTMqt4AIxthQrCEiPe3ee9V+2VikfbJ1dfYJ3qPmLDP/vQJqsNDo9hudQW0e+SgJSnjooAUlREWQAlJ8euLLxMfkfNV4tBSTYeCgw1hlKi9x0qDbXGibKoFaDrw9VgaLwKrLApXcF4rSfYatSA4plLKMWReh/0UN2oyYN32HvX1rZW999h/T9+Sx0b2jjwON4ClbZNe62ALl9zMi3PNxt5se0AEmqM68UuHKWUIvFw2hZ1/lj1I4Hu0Rsv83mj6nF/8K7+AIl9RlEdBRAFRRRBhCpiOIzUlQF1hF3H5+suxb357KGOOJk5Rr6ZXwhSEWjQolrzwQ4g/SJgxsoi1JHU106BBIBDYZ2wAp0YaLBK+6AqileygZau4A6MRMGgXqgjkbYjJs4x29iABBz8CHJCDomKQSmxcZbkWRwpkKJtB5RUS0I5oJK8c0EyORNJZ58UoQvUGGGM1B5MIuBZlcRKinoSIYe0piQoFYYdsvuVIpiw8BiEHAg2hBqSFFICJH4GrOiVx99wfDqeOAqJOhJ7r2KtzB+jnru0VZJglA1xRJUUoHSIb1DOqqQIJi7/cVlNtZrRznw15iQtRaE7gCnAqWQwlVBnSlWTakyulgKUqCtloUTQwTfPyr6bpm4OhYf7pUppcIASG03ZgMpm06XakOodEQSAIu0PWjFeUJLFBpQIJRBOIDG3xsEkOGnyjWONQOQBBldGQR05jKZIHTEShcQKPlh3wxKVNCgNCEyXHefHcQhMFOb5u7WaZDdqjxNwnNGljTW4ro69c25Za3zLldbxyX9bv7detKEN6tnoZg1sWqdW3vW8SPef+7lR6gEFAzgcTES9XRkBJcGGkSqj7Xyd/F6J9l1JQJJKIpEHlLj/HEPB442qkBNoAa3XeaSUZqsORBqOJNw4wZgEXOd3X7Am9//N3r/uIntdE/27l51n7Z96wAY1/dB/l+tCEXIQIOqPARj5GbcL6Ll+6llYgpN6fu11J+qVbMilfoRq/0KR9WuTQAMtgwg0UD8Kdl2oFd2cqCIapqYgSmGEVYc6EpDUiuuftZL6kew6OutzBplHvhWSYn5h3qJl0GlyTHYcPfGLwNFOOxFsKH9krCOp2amUChBAiRBsKKNuDacKSBX0wvN/tL3JKph4jpED7PDdpZIUgpBSogsE9aRagkttoMSE7NDIwSh2MIg1lmhpZVVSVEiotlhL4r6dsv+ufnxxTonF6ydxF1TS1UrceeoOKCVqiaBDYdghqqU8MOmDgY3HBwObIHZqAEh87UASrAASe5BI/lBsva5qABIbgUOwQY+XTcAl2nayJ2VrpCpJQREeL10wOE7eoeT2nVomCUYMoNREhWM2U6KSsEuICwcw6QiARDWlYNIKFsU0NAlAuJ2n1TL1BA9AaFKJailn4SVQomBOzzKHUuwSnkBJE9MsTXyzVX+Yo3rNXNle81X4pgOCQ0nHLLAxlS4JbFRFlbDHh4j2SkGJ/UNACQtuNRtcARP1Cw2sIlRRqow0KUYYrcoACSiRiGOSduWjiRUFgcWEYvDJWfcPtUQtBDuOdBurfz+JVXCZrcfX/eVn7KXS+9i755W3z2683Nr8+w7r8szD1uP5J6y3/m9AvVdtaP13bQQqqu0XNrtXRw9xLNfmW2pkbNBlEy3hB643HVI9pPKi6uDngCxO+n7JPiX9PFtLwjLDskOhYNtFIPlj13OWBXA4niIHJGLZtAXqXf8ta/nMA/bZXbdYvctr2JvnV7RXzzzB3q9T09o88E/rrZ5zA5vX97oT14caJAHI/eP+BIUUeu9xG9iE1OXoOh7rR9jDvPeI0rd953lrpvocm+lj/YgNsdSPCDNQM7q5oFbkFt05iU3nyiioI4D0dz53F+hzR/3osrMFo+r2gFQSdh72PM2Vy7tdp/q1+l3+QqbjHQ+DZwDJG/YjhToSGzUJNrAZ1YEkyNDgNNhvx7qt5qt6t5nCJtasSjppn53cuqt20sEh5FBGqqcASqglAg9BIamtjoDFxlEUWNirE+or3JdsFDqqpIrq70b/Kldigt6F6fUTcCBmng+lqJa8vVBB2CFaeIVgIvjAXiXfmBfrSAmQYocGGrfyIQFINzqQpMb0AfT4t1aHrpIS2y7WyqJtRwumGHW/oPRhxaw7YA+UcmCitnSQ3XfdxUpKfWh9mn0UwKT9NYVginYeYBrcOhcVTu08TSYUpFMwYePJ2sqDUlfZd6oVhJ5o2Hc5KIWj0Dt7p4MApe4OJboizAdKAsIiraojlJZGKCVKKUIJ+y0Fk6DkKTpdkjjzmlEBjJiU48RMx4M4slBiRU8hnkmU2gpdEVAB1IZQOEy4of4z39VO0ahBNuLT96z3my/aR5eca29UOt4+vrS6fX7bNdbm/r9bx8fusa5PP2Tdnn3Uer7wpMZT1uuV/9jA916zwR+9ZUPqv2PDGr5nIxt/ZGO+/NQmtm1u07q20ZENHWyObE46qGNpYmeyeRe1SGTdwxOyyrDnqFVt0n2L9RvUCfcXiPI8AOSsMqT9EPBFIfH4SMGNbtfMOr7+rDW993b75ObL7f2ratlbNcvZ63o/vlz2IHunTg1r9+9/WKf/PGw9Zd+xSRhoYweSKOS5AUpbF89w25Dbxw7FFkRhorxQnOxtwq6LEXKOzmilwMijN12heWI3t/vrqD4aAw1EvLHqoioiRRfrRdGm4zOEVQeM+Myx/+jOC4MzgVX30JXV3Z3A3SBdy3yVs+t2rrtjJv8FPQOFth1NP9kDwwZZ3mAk7dj8eqHAgm1X+7Sj8orxTJiEDqglEffE5ovWHek8T95FKAk6USkBoxRIUhD5QAq2HUBCsdG9gBFVEt0LUGI1sfVciQE9Aa1gsyx97kjeuVrCTiuhrhQtvGJg0mZXgONedlJHwrpL9yBpFceHh31IbIwFSNefpT1Q3E5i27EROAY4Yquk2FA22nacFxNV0gVSSVh30b5DLWXB5HCSWnzn8XsUZ/7AekcwNZNiEpj6pYqpgay8aOdRY9pOnSkDJmpMTDQU/0PYgVg40WJtoFWqarLXlEqG0ixXShFKPR1KtO1ZmAelgT4h094nVUuamFE6gAnQeGhBk2+chIMySibjqI4SKKVwij9PlBITdYQSYEIdcRtMsNRnUCMECmIijjg2qT9ORB0hsPR//Tn77LrL7bWyR9mbVU4QpM6xpjdfaS3vvNW+fvBfAtS91kWWV9dnBClN7t2ffURq6nEHFcDq8dzj1l2j54tPWR9dV1/ZgP3eedkGfvCGDfr4bRsstTW8yUc2+qtGNqFdc5uqzttzB3ZTlwltKtbzgCry02JlYYbnIVqUsW6WwIjajsA/oWsr6/xGXWty9632sSzI9+qcZW/XKGdv6H34StlD7PXyJ1mjGy53GLXXfe/51vPet26s/g5g89ygxnhuODYdMHnaT0oVkBNBB1zUpQhJEBMPib3Q8aG9Oj6wWfuRGy7x+hEtxWioGgMNRLxRR14nShWRwgtSRQFEGRgpzBDrRxw1Qc9I1BGDgBGfZVwRt+u0IGX/4ykH7ADSLwhH4aGgkmLaDmuOJp/ErLHtSivYAGDosO22ndQItl3owSbgaNLM1ZJCOo/Nq9R5Kqv2hIoJUErsuwRKtCvyISsvTyH55tsAJG4j7YCtidiL/Cdqs+gJ+9mJf9AGWTobaB9VCj1dd+jgEFJ32Hc5tZRsnC2oK7mFl6ktRTBh4VFHolbkG2Rl1QGkuAfpDll2tA1y2446koIN1JHYIOsqSTD0dknUzEpQSXWoJel5jCrpwkQlAaU8MCVQoi9YqpiklL58q663gCFB5mBScZn0XQCTVBN1pq+inUeNqaDOlNh52b1MAUoKPKRQUtgBKKn47Y1ZZd9xhEVotqneZlIAMxR0oCccUJqt5B323Tyt2FFKEUqLEvuO1j6oBDorFGmyK9JKf4UsPKy3CCZUT6qCImy4jIpIX0dQFV5yHV5j0co+BgBY5TOx00eOSdetKdVJUEkBSgoZ6GvstRUKYUxp09yGCxwD39RpvILKZ9debm9oUn/t9IPsvfMqWsOra1nzv15rLe68zdpKcXR45G7r9Ph91kU1qK5PPeijmyy/OLrq6zAesa7/0RDAutZ91LoJYt0AmGzBXrqtAVJbI2SjTdHzDcgBKfcdO9Iv9TWAiLYkG2n7NXjHmj/4jwCi2lXtnZrl7S1N/q+VP9Je1WLo3fOqWqt/3mRt7/2btZNVhzpq/2ZdT9uxyEBFct1A0EMcsgu5DD33RnigAfuT9B7puvFanPDe4BBBVHm3hu94x4em6iBxkj6P5WXbV9OhfDRQjvUjknUEGHx/ESk6HxkY6TPm55Zl1BEOBOm6UDuq7h32qdWyt7H6ybLrjiDMsCcbYnfYdb84GukBkePPhhuw5KpJ9VRSWIH9SNSRTpdth/WGSgpACtHsbFcFaklnaA8CXnK07s4+UfUPh4aCDthrpxF0QClp8yww8vpKCQrJoZcc6S1A0lYnAglLseyhe+l4hv19xzZHGWfrSfE4DEIOHjkHTP9FLRWCCQuPOtLftSeJDwggoqddCiSBCq+b1kHBtlN6r1AlybZzlaQPaDiYUI9bq8f0cMIUSodbbT3nKCUOQCR55yOjlgB/GAFM/77+Ut9dz76Snk3e92gzm0DZ+AiY0jpTXgAiq5pk58nSizv/I5ioLYW6kqLhKoyzIva9SiTwsPASKLHxlF3707TvhdpFFkrEq7GRaOHDKp4JFihh/2AzMdkStU7BpEkRkGAfMQBLbgSFEL7X1xFIWFnJCBZfKP4HmIW6Etflyks1Ke+8oBoSxXtsO99HlKTkYsiAnxM/n6fju8c1VyeMj96xIfVetQGv1bW+gkejG6+yBldcZC8cvpO9WvqP9q5W9J9cUdOayK764o4brNXdtzuk2j+keL5i5Z2kSIBV5yf+bZ0fv9+/5vs4Oj52n3V49B5rr9FBP+8o5dX5ucfs/2PvzcPmqsp0fRBUEMSBIcwgEBAImSEhTAkiIKPIqNLaDoADMg/KGJnCDGEmCYRBhgRIIAgyCEFmGUXUxoEWZ/TY/TunT/e5ftfp7muf537f9a699q6q70uUxG5Sf+yrvqlqV+2qb93red5nveshRdOfkI34qtKPwJ3gQgQYfq6OGU/ddHV1xylHV9MUxpi669bVpaoRXaTJ0Plj16nO3my16pyRH66u3X+P6g6pOmCEspvLec4UBK+5QHXFmbLf5lpsPID0L1qcizLilvod8CPBR5ihoY4IM8y6zmzj2CRw6vFfsknrlprATlIPyqgfka4zu47JXQGirIxKGJk6Gp3Tdaw9wq7j4H+OYBIuCNvmjF5LYYbVCTP01x+9HXm01IdXWWoi+x5tN5Q9klAy65pFxrqfMbLhWI+ERVbbdknBaMCM4MEkrZOhlmSRcSX02LqCzf1YMEtnhVrJ6PFl+1GTsq0vSiBpsO7WzSCrpIZt9z6l/z5gK7bZOdLrSVoDVdST9hqrbglpjVKplvbFUiP00MXGOwi1pIOQArMyS/zssqXFvwk0EAMHUFh5pPCwGMy2S3UkVBK++YETpMiA4Dh1qZBKKrfdqKGk65ChhFpKUDI4rZng1NvG+9qBe9iusbR9YRfRh2YKTNpOIMCU60y3lHWmpp33hOy8p1RnivpS1JbockA0nKatxMKts4OglC082TcllF5Tp4Doe0Z37ddl8wSU3tB6GZJaDHC/ZXBVIAAoYa0BJQY/1JIrAU/OBaBqMAlSKCWAlEEke0+DZ8fB7wtwoQAA0r/+Ukk54s1SQ4QKUEYGoz/FotVf6uf/aAth/4eU3E/vVQPRmVdXz10ztfr+lRdVT186pXrigjOq70nVPKLQw4xP7VvNkIK6aPzo6ozVl6qmbL5CdYkmMlftsX01Y/9dq5mKQd/yxU9Wt3/p76rZX/n76s6vfb66S3UpalN3KTzhx6H2/R1HfMFvBZBZ+rtZimbfJYjNE0QeuPjM6uGp6sZ97qnV7bJrr5E9dunOW1UX6zN3wfgNq3NHr1VN2Wz96swtN62maaJyJ+cSHOfoMe4WjOYcJ0BKmc29WBaiJixMOujqwHvCNef6YdtxULeiJgcAsfRYDAu8LOqtzwMBGdQ3C47Z5ZaGsMdqXRPWPnVnNuQLu44ww2eY2BUwIklHvSirIoGIdUf8HzHBs8XohBlk16GQ2H+MSSH/vzghW663kq09Gj6kb9e9LWEULwqVNE5RSuw6oED9xnYs1YeMvnabKqzwEXUVQN3w+4grx/oZbLuJmh1RS2JhHCoJ624zgYwFbA4NLQLVh8qhVyslwGQ1pAaQgB7WoCuxCDdQ36KVDs9NMySbMRGgmKTnna27VE+i5xUyP6BkiqmXjdeqL6GY/s7qSL4mAtuOmVoAiX+c0rYDXlgTqKQMJYGP7dutqWzLuquhtE4V9l1YeIApK6aw8pJasvpSUVs675jDbCsKWuGwt86D17fB1AxAeJ2pbefVNaZn1PkhQ8nUUllX6m7hsTaFAY7tHbJaEpRocEonbQY2gxJqSVBixu9qSVDSwM/W3nRcMDBpgOwNphpI2HAMpJ7KUzJPA6kfWkjL16qB+O+1EPenWuwKkGRHRfG+Vkm+wBU4/SeH6kv/rrQZxX0W6LIH1I/u0P5AN1xTvTBDO/ReO7V67qqLq2cvv6B6SrUhA5RCDvOloB5R7ejOIw4VFD5RTTtg7+r8rcdUp79jKYPVOZstV12kScrlO4+rrtpt22q6QgfXK6Ay81N7VTco3XfDwR9XrWqf6qbP7lfdoNvr9fMZqgldq7+7au9J1RUKWlykz9YFSnKevem7qjM2WKY6Z/MNqjNGbVpd84ldq9sP+bQpormyEeeh0GTRASNSdbMFpFlnnlCxdxL9+7DdWEBLfQjrFIVpUXuBG5BjC9JCiAXGdIiwhbDf9m4PqGpU+H3XKsxw0enWC+/DGhsYI/i/L+061JFbdUAojhJGBBkEJMHoCwpgHKLedRZm2IPeddsZjNhyAvsc14M1jmPW1tgit2aY7Dom0jF+9W/fZlegVkl0AGeBah1uGC3FwwyImpDbdut31JGob5hKUn1ngikr33UW6456EpYgIQeUzEcFmgaUANJoYuXATgtepaBsR1VsO6kFCzfovhZsEPhI222zIa3nV9A2xtrqW6kbPqyoMKw7VnKjwAg58EHeU1BqqCWsvC423v7Ul4oaE7Zd1JHcthtvUAJOAMlUEradrAfi3xRuSyh5wMFrSdm6o56k17rXaLVrEoCx78zCQykltQSYHE4CU6gms/Hq+lIEHgg93HDOydbF+jsacNgniV53qCbsPLYayAGIbOd5w872eqYnZcU0LDzFw3NdSXFiU0uy8F6+3zcCZKBiJ1rbGh0LT4MX2z2wXsXUkmoPGUpYeFJK1CR+rVg46TBCB8S0iRajlhgIAVOtloBTUkxm4zUtuwwkg5HCAAoCWCBAAPJbvtf6JtlwdfcFpcmw7ZJKcuuugJKAhHoCWCgp1uSweBcw/WSOtou/5boMpxemXVY9f40i4VJPz15+vimoJy88s3r8vG9KRQlSZ59cPSol9YhsuDuPPKy642uHVNd+cp/qmv33qq7+xO7VOVJW5241qjpvy5HVyUstVZ26zFLVae/WrSzyU1ddpjp55aWq88YNr6boOGf8iOqM8cMtLTfjoL2rWYd+2o7ZX/pMNeeIL1ZzpYbuEYDupaalY64mKnfoZ7fpd7eedIS19qHWyPuLDcv7w+QAIKE4PWb/vF173hf62gGtCDKgmFHR1CWZ9NjaI8IMUoEfVv2IMWL7jd5vdh27wH5S/0f8L5hVV6iiUhmhivxQY2Ml6/ifYsJHrTaAxP8aLbmw+idsuIo5Lmw3wZjyNhuC+y+nfQVcJa0kaKxhQLBwAwO/vGHfsG/pAkjr5GCDqySPJVviTvfxjfW8/gSUWC9AayGgEVDCAgRwu2uARiVZaKKhkjz+jUqKtB11JHaOtYar2pphhKQ7jwuYwror60kZSkktsY6BaHg3tRRrl8LKQyVFHYlGq/yzuEoaZ7bdNw85qDrrywdXN6jL8Xdvvqa6Ue33Z+rr6876enXqFw5I1p1Sd0XAgRkk9SSDkl5rG0qopTgaYCrrS1FbSkrp8AN2q+695gLrYM3WFMyEu4HJAhCpztSw81IAooyL97bwWik8Ag+CEq16sHYoftNPrbTwmGlTi6AQT+84oOQWXgtKqKVk4aGWsmKK+lKCktlxKCSi4lJC/wyIDEbAR10eBKD6FivqFauNeOHe2wEBG6DzHwIQysjtOxRSZ1sfoETnbxbI/kZdzl+bN9ug9OL1Sstdd2X1opQTcHpB6un5qy+pnhOgvi8F9YzqT09LRT150VmmpB4/T4GCKaeb5ffY2adU8xWaQFkBrYcVeHiI9U+nHFM9cPLR1QMnHV19R0GJ73zjSB1HVfep3vTt4w+v7tUW4YAHFTTvmC83IHQfdSiD0ZeqOwSiWw7/fDVTi2JnTVF4QpMU1g2hfplIsK4IpQqQsEW5pijTet3R/R7zpivDPO2lpPsRjAl1xDYZbIdxlD57AImF9NQ/S7su1JHVjDRps1g3twWIUEZYdbgNUas9Ys9tDUg0M6aVF/+rO22OXadNQVVaGK7/+X66rj16vw2/L1USCgUQoEaitx3hBvZPQn2EbWeLOTVAWrfqQiURcGCRHB0cSOBg3xGMQM2YvSalZN0cqCdlKHVRSRqIA0hh2+0gILFX0AQBCQkPkOg2DpRYNLcTj63nST2JdQsszM1gaqmlDKYcekj1pVRjwi5o1JFk290o6Dx2+wxLH5FAYvElAy4bwtGs8sePaKW8VAT/xFefdmx16Qlf8V1zlXyKelKGkmAMlPZUzNjVUg0ks/JGuFraLZSSrke0G6rtu9Wrs1R3mHf1eYOCyQIQVmcqYuOx0FYDFotsWWDbCDzoddAfb2C1pC3SI/DwXdSSUniy8Ewt6ZpwbUwtCUpYeCS8oq7kFl6hlGThZTAlC89qSgYkryWRsAsgZRhJGUUtxG9fyTBic7wAEnUk0nYGJKkhVFJAqQZSoZTUUocwBGuFSOph/72pmPbPH5hbvXL7DdWLN15bPT9ddt70ywUmHdeinBKcZO99/4oLzeJ7Zup51TOXOqSeuvjs6skLz6qevOBMgxXW3xOKiT9+7unVY6pRASvqVA9PPrF6WGugOB5SSu47gEqAul+gAkB26OtvK0AxT8GFuQLVbNWhbv7yZ6rrDv/76lZZdawVYgJC/B+lw/vEZ5brznWOJB91Paw6Yt5tqw5lNV+1SJQ36ujWc0+y7uk0X8ayI8zEJIt0HYthG+oow6hWRPxPASI/fC8y7LrY+yh2ZaaWS3IWB4S1hxZmWE123QeXmvw2HIL7L6l9BUwlrf8+UyTYZdhkRMCZAdFDjkG/tO2w06KO5OtkohkqW0a81+5HKGKT9/rmenyoaB1va5RaUDLbTh9qOkIAvF2lFtgc0OtIzUWypACpIxG8GL7au8wSBEo8dllPAkqkcxxMycJrqKWIiNcLalnvEMEHQg6EFrDnbpICwsbgH/YNDahlPYSaCP/gDLLUTfg72v8zkKM8GBCuOOnI6oqTj+oKJdZuAKU9k4VHcZijVEtlbYlo+NGqMxyhGepR3B64ezX9jBNsO+x5VwGm8zsVU6PO1LLz9PweTYtssWVCLfUKPDBr7hoPz2rpbldLLQsv4G1QCgtP1pFDqU7hZQvvFSklg1Jh3Wk2b5HvqCNldeSFeRRRqCKsOg4SZACJxaest7EO3lJJ2HMGJKBk6sgVEj/L3RR+J/tOAANK1KB4HKCEOqMTxevflbWlOtMLN15TPSe1ZHDCzkMxydJ7DtUEmFBOBqfzpZ4CTlOqpy4+p3rqIgcUYHpcYPreeZOrx6hNCU7Ez797xtcNTg+x7klK6gEpqe9ISd0HjFBGgtEcKafbpYpuUoeGG447TPsTnVSRhEMZ02oK1ct7xgJXJlDYpgCJg+vN5xkVy2f3Fb2PWHtMQrjf47dPt7AM+0iFOjpaNS6ARHsx1h/FYljSdSyEjc7dEVpADYUiKmFE7cjsOvWu864ovs3LobLwcC3crlu5Grnm8qaO+nZde9R+G39vKmnN5cwWAwZYZda5QQVL1A4fBlQS9pqrqLJbtUeSG7u9poADH9yNBSWvJ61k21404+AoL7fv2rUkqyMpUIGFGLuqskgWlbTthh80lUQreupUNZQIUAA0wBZQ6g4mQg9tGy9i4tSUTvrsPtVjqq/wzwpwLLpMQkyDpRfgvRD/5it0nVY/Nf6x9Q9PTYV/alr2MMCzdoNZJgM+0dm5V11QXTP5uOoqVJTSU8ersO1qSXDKYEI5rVMddeBu1Te0/uW+GVOrB264snpV9hgH5/CtCVR81iDCdhRUNj35AABAAElEQVSk7dii2sCkAYmdSClCs1tqLzuPOlNExnmO2DsUwLFpslqKrS4E2ToenpJ4ep1lbYlZ+KsPYeEVaukxxcNRS2HhqU4RdSUK7AGluq7UVkoeDbfkHVDKQPJtE7DqUEZEl2sQBYwEJKXsDEiCCnDJtl0HlIATQKpV0r+3oEQbomjxQ4cJwPRLdUH/8T3aLvwmDf4C0dOC0DMEIOIQkJ4FSFfIzlPN6Rl1e3jabD2Hkll71KAEJQOS1BJAesSAJLWkWtSDAtIDrG06+RiDEdHyu2XTEV64Rem6W449rLr59KPVPeF0e//5LPB+8nlDsfN55PPCZ5nPKaESa0EkOGGnkqrDfuXviP+zHID7soyA2uTdV7g6uv70I63xMuqIBfQ76v8RIFE/+rQmcdh13pvOAwslgKgXxXGIvmayZ3bdblpaoSSrL0CfYHY5/5dY/Px/E2Zg7dHmK/fj3m9jBHW+tFIlsTkfdRvsMTqAAxZqP9GMlbRd27azxN0mq+QY+Jg1pK5WdpXEB3i4PlTjpMJiYSs70lrIIew7wQ44ET8vVVIZ/+Y5RSshFNywVZcVmLSrrB7XoLSJR82pJ2HfEXRoqiWCFKyDGiD0oODDVacfa/+kWEz84wIhWr/guZP0ir5rURTGWmK2Cbiw84AG63mAErYH/9xYJ8w6GSAY2NkhFCuF2agd6et71JMMaN077RIb7NnnhmI0KoN2LjGYv/HsI6bY+JltTqc6Duck1MAA0gbTQHUmi4x3UUseeOgSD9dzDrUU65Ze1uJO1GFdW5Ja0iBILzS38HgNZV3Jww5AKcIO7G/Edfx9Yd8Z/HV9iSX7Atpk272WgJQtOwcSNp0ro6SOBBHrSBBAKmw7qyUJQrVaCih5/7kIOZRK6d9k36GWrDO3whOELFBudKN4Qw1nX1MXhpdvn1k9O+Py6kmB6AnB50kpo6fikH335KVTqidJ68nCe0IWnsFICukxwehRYKRgxMNnqmWREnwPyrZjwe19ghFrm+4RjOYcK4tOybpZJ3y1uu30Y6pbZNGhYFBGvP8slMaC5fPGZ4v4NgqI0EJca275fPPZ4TPGxILP4zNzbrTJCBMpwMZjkqy7UbvNHiN1tJnGApwPrHkmUNbdO+w6BRmoGbkicgBRJ+o8pI7USNXtOoAUHfXHW99JrHZStKO0hIQwgzrL9O26ziH77f2TUiUBC2w7Om2zcd+wlZe2Gs2uggcWGyqqm20XwGAH2vHrqfecoEQNaqg+wLQiou0Hqb12HJzHtZoSUMJu0/eWuAN8sgc93MAiWVoJEQGXSuK5WX+75QxKwI5EDh9kV2GCksC0IGqpDD2ce8TnrA7CzB1bAxABISKyRIltNi7rxmbkuv1fKqhj4zCDt+KwZpy07GdgJqEGfICQ1WP0D2+W132++JQZKQeDOgM87Vn4O5vRCjDUYJjB/vr5+Vmh8ZxQZRy+jbd2GxUIsRQBAI/1pCCIzeKK6VzVmc4fpM7ki2zpl2edH3qpJQ1w5WJaBrAAk61b0qDmu5oCJqklgTnUUoaSXlMddkhQ0vNngLRYuCYA3aAE9EuVlIMNgoKrpDaQfuTqqAEkryN1V0k1mEIllck76/mGfadaFIAzC0+2IOcmcs5khaQg6uM3ShTSFf0n991RvTzrhur76nn31DWXVE9KIT1+yZTqe7LqvnfRWdVjqiU9JmU0Xwm9RwWjRwSj7yr4AIxoTfSAujvcf+rx1bcFo3my6e6WTTeHQy2M7jrjxGr2OSdVbM1OfYeaETBC1aDMmQg9o72hWFfGZ5HPJJMXPivUjNhfiUkOEwYCD7yPvLcoY5Qy6TwSnHdN9Z13rz/9KIOR1Y9UH8aa32esd/dm7RHrjkjT+dqi7hDCpuMwdbSLB4aoH6GQaM/FGj+sczr6s/eRqyONIavacpLJb+8RuP/qOq4AKmm8BvZQJTtIkvPBo3PDOIHEww0Ag8HeYdGuJeUYuPxl1iiwVoFZFdbdpoLTSEGKQAJBBNY4xRoloESdCpXUqCWZGmvWkizgICCRuhslq5HgBEqJ/VJY1V1DSeAUlEwtSTHVNp6HHlBLZUT8Kx/f0WogAODNVxSN1SBD8RwI0YySppj/hgXEIKeDWx+Y2MfGNzf7zQuPyRqRdad/dAYCB47Aw0JTDdgWm5Y9gkXCwd8wiL+UIEXklsGbegsDNABiMOa5lOrMZ+beCbpUZ9yfJpr4/3RlnqvBiu0r7rlSYKLOdHVh500vk3lRX4o1TL6wtlFb0mDFrDtDSfBkBo7NY1taCIa8Xl5nrZZqKLHrKfYQs3IAioUUii+U0m+1gBaw85p47X/Q+2D1JF2DrJI0QbD4NypJ70+eKCTbLmpHZteVQErBhoUFUigloGQ1JaD0q5/Y++8W3iv2HIAkaon3i+eOzUsrJZrRvqZGtT+ce0v14m3XV89ed0X1pFoVfU/23WOXavNFWXb0wHtYUHp4yqnVg4LSA4LS/VJI98myu+/Mb1T3aXO9+y+YXN13yZnVvEvPrO7Ve8l7St0QSzaUEe87ExIWszLBYYLC5wyVzeeSCQ6fLa4/n7OYOKHmgRGWLTYuVt09V51rW7/feMaxVdSOABIH7YLozoBdx9ojUnVNGDl8DEAJQoemW2pHqCN611E/AkqkWWlYjJWe7TpNYEnqsq6xY7Dq/+DtfwVKlQSU2FI7tqWgt51Hq72W5MGDspbk24+jkiIGDsyQ9gQciInSi24z2Xh0iMBi8zVKQKlO3xmULJQQKgk1lvZJUuTZVZI6RKSAA2uTgJxBaZ0VM5TowxdxcxbPZjCNaNt4dejh+imn2MyRTgKkuZj9OogShDQIURwnEvz//0aHbvkeMKGYGCQZiBhcSZdhkzh4VPvRoBAWFj9nMLBN1aRqbPtp1IS+xvJjFsuAjCJgkCPO3KyTSA1InfFzbEOzDDWIM9jwmC9pjyPAQR2BgeVODWA9wTStrjHldUxWW+qiljTzzrWlEkyCEmrJuzwQEQ8oqcuDgMtrp6huKTy9dl+v1ILS9xUL13WzmpIG8hJKTA6w7nidQAk4d68l1SqJyQOTBZs8SNEQTOD9imCDpe1ia4g3a3VU1pFCIQWQsO4aUNLj1pOSH9p7xBqoDCY9V54324WjnJhg0FbpF4LDPzxwV/XK3bdWL91xY/X8LdOrZ26Qirru8uqJ6VOrx6dfqmNq9b0Zavx6nY6ZV1SP3Xhl9ZisOIIyvKd2KLDCe0anDmw6YEKnd2qKocj5LHDtUUhACHUaMELBMoHgb7kfaUsUFh1AqEHeeYm2mDjnxOq60440CBmMsN+1Rc0uGh+oH7EZH+k61BE1I+w5FFCvA6uObSZs0bmAxJIKwMQSC7YqJx1LSIm+dcOHyK7T2qx+uu7tz56er7BUSdh22GPs2LqFZDM7zWKDAY12B/CdNncgUUtylbSybfqHdUdHcKw7VFIsmiV5h5ppQEmx87DvSusu1Jhbd95wNWLgAJOIOjMp1iuMBUpSczw27YtQYiWYutl4/BMQMOCf9g8/eNLAghXH7JcBJw9mGpBsdv07X89ie9/8znf95O+ABhAh5PCGBljbAlqKgAGYzeNQBpE4s8i4oEVknN9zy99TdHYg0hy0fg7/5w2vhWAXcfhA6HvoMAAy8DGYU6cBACgXalcPCy73yc6Zc9lZdrD7LDWmhmKSvUeNCYuGgY5FkL641tXSfA1S1BRIbTED95qY98Tr7PLgtmTUlrKFl6AEdIGmQyktog2lZHbSYFBq1ZL02m1NUkctqQYSdR/i29htFmyI95E1SQo32JGgRF2pbdkBJH+vf25AAmoxGQmlBPyoX1FbYiIDmKK+xGci9m+iPgZsUdIAOLYm/4V6Af5UPetQkbZlOMpZdTm2B+G9ZIJBHZKFzSgYAinWMkrWGhMPg5EUToaR7oM9zPUPIBEuYcLD55yfUffjsZ/SY3N/Epe87yguPie3nX+yxbxZdxQwYjkHaxSjfkTcm8Xh1I4MRkkF1UBiMbkvKOfWgMT6PqXrANFXpYyAE+uUaIqMm8HeakS9t1jtnZrA9hfD9hysl4RfMBsZtea7lWZb1RJuJNu20aA/du3lrZlitOohpl23+XGlFOuSvKVQvdsr1h2pHD7U1JNYn8TMB3jEOqK2fWdA6hFwyCop1ZIIOIxei8Vz70xQeq/Vqrybg+pOLSi5WmrWl/DQgQGDB8oDGDHw26xaA1is8mew8iJ4LKZU2xkBioEOO4+BiJn8717SvjUMOIo5o1yyNcWgawehhEfsd1goAAygBIxQXKTDUGLMygGh1THU3oZz2YCoQZaBEBBi51FT4jwoEYBAHcGTUlNl151rfcioCQCnDjBpRmypPA1GLLDtqpY0YHlH8bRuScAbKCJuey0lCw+r0tYsJSVYQynVlFTfsGs0IJSii0Nal9S27vS+hZKMNUiAm+sIOEzd6trF9TSVFEDitgWjUiE1gKT3I6w7Jiv1BAEoebNSngdWIpZiKKYmmKSYpASpnfE54DPAZAVLk2uDasZ+BSi8lwElEpC8B7yvqCImCmbTBYxkvUUakvsFkPhMmCqXQuWxsVT5zAM6ak48FpMX3nss3tkXaRHsWcdX5x/x2YY6YlKJ8/GJLb27Ny2zqB9h1zXVUYCohpEBaRcppAQkbDrrgKLvP7395gobqbO3/leZrJo6EpD66mhJoM4gr1Ehhvm06JkohREqibU/I4Ysqz2T3m91H6v5qO6DeoltKagnsfMp97EYOH3uBDPaCmHdjZDUJ3Fn9SRBCYBstd5KJtHbLYZCKUXAoa2SsBPDtrNzACWtm9pitWXUamR5i4wy0wJK1JQmapHdsZ/ZtzpOfcMuP/WY6upvnlDNm3Zxda/sEYq4DAQoGwYPBjODkQYvbJoYuACRr+5nC2s15+T44xsGKP4GSDAgRT0J2+23L6pVjqwaboEU5+BglmzdnPmdDr63HmOy4IARAx0DZ5w7ZvJ8b4NjDIoGpVdt8AOEQI1ZMAAgTEENiIWxKCAGmjlTzzIr5i7ZeHztYEo1pqgv9VJLmpkzEDbVUsvGU0qL2gUDqNWWNEu3vZaKupJ1d0hKKZSjBR00KAeUgHmzzVCXetKg1l2tkng/s9JN72tZS4rr27616x3XXJOC0rZrqCQ9vqvWgFKoJVoaOZSwgbEb6UiOorU6k9533rM3BOJ/1MSF64CSRsUAEWL0QAW1w/uJtQZAfDt7XzuGjWrKKMEo26cJSGYXC0KoU649nw0ej7oRaheFBYxQx9QY77zkm7bfEUGGr+yzs/W0pK8l/7sopO1kk0f9iLg3+xyRrPPAgqsg6kR2ZHXkybqoHwEiDuBEmGE/WX+x9mi4LHiLevfDDIOM1EvQr7HuSK6xDohkm1lj665gaTnrirCF+rDJusuLWNuLZQWl2FyP5qvMqrDu6I/HhxqlRD2J5B3n8SCCd1yIvncBvWYM3NcmAb38+Ao4UEsipg6Qjjh43+ruay+u5gk2354x1QruDI7MCDn4ZyQBZ4fNPm+xGSqDBDNb7DEGmyaMvEt09adfVdX/4Ph1OrS3jsAErPh7Bj3qTkCJmDKPCWjsVl9bHUTgiO/fTL/j59SDgBGDJ4/F4BgAjO0SvMZR9F3T4MrfswbHaliCILNtZsHUdBhwsHiY+RJqQB3ddekZFhOmRmBgMsXk4YccfLhWa5h6qqWr8uy8M/RAuqvendYHR9/WIrqHU0i3BB5QoqaUgw7elDV3dNBAXUOpbjHEteN6oTgi7PFPhXXXTN0JSmktkqskt+1KlWTQj3pSqZj0dQAJeNmh94X7ZpWqz0l0czAg6VzUr1wpBZTcwiONB5ToXg6UCGuUUEI5A2Ss24AS7yMAQe0Aeuw13lOgxK3BSD8DVkwCcvKRPoS6DwET6nioLcCEMorH4r5MLoj9AyPqRnw+bjv/lOoGCzLs0YARQMLlaNSPFGhg7RH1I7fpWkACTAal+PlWBiFCDcCIvcfojELSdcfN1lJyVoveU9S7H2ZYgoAz2EuVrTZxhBTMNlqEaipJIQIGfAIE49ZfyWLg1pC1i0oy6w6lRMBBlt/2QwUMS91pryVZd1FPQimxxQXbpW+9wQdsQ8C6m4M3YwVGdqi+hEXYjoHbuiRZd1dN1iZoKv4ym+QfOA6+7zz892w+xj8j/6TMUhnQTR3J3qHzsw1UGpSsxYygk0H0Z8Hoz7+pD8EJYAAQBisAweNg2dggpMet1y7RlTptn4DlpIPvAVjYdNQoeCzbTK4An6kyU2RsmZCgxOCoQZHBEKuRgRp1wQybwYgBjBkwFhxRcMINqKLZWrfC+hLWrxiYzMpTfUm/t/qSWhLZ4tppPWpLgpzZRnpsqy3dFu2HimatpVoSHKNRK+/H4FBKve8SlGKNEgN4CfHG2iRBqSN1p/fB05FYd15L4noBlAwlLYAN8ND1m2sb1zd+HkDiPm0gZdtOE5mGStK5eU/NvtN7k+07vecOpWfttbiSTvZdVkpu36FqXlEAwiAi4FgtSSqpDJcAo7Dp8qQrAYlQg3/+77TbeBzsXN434t10jMeu5bMx68LTzaqbceoR1YbLCUBJGQEjDjbvpMPIvlttmNsFtetHACgrJAHJa0gBJLfsgBEAY8NLGql+bNT65mbEJnybE2Z4f79V0GDj9BL1e68nqYPD0FU8cSclQsBh0w+8Q8pJdSMBIltqJOWSSmpHwUndsaYJ6479U7DuIgpehxyWtzi476OUetPp8aMLee4EXiTuaJ/zbaWQmG3bAkwNwh4QiCCBkmyagfM7O2SBxC3rY/hHZYbP3zDQYa1Qkyn3z3GbroSRQPRPcfzWvwZOUk2oGQYwBjugZDNlKRcGpXywhon1S1JihBbYqZPvmVEzmHHf/9CgaDBqgC8pMik0twlrKDFAmjLTAAhUsf+wfhj0mVVjSWLb0bUB2EQNadaFp1ms18H0TaXxpJgKG6+3WkqbA2owe/Tm7mrJZ+61WjILb0GglBbPovIo+KMaYjFnJ5Sii4O3FSr73JXJxLKexPtSWncBpbDvAkDlbcAo7DomK6VCMiBpEgPwMpBMJXkLozroUE9QLB5O2KFUSaTwNJlAJfH+oRwdSEnVCEioT6BkB2m6BKNQRgEkbs0JkEoiSefLD1SLklPgdSPFu/XeMVEBRmxLzuSErcmx6o7Yf7dqo+UdQgGjoSsq0CCXA7uOBbG0C/qs1E27flTCqLTtSlABI1QV9SdrpDpsbUvIDh/iC2HVSLUf9V6iaLOAL5YdGscKIpNkkZFsswCBFI3ZeVpH5DvCsleS958LKJGIK0MO3mHBe92FdcfsC+vOQw7vsHZAJPno5gDwsAa9o8PavlCWHneqWdFJ4kq13gFEJIca61kUDnhDAxn/1Axq/I6YKzFsu9XXLDgFTNRVnp1zs7X8wVbD6mFAQaFEiAF15EpFNh2AMBgBIh3/nG75WYISAGMw4zHMItJAxSDoh8+gOQcBCODHwff8nkGO+wI2swTLc9k5ekBJdpJDUEk/vQYGOa4Bgxnrg7B2UIJh28297OxqjlQSAYebzj6xuv2CUxOYJld3qH4QNt6AamlmkcS7qYtamlXXlrKFpwE1BkoGSCYEFguPoEOy76KjQ1coCbaxRulNvWe+VUVK3kXIAaWkyUUTSr3rSQYlQT2DR9czQgzlz/g7O/Q+dQApvccGpPTelrYd70uEHCx9h0oCSFK0vI6skgDSswlIjwlIhWUH1AEQ1zNf07mq1xV2NNeX7+NnEcUHTtyf+xGMQN2ydskmKQq8UDe69byTba+jYw7a09SRNUhGGclit2UbAhKTyn3Uuf6AcUPVLmgz613n9SOPe5fQKWFUp+48Ek7diGTdgYKaRb03GVKNXnuFFGboR70XcHhe8v4M6466zHjZdNElgYADKin60qFeorPCzoVSAkgcHnKg7Q8hh+ji4NZdQAlverjOQ5iCNUrdoIRaAkjTzjrJZo/MoLHaos8ckW2SZvxzEyAgWot95ak2T7cxUDPgkfhCORCtBV5YXSgVIMKgAxiwbQwOVjdKNl2ACBiVB8DAXpO1l6FkA5isIQ1gzKrtKAazKIpzaxDUObmvWYMArvH4wA/wASXBUefhuZXnIkXGIEhdhdoLUXKivdh2DEBWtFadAGvG03ZnG4gYiKgbAKa2jRehB1NLWoTZmcQr1VJKfikFFrWlvN9SMZvPYYeuUGLxbOqmrlrKQkFJr3vg9UndoQRc/D1y4KCEMojsPUwg4uvi/UNJuzrypB2Tim5Aath2AiXBGazarrYdQDKFpIWrUvzEswE3VhuQYc0QUDJl1ANG2Hffv9uDJQYm3Y+f+eLXFGJAMU9XnVUw4rNwu95/UnVh1WHXmTJKMAog0W3eAg0KIdQLYuv1Rw0gWe0orUlSHLxsIYSqYjEte5QR9eZ/nnoyUW96X/btuiWPNQv8ioHSiNW9noRKom3PGCXZ6OpAzWdnqSN60FnAwVJ3tX0XXR8MSlZPYn2S753Efktse24fdiklOjlQtxq7zoqqXa3s3Rz0+B6ioPfd2qoTXW5KB9AAH9RAWdxmQGJABjDMPIEUgLJDs2sSbcSwWbzJPzVKiVYqPAYDBwNMAInB3tVKSx0ZKH4nYBQHoArrzqDklhr2m8Et3fI1Rx7wNBvna35m59N9XYkBvHj8BD8DUg0lC1MISlbv0GMwWDIgUqvAgkQdUshmMAK+rC+ijsQ6pAASt2wrwHGbwMTAhJVnYOqilnKnB2pLCkp0rFvKaqm1bkl1D6wiBkVL4WmQZNbeXSm9lVDyvZK8E3j0uatVqa9PisXOrnwcTvUEojGRAEiAyA6tbdLnhUmMweiNVENqKaQOIL3m4Yb6c6rFs/qMWgxcn2vSdkTAsZJxAUogGWwEogZwpIpCGfH7DC37O/8eZWQhBk0WSNSFWiZpyft9s5Ty9WrQeqSsOmA09D01kFBK1rlf/6usP/IFsb7dBIEGtpWIyHcJpFh/5C2DvJ0QW5Pz9yyk/aQUFn0lJ8kNsTDDEBbCqjOD2owt8ODU/8Ml8wqo3fzk0WrT4yEF7d4qqAzXbIZtH1hD5AEHDx54FLyAklRS3qYCKAlohBy20vqkLVZV2k7qiIBDdHJgprTluu8V+FZJLYYcStPO+ob9oxKhBkT8QxMI+J+adVo9hroM6z+sgOyzUP4G2HAAKSBGTy9CDy/dP9tm46gJ6g9tILHmiHqNKxYpE4CQFVLAIm67KxiA1j4ATxy+CFPf29+lc3GeDujx+O1zeN2KxwJogJQBFqXHa0UZAlwGflJZLKSM+De2HDCiZjRL4QYGJOoHBiYtiHQbrxl6aKqlHuuWdA4K5WVPPNtvSbah15W89dCCQ0nrlBZGKfFe6z2vlZLvKNuRvEtWqa1Rwm7TdUNh2uJZwcaDD+k2vu8AUaGMkjoyhaTHLpN2vYDUoZCoIRFq0OeT6D7vHRMKVC7vYUDH0nQCT6gfFCdfG4wEfOBD6yBu42uuPaqVfoUR76aWyMTjW+d8vZr5zWPUPNWtOoDE/2MoJGC0sey6MaofsacX9aPY/6izQ0MdaDAgJWUUnb+BEVYd6oi+dUS9tx26mq0fNHW0aj/MsGQS5i941dSTtpSlFl0SsO5Y60M3BGo9xLSzSmorpRJKRchh7Fpqnqj4N5Yd/wQeclja0nxbASUFKnbU41+mPYWwMLDogBGWByCKQEDUYmJAoJBtcNLfUE8gxcZ9UE0sQrUtHOTPUzz29UeesCsVUrbssMj+nIDUAYoSSJ3A8Hi47p/Tcth6yXL7U1rLpFurU/FzO48ep+M8JZBaKulNV0koLQZSbDteK+BmYHtZ4CVVBSgAEsEGYESIIdYlMSgBJW4NTMnG66qWUqcHU0tSXNQhuqqlm4t1SxoMgSIDozf+VDRcM3gG0lBKL79VNaUOKFFTaislqaWivVANpgQnANXlsIh3UkReF3Sbjs+dffZCHRXR7+5Aall2rEcSkLCUo8MHNUCCKbx/WHYZSAAousW3YPS0rFEsWq7xU3fq0K3DqA4xkJ6kjsji11u0fxIR7xmnfs2UUVsd4V4EkLDbPz5m/Wq/cUMt0BAdGpotg+o0HXUjlBO/p86ETQeMgBgLYfcau2HFQns6qwxHHa0mddQPM/wFI/MSepeoJ20tdWQdt7XolQ/SJC06bVh3svBqldSplMqu4KxPGrm6GrDKDsidHFRIpcMv/enGrfc+6xpBRJt/Vrpco2a8rc4PNQj8yCyTqMOYx89MVoMGv2NwBk6ACzChlIDaTx/3xYfYd7+XrecLYl91y062DIN7J5C6gaINJP2NWXfUenQAGL43dZVu+Z6fG6SAVRzxt73OU0KJ+yew/bGoJem5s+4GWIdtxxoU7ElW4wOOANIdF3uAgdg3iujGM45THeEEB9MUgSlsvBR6sIi4INaRxNMAF7WlB1J/NbYuwBrq6CAuKBGyaEBJg+tgUPKGrNoS/enui2exvOpIeGrE2lBKnUGHchO/ckJjcEE19TiAVwAobrnmEVIBdPlzp5QldmGt3FPnBk0Y+CwyueJ5UwfFhqZ+hF1n9SMCDT2BxLYlvn1JKCODUQIQEOLgWkePOt4TS9Rdfo4l6lDDbCtBr7rD99s1A2njFQp1lIA0VD/bSUs5UEjsEBsdvtmIrxuQBoLRZycNt0342ECTXWFpjMxCWLq39DszLKFw+UtfNsVG6klEwaklsTYJe41mplh31JNYN2RAaqsk6+SQQg6y7nbQ+iGsP/rdDV9t6dze3uwCKaZhghLdvC9Xu/3opIAFR1qJxacZRmqvQyGaZFSu0eh78/o1y2VgYbBgUEA5EIumWI46YhBANbFeiEGEv+V+fxWQgA/AySAKwKTbbL3p7zKU+HsdBq74+4Bd3JZAqu/rMfDCttNrINWVbTvF3UnbYdmw5oRCNuqIGTLpKr6+/QLqCCc4lM483r7+lhpr1jZeEXrItaWiL97VqYs4aml6qi3NLJJ4UkvW6sYCD94PDyhhLQFLbCjvGE5j1i7pOyXOaijVbYZ4/7ovni0i4XrPSbbxHpfpu6gr/YsmLAaQpJgCLAYZQNPt0Ocp/519HRCKW4981+qIxbFl7Dstjn0l1Y+yXfewvU7qR9FVgbVEDYWEXacDEGF9cv0CRgDIjxne0eG26d6JQVbq/epMwpYkJCmpFzL5IOJ9lHYe3nD5pTKQUETZrguFJCDtrlDRPop824Z829GhYbgpniaQPMTgymiM1YtQRaGMPiur7tM7DLOu3hFmYCEsvSj7YYa/dFRewu8ni20+oQZ2b50goIyQStpGgKI9D5Fs6kmRiKuVUup3V0ApOi1MoJ6UWguZUkpxcDqMn33EF+yf8Q2pI2aTtoBUM04GA4rJ9HozGKmGYn3m/hg95uqFo6gm7BcGHe4PgGK9R9SjfGEqkGO76/ox/1N2mFlsBoteoAAYAQtuBYvy6GW/hVLisUNNDQik4jxxX6kk7xSRbDuBmNfKQMhaF0IcnrabbW1naJ45T4teGZRYBEkNAYVEHYm0HbUELBxmzqSugJTZeOeqvkToISLixYLaRm1JYAq1hBrznnihlkoLr27SStiBQZUB9vl5WkArewqbigWhtM6h2ehPHlWH9BJK0ZBVn4vOLuHl4tkUCde1KKFUW3jUHWOdmCBicEqA0ufFlc6C3HKfgBC3qKJQRnXk2/ramTqii0fapgK7Tqqd1GisP4r6EYu2CX6UNaQMooCRrh9wB0TYovS24yDIwiSARqwRYmDyQaISe3bm5KOr6Scf7jBKQNpIYQacigwkwSkAtZf2QosO35awU8sgQBNAKlN0vjus14sCRtSNPjNxi+pA7cjMti/NMINckv42E0s4Wf6Kl0+/Ozo2oJKoJTG7QSUR196JehJQCuuum1LSuqYd1SuvXjT7vmoMvegUcuAf4qsHfbyac9UFtlaC6CsDK6vyTR2VSgZlZDAqItp/qiPRlkCj4C8oARusPorJZpFoEOAWJcFAwSCC6vI6kq8JIjAwOJASqEz5LCyQErzCtjNVlR6vA2QFkABXgMwWy9Z1JIDKQErgI2w7QhyokYe1HuleWWwAiUQdgOFrwISFwyBlRweYVF+Sjeehh0ItyfazWpQK5MTJB+3yUAQecjRc1lJO4HVASU1ZZTnSQodBGiuLuhi2FinCf5TFxWQFKPkmf8XWFZp4MInh/cUeA9CxeNY7hPteShZ4kKJ0gDhI+CzURwma9tfl3/nX9eMQsEkwkoXqce+6n92boY70GeT5o9rDrgPC0Vw1AykFF0IVPTPHF8nWMJpu9hwdGGjAGjCKEAN1Q95vlC8Tj+vUjeGwj++UgQSMqBl1AxJbTuw1mg4NdaABwAAbggoBpdimnO/5HV0cqBn9vWy6z0hRfVrKap+thnYJM/R3hf0rhuP+XaknsW7IbDupJBTTSEnv6N5tIYcuUPqoFFS7k0O5aPbIgz9R3Ttjqs2UaYnPPxsDEDUCBlhsN9SRQUOQCWvNwUFKLVlfRX2FLs78XSgHHoeu2tbo9OUnbLAKIJGOMttOjx1RbAscMPgPlLDrppDCsjOwFJApLTsel78TRP08oa7i78Oui1uAxwGQdPB6E5C4BrxOLEfAij3FLqYM2AzozKxZj3SftkmnfoRtw0FtCLWEAqKORE0BKyfAxAZtN2HjyeLJNh5qKUfE3fpjwJtzGTaemrXKFsyhh+llB/HLbcZOlwC38NKWFrPruhIDrq9VostAbPZX7qm0sLFw9RMUlGyDP01GcgJPk5AAkysmDz4YRABUHCm9yWdvsCPuS9LT0p6y6axlkJS5LYgVFBu1o6SOeI8ALJ91t+u61I8Ki87Scw1l5IrIQHSLdwP3HnVqGWXbj/iaM9TuDd881mB0xP4fyzAizBDqqBuQ2OKlK5BUQyKsAIDKwwIMBqIR1o0BZcQGfCyEjTDD+A99MIcZmND2R9X+FfirrgD1pFHqbYd1t7VqSQQcJqj3HRtsRcjB7LuGUqqtuyMVM71aPejuU/ufBzRzJ1HEwMnaCywKLAdumTky06UG4Cqmaavl8EFOqaXB2hRE3dIHlYRyQGUxKKAeOFBeATtsF5RU1JEy6AxIetwBVUsCRYZFSs21YWUQEkhCFQkqHg1PQOX+GX6AKWCUFFI8HkDKr7FekMtCT14DAyLqADuIfXa4lqgSajwA6RYpHoIL0UIIIGHRXXfaETZglWC6QTNqDz2UNl5au2Q2XoqIyxLKXcRVr/AFtQo9TPONAG3d0kxqSykeHt3DNfnAcsp1JUGpTOCxFmeg/nevP929rtQRdlBT07r/XbLxDEyqL2n9liUyBXK/pVN358Hnp9dR/z3JTqkifWZrZQSMZNXpPcE2trVHUv6mjqzTt/evsy7f+h+wpQnJrvNYt9eLesGInoVAnkkHNh2dGCzmL+WKAqYeGCGGXDfCqtNBmyAWqbMEI/evi/qRIt907wdIHvne1DblM4Uk6AAfUnQBpIARa5RcGQGjYdWnpI7o6k1nBraZGLvuex1Iq6p+JMflrxqM+nfuXwGuAPUkouAopfFKzLGh1vYbqyuD7LuPqF6EbUcUPNt3svNO/NyB1XdvmWb7sxBW4KB7Ai19on8XgycbkvFPycJVBlYGCcIMuRu31AALT4GGLWDNQCpVBAoidePW36N+gBrhBiDHwBBAYnbrwKOf3T/UHbdRLwsNpAI4BpgaHjwfCyL8MdYo+fMz+AGpOFeGUgmkBKWskvw80XHc1iMJSPY6VcMAvNidXF8GdZJX1HWw2VA81BKiLoQdx/fTT/maHUSBsXWaYCrrSz1sPFmAuf1Qj4i41ZZUz2IWb2qJJq2CJW1teI5RVyJJRtgB26oRC2/UlbpbeICYxaaEWNgYr2M7dNSSFIspJiU3rcYEnBKgDCYApeMANPVhIANm+WfpPnocHpPPGufhveBznGGk5xb7Ibk6UvIzbdAXdl2EGVC31NkGghEg4lpyTdn1lU4MEWLgvb1RKhflO+3kr9bKaAGAtJECDbsMW0NAUuS7Zdlhx5G0Cyi1YUSvOpTRwdsP046wm6ozg9t1OClsE+PbTCxTbdxvpNoHylt1BYatsvR8WguxBQTSnoWtLGplP6U65OBQekSqh2gr6ajyADq/Srus8k8JkLBu8NJpAZTTdVE/wlIDSGrv40BCXTCYF+oiBm39HGAxWKN8UEEoIrNONEDw2AwczHrx/7MlqPqUqS+AhDUGWDoUEgqmACB/k600B48BRpCJNFzUtbDXov4VXaabC3HTYzcUUjcgBXS9jmQLZA28araqwZAB2bs2zLVOCTRaBRgMUFhxt53rYQXUEkBi0Lr2G1+xgQs4NcFEjakMPjRtPArmvnaptvFY84KNl9USa5c0WKKWmMV7PLy08GooWWcHDcbPzyvDDnfagtFcV9LnZeHbDdVbortiquGUAQWk4gAsC3PY/RKI9PmqYVRsOYE6YiGsqSOaqcque5R0XW3X8X+AOmLNVk8YSRUBIiL2XEuuKbv/cr0txCDlS0CF93W6Qgz7bDO6A0iEGOjC300hEfneTfZ7G0jABhVEnQgoWc1IaslrRm7VBYyoHdHVe6+xG6kp8zrWSDnSdSTs3qqxqP84/SuwlK9PeodFuEnMjV5TbYW02I3N8SYp5BD1pIf1j8NsPQrN3NLUlHoOLX74HbCicE0XBWaHOe6tgRULCsvN+s0BpEaYoQuQDBSuTBjoAQF2FnUiZr0+SKQ9dTTYMMOlbmDn0ICOxWdA0n0XGEgNG80Tf66IAOLrucZjrWeUhvMAhfdO89dDiELnE8C6A7ANJL2+oo7E8416GeAlPYgtyXor4M5Mmxk0AQQsOBJ1LI4EJFg6RIGx564RkK7++pftlhl1BpPsvOtPP9LqS/ydJ/JKG+8b3oIopfFi7ZLbeBF6UET82gvyglrUkm2ZTuAhWXikxMLCYyD2upJDic8G6TPfgZaN5+ZZ3YXPyuDR8KSWfqDPnepr8VlkfyKrMclSI/QSB5MVPxwuoaiA1oBHPAaqSIfbdDWM+KwzISNZl9WRPvcshn31IdoFeboOEPOeAWZUYx1gYOdYT9H5luaCkSYaXEssWep3XHPUbyTqZmhy8TXWGyVVVN4OBCSWYeyhLSf2LhQSKTuAhG33uUkeXHAw6Wv9jN+xcBarztSR2gTtO35j2XUpXbeeW/zDVqVV0Dsm94fR/hV4S68AUGJH2Ujd6UNmsyCk+Y6CEju0MigCASwR7DdUitsZ3nvu9woYMGNkpoi9hF1H6sgXwzqQ/lVAikGcAby26wYCkgZt2XnEwlEPKCDgZgpJUOSW58HzMuglWxAgcQ6zAxdEIZUwElSIjMdz5BYYstL/X1/3Bbv/S9YhNiH1nghpNABYqr2GSipUWXlOqcAMJFmOgBfVh0VEdwqK5QxwDPooFpJWBBcIKmDpUPBmJk3Re/opR1RXHH9YdeWJX2qAiUGNBpxNGy/Vlwg+nB0xcSDnyov6RSzC9dCDwETo4RqvLTGbD7VE7cMtPBq0NqHU7uxgnxHVHak5NqPhpYXXbRsL7dz7Mv0NmQgBJh1MjjikmLHVDFAJUgDFYeUtqFBU+QjwxK39zv/eH8M3Y+QcTAysbvRisffR074eztQRa49UQ43uDFkdASM6MNxRR7tLGJkqSjBCeXJdUaUoVQ8xHGPv2VEHqE9dNxipVsTGmaGQcuQ71ZDopLKb1hbuTdugcUOtbdDB6rRQA0lQkkqKg/VJJOoCRqGO2GbiYyPXtxoz25T7Ythlq41W7O979JYOxv0H8ytAyIFtxG2xq+pJrE+ii+9h+3zUZn78M9JBAAViazZYpyEwMItnFso/LJ66d+P2gAOBBv6ZAQbqhUE2gFTXjwQj6kdtyw6FFCpJvwNerFkCSFhzDDx/UOcHBg6z7WSzAMoITgCQhQaSqRXBqICDKRZZhTwuKS0K38y0OS8zcaDB62oqspb92ABSWyWlOpKUHK/R4KfzsaCTa8Yg++vn59tWHdRiGMwAEhbO9QISM2jUEbdYeCifaQLPpcd+sbrsuEO6gskVUw8w2fqlZn2ptvHo9HCmFNrZVt+YdzVqqbbwqH0QeGDWT4HeNv+j5dAdZV0pFtHGeqUiGm5qKSw89cHT4ueyu0NesySFwv5KXl/yLg9WYwJOUk4ZUAYqoKJD17EGVoArbgUhA5l/b3+v+9pjBYxe8gaq1LaYeOEGlLvDujryXV1p/svkAWWIQjQYqabKOiOuCdeGa8S1wqID6ICdtkA0z2UDRgsxSAEzeTjnKwd3hRGAAkABpG4JO3rY7S4gWR+7AJIUEgoooIRSskMg4mcljGiiut/W2HUbml3nnb3fnTt798fP/hVYZFeAJqxj136PdXAgCs5OsFecdpxBhhkoLXxQBBTdo7UPUMKr/+MPnzbbjkGEmSIzev5xuZ+3C6qBBFhQA6aQpEY8saaBuaEqugOJ89M2BggxIKGQAAMWjNl26Tmy6LYGkgDRq4YUtSrODRSTOjK18tuf28ZtvsX4iwYhBjXr7KyBCUhzfn5PkCKfLwc09JgGViBUHnpt+bwJSHbeBCTBlNcJeJnNYxGxHxRW0BMa2LB0QuUAImbS1qlBC2JDOU0+9JPVxUd/obr0GAfT5ccfWl15wmENxdQTTLaw1kMTDIy2qDbVl7Dx2EY9IuK5tjTNe+KFhWdth7DwNABHH7ynZVt1qyvRWqq28Hxr9FhIm9csaXKTN/2TXWahB10X3osAE+8HE6N8GKCSiuoKq6SsDFwOsgyhAJEek8fnPAYj1UvZ8wirjufGppKssWrXjsKqe0o96Qh6cA0aykgw4loBo1BGTDRibyNqhLzH0076ajVp+MZdgcSi12FSQFskhdQGEk1VWZax+0gHEm2DaKyKZQeQAkpAiMPi3QowYNOhjEjWHTBh0+oT2mYCu27Hzdaqtlo/2XWqHTGJXWSDUf+B+1eAK6AP+Pxx673XUnfDh7zLAgr8AzLwoo5QOIQLuHU4vGI1HWaY/NOiigg28I/KP3ATSCkB97sUaJASsZqLqaM2kDSAM2gnUAAvLDtAiFLhcRkoAATPDUBRW+J3qAueI4BA7TTVVy8wRD2nVkioHh6LgjgzcF4PKhCLhoOved1YhfRIA7Q1ZPV6ukKQ85dAKs4rmxDlyHk9USjwCrS8TgZA0lsM6nRTuA6FpCP615ldpxl1LI49aMetq/2215bTH/9oddHRnzcwTZViCjBd1VFj6qKYEphi/RLrnqhrmI1HGi+rJV+3xPPy1kNTbZdb6xxuULrWug8AUwbouq5U98HLFt5DYeH5QlquM6rb1VKxmFaTHQvW6D2I9kMBpxJQQMrtvQJUGVpYcXHUv+fvuV8GETUjnceUETBSTN1gpOdm647MqlNnb1nV1E4tyIBVp/cqYNRURqlepG4YRLuZYDiMUicG1QLZTgKL9Sv77GxrjFBD5REdvdnBuaGQklUHrAg0sG5wd2078XG1DQJIBwlIwObvBJ2AUtzysxpGm9kWE6ijvbdUum7kepa+HbO2WoVpXBg+5J39MEMfGYv+CmzEpn7qQ0efu/OOOcwGQf7xGfABEgM9Aya3DJpWfJdVBhT4B2aRoK/G/04PILV6zZldFzDS4AyEGLBt0I7BmhqSQg06J9YZ9SKsQJQDoQrgxPn5uVuDCUi/o061oEBqKRXdF9VjakxQYIACCqwJYvBkBs/3BlwBK64Nz9PTdglI+fUMBkLZkoIn928m7V6wc1PDYxZOfJhBHyXEoGVpO9lsZtdlIB1TXXjk53N/MxZOsqr/YoHpEimmqccWYFKdiRBEHX5ogymi4mV9KaXxpJai0wMDKmoJ26lO4Xk0nO0sHtOCz4HqSi8SDb/fa4/R3SECD66WvLaUt7NIXR7eEJii0wMTBuDUAJQmSXwu4/i9rDeHVJdb/S7+Drjx+bJJiD7/2aYDRlKrUTdqWHV6DVh11MtKGJkyUjTebboIL8iiE8ADRiQncycGJSFnnPo134r8Pb7otYQRX9OVAXU0GJB2VaeVNpA+JRsOlQSA4gBE/MyUkX6PVcdCWMIMe45xu24bpW9HrrGcx721e8CiH436Z+hfAV2BCDnMnnqOR7f1j14CCSXgRf4mkPhHZ3DAW2ew5h+6rZCACnUZ368oYNELSCgkj1xboEFqBRVE/YZzMVgwgPA1P7MFsqq7UGfiPETLFwpIgiMhiIACqscCFIIxUGaW/uzcb6nh5bVWV+N7whyuHn9o50TheJBioDpSAJfXJ+jqNUbHBs7N9UWBesTdk3aAngGaxpxYPSgj1JD1rZO9wy31I1dIDitA1D4O23un6qKjBCbZeVOtznRodYWsvKsMTF+urpVFNP2Uwz0uXnR9iB55EXwgSEG3B9QSNpOrJU/iUZhnWwu6h1MjIewwGJQYyKMPnqfwysBDqCVP4gEEwER9ifZDKHiuD9AwOOm9QtFwNCClz6OBBtj0OAJodn89Do/JYxPv5jNdK6Nv16k6WY7U93gN1I1o8xTKCBg9ajUjT9LRIBdgA24AbhsuygKtQwxsJ3GENU2l+0J5BJSw4ggxjNQmmWyUmS071ZNiywlTSPq7jynyvUdLIQEkOn4DoDhKEH1y200r1h3tL3XE2iM6e7PD9Lj1tdVEaqbat+v6qFisV4APHP9UxLhZS0QtgwES1QAcUEkxaFLYB1gRbGA2zyBBr7leQDJrS4V8t9MKNRGKglssLw3YDNLYg8ABiw4I8ZwYLCj4O5CetVoVfzMwkIBBoVbyeWooYPUR7SasQF2K1wCQUEevSqUwqDBovv7kQzbg8dq9jtSqWwGbeD3lOe1rXl+8Rp1btmXAsI5++/lRg7xW1rkwaFMMp66DSgJEqCRi4FE/AkrYeQdOGtcBpADUoQlMHXWmlMy79qSv2LoXZuossOXxeFxSfNaK6Gwppinqj1fYeK6WPPDAzB87Kpq0WthB623oSFAqJesYrkEc0AaUvOUQaokGrd4Lr1ZLHnogIg4czMoTKLCKDU5ZOT2idCLr4wpIFaAKYDVuAVA6uC81Kx4Ti47zYB0ST8emIxnIc2tHvJswSm2AFIln+wjqRWHR0TeQNB3XDBhZiEHvJXWjKQoxlCAqv8aGI8hAf7rRayzbBBKNVQvLDlsPhUTsG8uOlB2W3ScFm4ASYOJrfsYBiDhCHe215UbVLiPWq7bfZIh2g07dGVQ/2mi5pSYu1gGpf7Il+wrcNuWUic/Oudn+AemqnYGkmXsAiTVFQCqAxLokZqTElBkI6DdXAon6T61c1KHhTwEkBu40eMcAnmDEOh3Ox4AfgQJgR8qJQQhQACiSUdRbiGJnIFFDypYd0ANGLSDxvZ2rhgJA4nnyOAAJ0NrGgCpeM2jee835NlgSNGCm7UDyLdStbsU5LdiQXlfHOdt1pDi3J+0i2WdAlB3KNWSgZHJAnBjrB3sn4GDqCLvOFJKrJAfS+J5ACjB9cc+PeJ0J1XQMqqmw84o6E/UMB1OsY8LKIyruKb+oL3nogSTeOW7hpbpSHXZICTx1drCwQ5HAIwjA9eU1WncHWXgReMjx8LRuCRsP26wEU8DJlFMBKPu8CC4oHd5HYNM40u8AkH2u0mcLReQgcouO628BhlQzwrptKCOrGV1nwJ0vFe2dFxRekEoEzNTY6NaOKvLNFenafprF9oE87xnqtARQ+2u2JEcdjV7jnQMCyWtMS3cA6UC1/6mh5BAyEAlUBxZHqCM6e7MR34QNV6lGrbG81Y/Y72zJHh37r36xX4F7rjxvMsVZ6kEGJFSAUl/UjVBHUXindgKQiHYzcDaUSwkkhQ0MSCn9hkLyQIMG44aSABA6/uyDNOooggUM/sxQGZxQC00g+U60jRqSAWmwjt8FkAQR6jg1kKRQBAQUCoMZgxH1AYr1PAdm6AMDSa8B2C0okARorkt9fjbrkyoUbFGCvHYUEhYQ0eBY2Op2XQBJ6igppAuO/NygQAowcYtqulD3KVUT65nCziPxVSbzXDG5SstgijSebDwGXWpLoZbcwlNdSdfPFtHKzooEHjul0gEby4vPHVCqLTzfY8lqS1Kovm7JF9QCCQI0NZxq5ZQBJbCgcjKogFXrsN8nAAWEgB3XnJBOgAhVxBq7l++fbc8xAgw8/ydmAaO0bQSqSOuLIkWHRReqiHoR4GZSQYcNh9HRquMdXu0xbnhPIKGOSNJRNxqrODdQalh2KCSpJ+w6jhFD3q3O/Ws3FNIBW28s8DiUTA0lCB0gUNmh7+nKQO2ItUe7jVrfdpU2u069L7cY8q7+RnyLfTTun3ApdZWezKDAPyWDLnUSBnuAhHrgcIXUBBJqxaw0zegbCsmApMangpmriAJIDNqhXgxG+j5ZWPw9ygdrJZqMktIKIHAunh/QiPVObSXmaqUXHBYcSECQa0In81j4S52sUyGVECxeW8O2S+DltQNkXm8JJIGb14HiI8mH8mRywEBIYouaDaEGBrMOIGmmzWx7YYEUcDpkr49Up/z9fl5r6qKaGnYedaZk5fE8qDFhP9E9wupLKSLOYGy1pekspPXuDigIwg5lZwez8ObU+yu9cC9dwz3wgFpiF1az8RKYsPLYbwkbDTi5cgpAhYJySDGB6Hb8TFYcn3OuL2ADcDwWj0mzVJYxvPoQDVPZktyTdCi5WGfk9SLfTC/WF6EITRXJtozgAoD2vaxOK7prHG9W6HTBiAlBWxGV3wObLVZd2rZ62XLt5QxI1JFyDSmAlGw7OviXQGL7if0FGsCDUjJFlEC0v0C1v77moIkqtSPWHu0yfF2z67ZcdyW1FdP6I6Xr+vWjPiAW+xX47g1XzGcgwDd3ID1nQKKWQx2Jw1N2NZAYOC3YIEhYbadDIZVAClsrgaIFJAZnwIVVRwyXAYLn8/CN3nySGSuzVywWS9sZkHyLC55jE3wEDBYASAmCqDLub5adFEooJAYoBiJmwg4kTxK+NUDS82sAKdYiCUiaDFBsp4EtAyJAYh0Qfema648UZkjqKGo+AZm/9NZV0+dNNTUSeqnWRDqvtvOOsmBFG0xsj8FGgiyotSQeNl7aAPDhG+vAQ6glEmqlWuKao5baYEIxMTEhfYhqIvEGQPhsMHng/WIS46ByWAGs+vDf8TcGH92H+/M4PCYQovOCWXOaCPAc2FojBxdkN/r6IrfneC0ZRHqNgChUEa8fQKOKcmcNs+l8o72v7rvLgDDCgmMDzFGrL1ONW/c9FUBiDzIDkvYhw8aLdUihkMat+141RiZlp9ZB6tTwCQGJOpJDycGEYuL7/dIBkEIdYdfRu46OLWNUPwJIw4e8q2/XLfbRuH/CpUgH8Y8YdRIUkq230aydMINZdhr4vYb0kqkTgES9Bc+eAbSpkHxRLfczhSRrrKFcSiChGhKQQiExs2WgYn8YFl2iFBh4XlexOaf5FL9mMWkTSN3OU4QarIaERZhUip4XQOJ55iCFrEgsOwYtulczCHFtmFGjXBpAsqh5Un8BwXhtWSHpfHHerJB6A4lrz2vkGnBeFAWD+w0KMuT1RylhB4gcRupVpwDCXwqi9v2+sMeOFh2/ULWmhqWXE3oRgvDYuNl5qmtlxaTwA/USEnnAlPZDxJ4BUyOJp83peH10i3cbz9US1hhgcitvluA029b9hGpiYa0BShAJSKFsOAJWgMYO4KUjfp/hI8ABICYbJYQ4p1lzc8s4N3sYKbRw89UWMukE0RQLLbCImO3mDUS6BqhH7E2gzfsE0Ek+lkqo29cWZJA6AkTjBSR2aR671rsMUMNLIKGOkkIat95KCUjrVnsJSPtsuWG1r4C033iHkqmiAkZACSCxEHZvhRnYaoL60TYbrVqNXmsFa7w8YvV39uPefT4s/ivQBBKhBgcSqiGAxIDNuiDqLFFDQiExeFNLRoMZ1wAAQABJREFUykAqQDEokBioBYdQSL6D6g/t8fD9GYh4bgwSUUeixkX9iti3tQ5648cGFLcGuwEJIASU9HXLJjQg/ZZFuPW+RBTBzbLToIjNxGwde4fXaUASCLkuHjXvBaQ4L7fpvB1AqhfHcv7creHFx63AzgCMQsP+YlAjWBBx74ARIIrfHThp8GBDGz6DfY+lx7qmDKcUH49OEB4djxCE0nmWBjze+u4RfkAxYV3Nuewsa0EUa5cY1GkeyyBPKKAjjTcnWXkZTrcXyikBSsA2SOk6YbHZAWTiiJ/ZLeChHnSHTXB4T1FBfLZMCSlkwbqvp9WLjvZHroY8xk0dLJJzzRj3lBRY6A4iLFber+vpwiAY7bPt6EFhhDpi8Ss1owlq67X1eiuaSvI6kpJ2qinRsy4UUiTttlaT5J2HrVntpth3AAmV5FByVVSqI1NJAhK7wmLXEff+yOZrWQuxUWsq0CALcNgq/Waqi380XsLPePUph0+kOMtMkQKvhRraQGLA1sBvQHpN3bd/7LFv/jaHDTSIWsoOUCTl0hNIDNBxFECioSm2HeqLOhKDB0Bi4ECxcC4sRQOSngfPhz2X8nnK8ASDf1YrxfkaQPLO4qwF4vVRNwPGpNw4HzNlFBqzdaygUEiAoyuQUF7dzjkQkEKhcX69HoDHa+S94D2hZjHvynMt1GCDm2pJ3rnB1yXdrIartBOiw8Jxn977LVNJ3UBVwinWNl1+XN2mCDiZpacBOFQTqo4NBlENlspTPYzkGQk0j4qn9Uu6zvXOtDOsbZJvAphaEEmxsOcS70WoJ1dQDio+I/XhsInv+TvULvfjPSXhZzUhA5D3nyvXEtX954ouC9eSmvMuC6i+CCugBFmjFdac26re+JZrwDqjs798cLXn+BELBKMIMmy1znvUa/J91daCUm3bvdNsOxbJsv0ESiqANHGT1dSpYU2z7NpAMigltcTX2HQAKey6PWXX0Z1hktYfjf/QB6qRAGnIu/px7yWcDX+Tl3/zlK9P5J8R++IXJMlkFwEElBBRZEvaacBmACYBx2JVWx+kQZO9kVgYi0rKoOimXAay7P7si2H/XfaXQUGBiD//2LslYLUwU0UpAQhqSKx3sueniDbwiiRgR3iiFxyySmEtEEDy7cR5HFoRAQQPVdxrKTvSUwxgnJ+f8/uuQKJZq52zB5QAVT53WHaxMLfeqI/H/91Lj9vCTGb8T94xU7UY72d33elHWhybgS62omCgD4vo4mMOWaRAKiF1yF47dSingeBU1pp4vtRZzM7TbrU5mXddDac6meedxPmMGqCoOSnogpohBQlYyoOflccz+rtn7kL5CDy6L4/BY7HBIKqMCY8BSKGL2L01p+UMQopu6zmyjsghRHw71YeSLfct2XKA17YJQRHp/WGN0XSFF85Qn8Futlz7Z7HmiCADVh0w2lbHhA+ptdd6K5htl+tIUlDUmBpA+vBq2tNsjayQPi7Lbh8ppE8AoI7DYcTvsOuoH+0yYl3ti7a6+te9Xx0alq+wAP8mA1L/pEv2FWANkgHpIQFJa22wpWLAJ+YdQKK+839++ZO8VgcVgWKh1mFhA4GitNKayqWHlRZq5U9pDySl+Tintwt6xhJVPLeX759tCsUW4Co8QeEfYFLTGhhILTg0oNAC0q8AEgolUn4OJAYnBjNqWLxm1GEAiTVEjX52CwukPwaQfmavA8XH+Ukvsi6GSQIDKMVyZtrTZfsQ/2ZWTl3J1rjkgXKy1WhKaCyur7NyUgujds2JvZraysnh5GuavAOEmriinICT7EnrkxdBCE0I6uatbu1Rd2KiAlSwNPOhWpTDxn/G3/C3OADUgFioC+hIx2EX2r5EM+sO3LaQVevOuN5+bc+yxawou6yEzjvJa0NSpAYhWamljcr6LeLy1wpGX0696drw6fY9Vp13ZPAgw/ba2Xk7baRpKkm2HYop6khbqI6k5si+hXmqIU3cZNXqI5s5kPZUPWhvLY6ljoRtB3jaB+oo7DrqRztvsU5O2NEyaNiQZfv1oyUbDX+bV3/bBadNxjOnSIxCwpYKSywDSTBiwSoKhsWjNmCqcwHJN4r9gCLCBlHbGRgUUVPRLYO4Em8M7HaOX6YWPoIOCSmadFJ0Jp6LEqNuha3WC0hdF+CGPTggkLALBYQcO7+3+v6cm81W4vr8WAVzYuecGyWFvZjbIgmotvneWwEknZ/rC+x5T5jVk1ZjUGcGzlofEl4MroQEYs3LXYoZM2getAjqSAsDtk99dJu8xsnaFhElP863xmCNk8XI88JbknrqBpFsPTpB8Bqs5qTXM6/LXkwPXn+Z1XO4BkAFuPgurH5LvccOgKO/AToEKbgfkwuuGXUgoGctfWQdGoAu1wJW1blCBUVKjki72XGyHQkoWPRek4I2hLAqqRMB4NO/eGC165jNq42Wb7YD6gai+JkFGVQf2lIBBmC0w9AP2u22G7w/23bUkUatvmyVgw2FZbfd0FVsP7Ndtf3EnqPXV11ogwqVFEoJtRSHw4m1Rxupd90Gtv6IQMN2Q0nYrWg97D78wWUn/21GpP5Zl+grcNt5p0xm0GPwI/ZNhPvNV55OoQFXIKgjBl8K73TDxp7Dn8ePDyvNgKT9aVA3XtvxRbXdrbSkXEIhGZB+aedgvVMolZ8Kdsx4qaUAP+sIscBAki2GRWYQKgDIz/6s31nsO9WQ9NqwJHnebJ9BapB4MFYQgxczcdJZALEG0k8SkKLBahE355wBwbhtwDBZdl0UEoERAiIAiTU4pA0BEgM3aik6HPA1gQAGWnrJMahig3165+0Wm223IKCq1VNahNsKRTCIW8uiou6UF94GoKRQAIXtzSRIYWGipAAK6T3ggrrhlmvB1/yc32MHcv1c9ch6M/DIfpMio5UPGxKSjDMFJCuRIAYLWGmVZAA66wQLjaBMid4TJsGOQ7E6hA5Xw9ov23YfgGjPcSPy9V9QIHmQYWnt4Pwug89EbSMxceOVq+0FJVTShA+tlIMNo9RCaLhsPYt+l0DSfSZ9eIjWEq1d7a4FrnsqaYdK2jtBqQmnobb2KOw66kc7KtBAQ1U25Buxxrv764+WaCr8DV+8/jEn47Ez+AEk6kLEuRkYy24NAAnVg53HYElthcEQ5cD3DOJu2QEkQNZcH+RdsVuDdgEkersBrwADSoUFjN2B5JvldbPsGucpFUsGUwkkt8x4beV5AS4hBoroDHDUGbg+WJPYhbFo2BVSDyCVUGqcW+en3iRVNVDHbwfSXAHpRhtUud7UsGh5AxxfvO92AxRKCQXAYMxge/nXv5oHxAUBxuL8m923Gl4dqtrTSZ/d1xbiYu/R9NW2yZB68k7kRbNX1WJMQSmt5ttiaHdbAQObD4CgYrDTUFTAxQ5Bme8BDb8DNvwdfz/rAgUQgI7uz+OgyKjFRSiEQEJefNwCEFYc4KTdD2oVJUTS8JuHHFSd/Ln9ql2kiDqu5fKDKyRgRJCBfnVbKeKNOpok+w0o7QCU9D21pPGy7WKBLH/bXou0HRBTHWln1iKpnx1AQiUFlABTwAmrjs4MpOuw61gQO2nTNWzn6D6Q/oaDcf/USy1177UXTKaPHQsDARL9v7DFvHifujVIIQELVAVQQj3wD416IGJLsCFbfUkhoaZQVkSje3f7Bg4+QAeQ2GwPqxAl9vPHH3AgPXin7aJKDecPppCea1h2g58nFFI6X1ZI3YGEZYYiI5XFa6TuwOs0IAnIrNHiOpDOIzbOc+famPJqQxCF9JcCSQtBKeCjBlCk2JSoV643UEKhAmyeHzFqUmAMxIsi/t0x2HbpLr6wfwOgsoIqupLHPk5l/QlFgjLJ664EjNiOA5DUx4mmbFA3fqTfSelgDXrdJ3W8MOutaMOU1nVxngwg1YICQFiOtFc6/ZADq1M+t7+1/hnsNYcl1+vW+tUpNTd6zXdXEwSeHQUVjgyloStX20olkbZjPRIqihZC7aTddhutrD2MVq0+OmwtWXAtIAk8e6fDlJKsOtSR23VeP9pBgQZaBgEkYt/sAtAfH/tXYLFfAfn087GmvD2PgKQZOAMy1hS91QIsDLxeJ/m1tbghafeQFNJLChwAsq5AUkihVhEEG9q1lhoQ1H58TZB3TSDNx9ofCtakzahVAaRuNaSwFDMcOvZd0nnMvqvP19gCIiukH5oyZB8dzk1cmJoDNQnWsKBaeN22aFgKcIGAlGEEmNL5B1JIAjGvkS0QgM6zAhL200Pq+k3dCksUpfQzPT9qa1h4FO95jsCT5NrBu2zfOVt/CwAy2OD71/5+51GbZkAx4BMtb++CmzcbpNeeYIFthnIxCw1oJXAZVABLt8PUDorHVQ+PgfLBPgQ+KDXggwICjlfoOPXzB1R7bz2q2l395xbmdXYFkfrU8XPrV6e03Ighy0odrWA7vn5k0yGqBelIUEIlbbfRB6pttGcZ8W+SdgaklLSL9Ujj11+p2n7jVZW0W7P6mNYimUJSfSirJIBkKgkYbWjqaI/RG+hv17cFsXRo2Gq99/WBtNhH4P4JG1fg/mkXzmc7AAY/LDKA5BHuZy3izeJY1vlYg1RUgA7UErP1x1VbYa3QggCpTqO1lASKAsWSgfSzHC8HCgy21JAYgLETSyBhDRK0QFV1B58eN0AUt0mR9QaSA4FrgSqhEH7f9Iss6UfyDVvy/0ugJoTRG4KlMoqvFxxIqDG6C6BeqYk8cvPV9hp5zexoy++xS1ngiYoiRYaFSr3k8q8fvlCD5sIMsIv7b3ccNrT6wp47WlCCHXFP+fz+nuST1Ue3ctsZ97hDEzgOM4gAEoCSD9lrgOyqEznqn1+ZoIPqATyXKXzBY572hQNMAe01fqRUUF0TWtjXvoEmAT2BJChtohrQsFXfUY1Zi5j3+6udNlu9AkhxACWsO2pJpO2If5O0GzlkmY6eduz8TLCBpN2uI9at9pAVhwICSHGgkrDp+J6o9+5aDLvriPVsQWwG0torWOy7MUj0v+lfgcV1BVR/mI81xeBmll0ASQEFbDPqNDRX/c83ky0lIDH4Aypsok4gpQ4KsuzovICKiGCDWVtZvQgWBiMN0kkxuELyrgkoJFJ2RHZRJ8CpHWowIGENFkrMnqcpsRb4Qp2YXQcA611beY5eQ0IhaQtz1dCIszPYM8hTHOdrFqtimQFjlCNA8teWYu28Dl6TwS8gFLfp5/n83WtIpBSxJQM4rLcBSI+qmwFQxyokeo4i/elj9ysaPsesRaw70mb8LS17/rvYdgs7yJd//7Eth1W7bbVFRasjalN0lDhM0Drps58woKCyANipAowdUjl8f4pqPtR9aONzyB4Tq4+N2LjaTY/1sbHD3nKQ9wIStSOi2yNXf6dA896K2DbriIDSTpvVUMK6M5WUbLuxWqPkSbul3baTwkIljV5r+Wpb2XY76v67aKO+CDa0ocT3KCNqR6gj1h/RoSGAxLblIxVqWFzjT/88/SvQuAIP3XDZfKwp+n4xCJtCUkCBgZdgQay5ARYGDg26DIxAgFgttlGpkIAY96F7NYN8DNq1koh9kRi805GBVEe/saYAEm1lLPYdKTvZibYO6TUWxnovuwAfO7h2VWIBCQOgzonSE7TKUEEbSKzJwo4kNsyeSKglfmZA0rlZJNzZISJBMNRY264zKHJ+Ha3zAxoAy+u2HoGmgO7RIs+bvI516zRrsYQ9+T8FRP4GC5EGoazTAlws9GSSgG33yY9MWKDBlVl8Ocj3v17A66HAQuzqarc9rmM3IA0VjDzIsIxi3urIsOEHpWxWV6eFNexwKLlayipJ4YYJsu1Yj9TeioKuDXT73loqyzo2qI6EbRcqyaAkEHGLlQeM2GriY0rXEWhoAGkdAWmt5fprkBqjZP+bxXYFWNXOYMvAxoALkEjMMeARbMgFfKkiqwHZDN9tO2bkL3cFkm+cZ0DSABp2msFC3RGs0aqpiQCSA+I/BDrUCuqjBtI1psJIvRG4oL5F0g8F5S2KBL60s22txBL08jmSVdYGklTfvwtiQDMDCYWi144aAoTUZmgOCrQBL7/j3GFlxjnt2gA6g2yoJG4LhZTPn4Ck84cqJO7eASRNEnh/qGPNv3W6gZTrw+umloViRDmSAHz+nlst4MAkAdvushO/0gdND0i8JdBdQCABqzaUIsgARLDagAh96OxQDagEE/bdJFl3OxBuEHCw7caEbaf4N+EGEndbrKKUXmHboZJ2E3AcSm7fASO+Rz2hjrDrdtbfNYFknb77QFpsI3D/RI0rQI0GO4pOBAzCDPqsKWLgZedY7CkbfDUQoigi2IA1BpBcIT1ghXbqK1heLByNtkMROGDgdyBFuEGDN8Cww/cHAkjAgboQgz5pPhY+8vzYOA1YlkBCifHcSiVWnyM9fgCihIHAQYiCvwUo3YBEvYjXxlofFqOSaCNYQQ0LWPL6LN2n+9s59XidSbsSTAFFXrMDmGvYASS9bq49i43Z/4fAyXdmXFrNl/qJ+h3nZrJArY/EHZMJrhG1JNrg3D/tYsWcT+8DaXECCUD1OF8bSL4IdhltE/4e1X1WNqtuZ6kaPwBSJ5Sw9LaTSiJtR/zb1iMp/m37IyUojaYWJbXFeiTSdtSSSNztroWygChgVKojtpwogTR2nfdKbb27D6TGKNn/ZrFdgSdnz7TBjAWuDMLMuhnoGBSxxgBD1JHctksqQAMwhXbqO1h9saCW9UtsNBddHqy+I8gw8HN/oGbdFKyWBDQYnOs2PgYkKSQ6QjD4P6x02Utac0P3beoq9LLz9U4F+LAGiZinc3itqgREUmLAqQBgTyDJrmRXUcIUWIZ0QQAMRMFJ4HltDSBFmEJbtKP8eC2mylog+qf0fYYirxkg1gotK6QMJO1aC5AUOCFY8ZgmDjw2tiQKMrZbB1w8L2LpQJMJBpvisSbnoB3f+u7fvQbdJeHnDXuzrZDi+25QUqKuhNLmqywtoLy7Gr/++1wdae0Q64fsMDAltSTVhFrCwsO6QyURbrC0HSpJ+yWxSDZUEmk9FBdpO8INO2+xtupjgpKUEhBCGQWMgBXq6KPD1lbdac1cQxq7Lgqpv+3EYhuA+ydqXgGK4d689NuqSQhIzz1qgz61EgOS1AAWESoE680GXhvYf5UVEom0Xz/nHR6oO2HzATEGTuo7QMbXI7VUUkBJgzMQCbUQLYoAEpaZWYpScNRMYvsJlFgDfKU1qMfKFpoBogRSDcASSNFpHNjw2jkXg7zv2HqWNpG7yWpaABHoBqTDjuwa2AgQxW0BpLZCyzWkBCTUIKoVILHw9bHbrzPgAV3+ltdu253rujMhsMWysl7p4IBtxyLZ4w/+eM9Z+5IAkIV+jQOonHisDKUAUPu2G5D0NwEkwgzDlZIbu84KFkIgyLCLwOHHWranUYYTkBKggBI1JlTStoqAm0piTVJsa84eSVJJwwS6UiURAce6Az7UlKgZASe+p3ZE/7qd9PiTBK8INQAk9bLrK6TmMNn/bnFdAQYwiuLUaBiEAQu2GIMya5FQSFhwQAKwMIiHEjA7Tff1NULq8PCK152w+SIBV9aRGEy5v6kkqyVJVQCjNpBQAHoMgESHgufnkQK8x1QL9S2emysxwOcNYMMaNBUm5dFUYQlISR3ZOf/4S3suPCfUlQFJEA0gocZop4TiuPPSM62FDyoSOxPo8vqoXTWBVKqyZNF1wAiV1mkZdgeStsAwIF1uDT25H6+P8zJJIG0HoFG2wIt6HrYdC2VplXPJcYf1gdQNEN1+FmDp9rviZ4MCqdfjJJVEmGHkGgogaP+iHVQ7IhWHvQY4aPtjYOI2DsGK2hLg2lFW3PZSSSygpavDmNTbjj2SsO54bFvTlFTSjgJN/dgCU4JTqY6w6yaqS8O2Q1e1Tt9sXz6qH2pYXMNv/zztK0Cs2oF0nwPped9s703FvqkhUS/xmtCPcs3EBnsN7qgXahcRyfa6kxqfym4jAUd9h4HeYFHadoISigK15TBqJt7MktJaHx6PDfJQCT9S14LoCPHmD5QAVFdsFu7+b4GBvy+tQaBnSi4UmIGotusCSNSsaiD9xFRPBpKsMLpXPDHrOut7Brh/ItuQuDX1G16fqUa9rrAisypDQdoRdaO4rZ8Dr7uh0CJlZwrpaauXYVNiw5H0u/Xck83adCDRzSIt4hW0UVNh23GtuGbstkvbnJjZ929713gaaTmAUgCo59cBnoFui8fZACBp7dGmimnTlYFE3LaCC4EG7DWr+QCMONQklUapuxqkXCWxYHYHrUvaRhFwbyXknRvMuhOUqE2FSpqwwQfUSkjx8fTYPD4Wnh/rZHWEXce2E9sISHRqYHHsGK1Fao8T/e/7V2CxXAEsqRJIDLgoE+o0zMBDIVkRP633sbU+mq0TMcZOI57NoMj9ou7kgYOkXrJtl+pIWSUlKJlaKSw7AQbYACRCBUSaSZKRAqRWZeDTc3MlVke/zRpMKqxRR7LaDvWdZNcJBm4RdgKJdUAoMF4PEHzqzplWQwJM1HRQkL4FBR2/1UA2gdYgqMcN9TggkFLNrCuQUuyb82cgyYKjVRPAA6DAF2UYEXHqftimdNtATbLlAl0b6NnGxnA9B9ViwFxi/6YXUAa4Nhv0uk/758VjoKwAkgUaZNmRiJsgKLGYtQQHQKLuEwffo5o+KpWUbTsFF7yVUFJJsu5YLMtmfeyT5J0fVrTHJuAAlLDv/FhLt36gjlBRtA2iseo4qTaghG23WAaf/kn6V6B9BSjaU0MCKlh2JZBQAgGk/81mfVI7xI6ZpaNAnlPU+AUNgNHxOxJwqAxUFYMmVp/VkVKNhwHVFEUDSm6f8XMGeBQPdSjA8F2l7Kwbueo5xK4b7YOkJrCuctKOYIM2+rPHR4EBiKySmkCKNUhYbig4LDNUB4M856WWRqeEp++8wbYlYJDHNrQ9kWRlRoPVCFN0qLIOlZRUU0DRIFyn/LJlVwJJFqEpJIAkuPB6eG08X14zSpSJA+8ZCUmeHxME4EkQYvbFk23b7CUWNgUQel6DNkTi+wHua7Zd/N1gt+Xj6G+pIVHvYSErAQSUTFcoUfMRmFwloWiAyBqWoCOZtzVrktRuaOzay1sMfJSgFJv2mUpChelvCDhMohXRpgpGCD7tA7tuB0ELy278hz5oUNpSz6s9TvS/71+BxXIFUCBmuwWQXgiF9KxZUwakIjVXK4JfVs/KHqIjNvULDxykbczbwQaBLGo8DSCp1gMYUFwM6E0g/cDAQJiAAbbRrSHWIhV2ImolzmFA0uNllRRQ4laDOjCNyHVvIM23AZ6aDLuF0vGb4MAbUiOsg7J+dliFAcHyfKbIwrYrbls1LJrOZsvQLLtXBERfB2UKqQDS7ReemlRdASTV2XguVkdSIIX3gfcSexH1SqPVg3bcuq+QSijw9WAQid+375e+Xygg8VjF4xBuiFrP2LXfIyitJChpmwkBoVRK1JQsiJCgRE3JVJLAsoMg47adGq6qlkT3BtYmkbaz7uFSSRGcmCA1Ra2Kx24eCklIGXGgkAg1bK3nMV4Htt1iGXz6J+lfgfYVYNtmOhJEqIHQgFl2Guio05RAyrUaqQoG/acFC+w02g5RWI/AAcoKy62uIwkWybYDAKxJCmgAIodRrRZQVSiQNzX7Z3ClJhK2IgO1R7+ftQBCM2nnMWwGeVcsoZKSUgJGBqQagN2B9IwpIbpXsDCVfXh4Dq8+PMesPCCAXUg3ijr67V2/m6qsC4xMIYVl+LqFIoDavyUgoS6xJNlmAuUZCmn2hacZkLh2/D0KiWtM8ITrQTNW1mqxdgpVR92J/ZGO+/TejQGxHBz5Ohfpi0Gz/Tdvu+8DOAt627o2Cw2kOE96HKBkKmnN5SxtN07xb8DRFUoCEmBCKWHduUpazdck0XCV3WQTlNiWYuMV1SNP1h2Pz8LbrWS/YcehlLYXdHbgEKB22ET1qHQApe02HlJtvaGUl4Bktt3aK05sjxX97/tXYJFfAWbSts5Hgx+x79qyqxWSD/opxi21Eyrpp9/7jttpD7XqOyyolZ1U1pG62XYohBpIr7tawLIDSLL8iDVTF4nod1iDrJPyRbhFxFz3yRHzbAtSoyqh5OqInzkEayA0LbtnrFYUsWu6bZNcY0vxX2rg59y8PqBgYYoEaFSXhymiloRNKCjlo65htS1DYM/1ykBSyi+AxOtnHx+eM7A1IAmGqDSCJ1ilrEdiUoGSZMt1ot+kA/tAaiqUBVZHAZG4LaCUIR6/W5hbPQ73HypwsB4JaLDlA+DwoIP2QRIosNao+RBCAEYBJWLg1JLYamJbFsoalFwpjVAdaRNZgkMFPBq3AqVRSvRRr2LBLNagH1pkK0WGKuLYXufjAFwAiWPYastNXuSDT/8E/SvQvgLfmX6J9bKjgG4q5/mw7J5xy062GAMfMWcGYAZuBkSUxY91H+w068b9uOo7srMs2PCq4uLJTrM6kgZbEml2PwGHOk+oJKDkRwkkdo39gdlRP9DWEyz0jPZGVudK0W/i170i5qHADEiy6FwZuTJxm5DBPYD0Wl1DUl0KZcYWD6TqiF3TsJQBntfJgtk/sjOu/o7X1tm2KK2BCpvQ7LtUvyrUUQOIUo8OpB9YnP0PL0shCUh2flJ2NwpIUkgZSPb3PzIViRrlmqMc2ead5wiQ2N6bXVEHW4uUB9diwH3bKaJ4bQsDjvbfxmOk279YJfG4PIZuhwoem2th63AtaB2lmg9rk7JakqIpLbwAEyEHEnPUhDxxp3VJgtJ4dXAYqe3NsQPtsVOAgnoSi3CBEsADTNtspDZEgo8dghT1o+2lkLbZaFX9DbHylXke89tjRf/7/hVY5Ffg3qsv8G7fsqeIVZMiYwvtnLKThcR2C26/FSGF3/7U+qnNv+Uas/yIfpudxn1laTHTD5BhbVn8u2HbefgAcMRh9RRTSL6NOYk9ajYMrs/Pu8VCBkATWOSkXVZiRcTcbEEeHwWWVBJKKR0OA1cbZtkxwAu0llwTaHjtnMMUioBEYg0liW34C10j1lvx+ghB2DorXQueOzFyYJdVUgmlqF/9KUExqR3UJsqOZq3YlEAWwDiQfGEs3SoIKBiQ9NpQZWbZ8fcCEt3Bra/d4/fbYl7qXkAMIF141Bf6ll3ApA2Zhf0+Hke3C5y0G+Qc0fV7C21DEWppy3UFDyXe6N6NxTZJ8In4toEJKEk9kaDbHqAAGcGGbSzoII4luKEO9lvSRnsVjw3wUGEADzBRt8ImnCCbjgMocRiQ9P34D72/D6RFPvr2T9BxBeZcdtZ86iQkykhqMbCVC2MZeFEhkZpj4LQAgQbF32kgpAZF41HqF9QxsNNYw1Srl7QeSQN+tu1+qzqSqaQaSgzowMEWqepvsa+oj5BqYxtx39UWa1DPUT9j0LaFuznY0IqYZ9uuCaVQR0DQzikgMMBjE1rKLgEJ6zIsM5qbcqDS6IrAuW2L91+80lCMDVUm8Ni6JLtNYYoMIyLudc0MqDlgXjbAMCFACUYNy9chnWTgDoBmgJVA0qSA7SgIgoRld6F2Yh1I8fy3V0gM+AUoen49CBgWyMorzgOQ3goosT4Je431SZurQerwIe80RcNaoAg8bCvoUPcxMClpR3cFUndAinVMQIk+d3QOH6YFstiBJZRQTVuovjR6Ta9ZZTAJelt/SArL4KT1TVJNASh+1jFY9H/QvwKL+grMumjyZCwe1vnY9hN01DaoeOsgBl7sqVA7rEfCXkLxABjixZG0y8EGLVxlrY7XkYr4d7LtUAUMrAChPDqApMdAqWDZEW4IaxDVVEbMeW7AJEfM0+PT981VkkMp0nxhl3HuUCjdgARkUWa8xrlXnGPgZb0P5ybwATTNwtR18NcT5ws1lqxCQBQwkoKK8+fXq+uCOgP8EVLgWvoGfTeZOpt90elNIMk+NUWl54FaNIWUetqZQpKqItRw/hGfG3DA/m8NpBIyBSy6Qqn820G+ZjCPowGq1jn+Uijx2NR5OOzxdQuUUDObqe6zxarLqJ8ctaXlZeOtWNt4BZi8xqQYt9STQUkLZrHtCDaw1ik/f84jQKGchq+2jMHOHlcJP5QYiTpCDA4lV0tACaU0dv1+sGFRj7/9x29dgRu/edzkJ2dHHeh+s4qi2zfWG5YQUeRQSV5LSlCSkgEWzMhJ2uWFq1IQ0QevDESEskIFsZ6pDaU8QOtxsQhRWSiV+669yBZ7YpnRkYAEWhlscEuxDl1EjQvgmB2YknyAIGBgCkkqLQNJkP0XQQ34Rg2JkAALTXmNc6aqwarsO+o0nJswAUAAzp1hirDuAkz1bZyf58Y1cHWWtp7QuS3GrRoZ15JAB2uwUGe3nXdKBpJZfBlIsuxKIKmGxH3YWJDY97Gf2mvJABKQaQGj8f0gECrBE4N53Obf9Xr8QR4b8ET6DVhsmg7ScPHYnAv7zn4veLhaWtbaDBF6AB6y0VQD0pbmgGljj3Lb+iKtMwJK2HZ0gaBuxPny809QQoURBwd21JUAE0qMx+4GpZGr94MNreGy/+2ivgLTJx81kS0LYrBvL45lxl6qJFQBUGJGj830uEINT2sAxCpCPYTlZ3UkGqDm+pMHIiLcECrJoCQwcPt/ZeUBk1gkSgNV4MjiXdZLYZlho2ENlhFzlFgskA3FEo+foZQSfWWAwgAoKBBMACy8Ll8Y6zUkgIQdyeBODQflwfk5958U3OC1WdBDCscgm1RfWHcOQBSRq6IGjPS33MfsOupHKWFH/YrHpz8gipDQCKGKb53zdQdSer5h8aFEc6hBsCb2TcNcIDZLQYhjDtpzwIH6v61C6gaBAhgdr6vb3/f4WQzk5W2AowG5OF+Px+E+BhgpH2yz9hFKJh6b8xF0qNWSOnmr/lPbeJ7GA0zUf7DyiHMDI+pJJO8IL7ALLfDhcXhM6klWUxKkwr4jSEHNapRsPIA3RkpsfLLvvI4kxdWvIy3q4bf/+O0rcPXXvzSRSDMLKok5U7SnRoNtx8ybGTuDHrWkf9bAzyBMPQkFwwDOgtEn1In6Bxo8UQ/Ej1EQVkeSnRTxbwAWVh+qgME4oGEwYoBGMZRA0jl5HnSSwDZDrVBXIemWgw3025OyiBpXtu30OAY7VFJa92RqiRCFvjeFUkChDSSUGd0rOOeDMy+rblXrniekJGkfxPWJ6DevayAIEnSww9KExXl5rboO3JcuGChJCyjommNJAkPWh9FrkEapbPXB8+Yaec2J+/g6JAtBpNg3EwsgRt2N53z0QXsMCKSuA2wMtP+Vb3tBoNdz7vX3XX5egqj82sCxkI8fQMIyo76DpUabHw6+RyUZNIrnQYuhXmBie/ExstsAD9tXEE6ISDdw4mdbKq03TPUozlnWk6KfHs9pc4FuC1l4I1SzotnrqDXdHmRhbNh3gK89XvS/71+BRX4FHtBs+nnFi+lEQHse0nLM0hnoGHix3xgsHUovmn2HTcaASIdpknZZvTztwYZIwXn9iTqSYuMEIjQAo0gAjwFJA2yoo04gvWj1Gmpb9159vkWwsbHKYAPPjeeV60hYaFIs+fEFHeATMXNuA0ZmmQFA/T2KA8iGQiqBxPYPt0iheLeGuWYZ0l6I8wJls+1CJen1sNVGrcw8RdjtvKGO7LyCKqoSmHugYZ7BkI7qpOXYt4rHDCA1ak6qaZHKI7rP+0CHcq4XquqoA3d/+wGpGLxDXeTbAhgNlTTQfVq/KyHU/nphoETKzRaoCj6sBxq95rusQ7d16VarH+CEYsGqa0MJRbORFE0DTMnKM5CYunGIBJwi1k0MnPOhrqhLBZTsHDyuDl88KwVmQYplzcbTthOqWREPdyjRSki23cRFPgD1T9C/AuUV0I6o87GjXtGaH+LbDIi2DUVSSQYlWVQoJeo6DMQGJyXcXpd9RiyZjgKoB2CBegFmqCuDRWHbmYIBGFIHAQ0G2ThCNYR9xuPwmA+qjkP4gueYwxcpYj5gok9wCKXkYPIgBT/LAPzVTwxIYZsBG15/1JAemnl5dfPZJ1iikD2SUGg8LyCNMiPo4aDtrvwMuOl5xDmBkakygRrVyWv4g8IgXDteH6+T9wRlyBqkV797TwISAPWIOurTak56nwhBoB6ZWDwqC/buK6dUN511fLXvdmPeXkBqwSODqPx5NyiVvx/k6zaEyu/z+YpzZJUZj5sGfWAzfIgi14IDPefoqBDHOPWhA0xEsksoxbnsPHqcDQW1ANPGUjamuGTHbbZy2HleZxoj2411TJ6gW8mUEnUigBMqLB4bpQTwInIONMMaRIHRXJWaEofWNk0ux4r+1/0rsMivwK1TvjH/e7dNN9uOWTYFdbYyRyWQKEPtUOhn8EORUNAHTty+JoCxTueZOTdZd2xvgOopOEBmsEhrhbJtl1VSPYDHQB1Aigg252awpVsCtREsKaCJIjBrkHPoubStwbZKMigRNc/1KkFQ6iifT1ABLtStAAO2XAmkb035hoUbIvrtKT9ttaFkHPCMODyBAwNtUoABWjuXfsbvAQow4npg1QHtUh2VSmfeVecJhidWP5R6NYWEotP1Y9sN1BzXmPfJQhAPzbVWTgCUHWNvOOPYJQ9GQKGARVZJAYsFuI2Bu9ttBlLrPPmc+jn3Y7AHNKOBkTbTIwFnh1lt/jXNUVnMinUHaFBUXc+px8PG20iPiWLaWDZf1Jk2TappmJJ51JoAiqfzCEKsaJacQUmPH0qMcwAlDh4PFWWPI8ihvswWVE1pq/XeJ5CuOHmRD0D9E/SvQHkFqCM9OHOqxbexxEiyoZIIKGDdMfj+Xt0D/iDlQG2IQZADJQEw7p92scWyaa3DfbH8vI7k8e+w7WzgljWGSorYOIN3ediAzYAr5WCJN52D54IKC2vQ1jzpZwzEZg0KkgzOkeirrcFahRGYyEolKTLOG4GGDAdTKh6j5jwoP2pI3xIU7lYth6QdwQaUDK+fBGKuXwkyppSkfgxMwEkHX3MeXjMLcLEHeX3YjAAQGHGNuW4/Yy2RIvgR3b7j4snVzMnHVG/qb0ogYfMBMp4D8Pzp4/dboIF4PBMEmrFeeOTAa5DyIFoM4P+lf7YAMOn2/BcplOI5ldeQn2mwd7tuWVNCwAcrjSQc2074oQFfa4ccSksbGABTNyjxMx6ztPIAjKkmgIJqAk7UhkjSpfVMrD2iRgRwAJlBD7ilI8DE4wBQewypKoudK4HXB1I5Uva/XmxX4NvXXGAKhAAB1g+JOUBAgZ3Bl7QbkGHg5OBrDn73oGbk1C1QL//AAllg8UINCwbO6PbQUEkxcP/GweGDtwZuA5L2+5GyAnyoIRbvUssBEBZsiK4SYQ1qYI9z2FopQc9UElAQeLJSacAItVIn7AAEig47DjigVAAQXRpuPfckS609Mes6i2PznLgOtjhX9R9gmIErMKGAAK8d+hpIEl7gb/hbFB3n4vXxOEAFq44JwfPzbrVk4b16T6gDzTj1iLpLg64Vjw0E47la/UiQRL1R50JVcb9jPzlwwq7b4P1f9mcx8A92W4Ihff1WA8ngMMjziIGeQR4wWZjBrLv3SCmtpC4M9JbzbSTo+m01H8W16W8HlAYCk51fQMHO2+R976gtvQSorJ4CUisTYFjWgURdKg7dn699/dOyfD2f83J/wIQtuPZyS038f+2debRV5XnGNTUmNjWgIuIUES+gzAhOQeEKYRIxanBMaq0TRTEBxRgV5TjFJNSg4izOUqUicaCmasxxJbYmWhyS1XStZrWJTWhMmnat/tmule4+v/fb37n7Hs8dgIuiPn+8a5+zzx7Oec6933Oe932+93vPBiHfyAhkBB6+7tI6KoSOCG89tzYcd6TfSJcx4DFAQ06oJuYBYb3mtX/WMQyAOPWwSEMWUUfSABstiPTLviNt13nQJnUFaWQ1EUoCgigJiUEb9cC9MVxwn1eUGuw0iVeDOYN6R9quyUCh60F0WYXl1FmQn16D/FAs1I+4X6NZqT7zz158Jojwu6tuiiXEH7hmSXTR3vDMY0HY1JlQKKQvQ6GpFpRs8cmBCPmkeCv2ZyJCFUFknAup8/nAms8IhmHbvmdFWM3vry0WST0ty7c6O2xMbYNoxQR5co28hDnnQtp0dXhCc6YeuvaSYtHJx3RKX22zZFMlkeaBntea93X3vHqtCiEFKXV3XtNrXamU5v09vjepmiCIcpBPLYI+LuUBMZG6S/Ueaj9jZddmcb0gAxSNCKb5flnZoHRy5H3UmhR1UnsE6bic4gsFtMv2HWSUSQkS6r9de1sT8fC8eV8eK7w1AlsdgRsWntnOMgvff+T2GNiwgTPwQzCkqLBAp1iv5+vDwPBT1Sxw2f1gzapIa/2YFkT6hf/zH8ipJ+JisO00YGsQJdWESkIxQDwdpCRigiAUqAqOgSCoW3EtFp/DOfb3ax+IjtbM04EoUW5xDw3OpM8YqJNSyTbzzqTXSKFlMkK5RPos1XIaJgEZF7gn94t5QErZoVS+s/LrQRiJeFnBNilBzovlOpQ6JNXIe6e+REBWkBCkCcGSZsyqCFIH1yCjpx8NyzaKjBoQRopVSy8s3nz+yaZJsQkbiBhlhZrN84/+RrU2OoPfJyL7QBBQM4E0EUOPA37z8c3XqzzfJFISkbyLDHrY19V73V/vEfKAYFAgEM4oNVWFfA5W/7kJ0ZGB1V+1JLkCgwETYxtmB53bIJ0KETWUTkkuIqNadaDQ8/buonqsHxuBbQ4BFcHruLNQSpgcqGOQIntNAyXpIH69v6Z0Eh2wUSovP661ipQielLKBbKI9j7UkZiPJLKg/sTgyyRSJte26vYQpBTElMgIxZIK/j+J4xnoUWUQAIRJanDD+jUxiFfnIwUhVO8hkkH5cC2uCfFBdhHcQ6QXaTQRX6gjEUdOoUEypM+oiaFWUGYPSnHcs3RhKCUcf+DS6P8nUoB8SfVBjhAFS2ek6Ki1QUJgAsH+i9KaEAmf641nH4/UIFjiqkPhULO696qvFLd/bUE0hWUO1f9uTHOQor4m8gVblsPgGrwfVCoYYYJYvi3UjzJZVEihW5LMx2/ptsX99Gu/rjRabVP6z20qIfXmeNmoQ6VkcqK2g+kA5YShIBkTdkxmBNnCaSUUSqcbIoKYmslomxtc/IaMwOYgcN+yRfEL++nbvxHFcVJALzx4WyP49U7RnJqT7OLFE1pzZ436rNFrjUmc1JGYYMsv/9Q5PM1lQh0k40FKazGoZsKAHII0KkSByskKCRWApZxuDbyXXEfCWZY7Q2C2IN0WKqlMneV7hBoTMUVdp9xyb1QY9wlzgQZ4SA1SISWJaoEo6GLBirEPyrF2zxULC/DBaMDgTw8/OlRwLGlKzuMzQ2gYLiAfHvP+ScthkYeEUJzUisCKGhWk9+LDtwemj6+4OggFMrrzsvNlZni1QUjUwcAp6kfCE3XIfZmUzI8BujPwPTxw9UXvb7quFaG0IIlO5NTqnM3d1+JeIosa/w+6Z723pNQbggnl0oNyanWdsHNDMjuXykm1pux2o3aDOQGlxGNSfqTcmhVRPNf5uoY7c2/OYOdztn0Eli86s/2x5Uvr1C74pb1adudHNeOfWf8RKu5TMH/ouq9qkF4iB9ji4t5lX4nnEAZqCuWQ5wrltF1MYA3jgbo9hAGgTN2JGJoJA7KAKMLUIJJgkEcF0K2AlBTKDSdaNW2XlFiqVyVXX67n5DZHqdVRlYgY2DFCYLrg/XENSAQyzaoDtUgLHojozsvPD5K4XwO+uqQXz4usIQLSm8xP4nNDNqQ0cehhG+f5P4pMSclBXpAQKpOVdlF7Lzx4a3ymdVI24PzgtUuKe5UaRBm98dyTQUa0HMoOO7Bi3hJKDGs+ayZxPQiSHwiP3JBMEJ0G+xYDdKfXGfjzMb0hgXxsq21P52/OOT1dU6/nQT/SZs33SK/X8n9fr5TSppBMU0qtVySlc0RKdZSNgi0qp0FQ2dqdDQqQVSilRED5Mee158/lrRH40CKwYsk5tTv0C51f6XdfcYHSVReGQrhbKoG4S4PzHRo0b7/0L4pbvzq/uO3SBfqFflOQBYNzWMelCFAKqA7SV7n4T+qug5QyYYiYIKdSufy3ak0oqlwngSBoGvqEaisM5LTVYeDPSox0GIN0Ir7UoTzfB+IhLZfizbg3RARxkaYLMtK5kGesvKrrQhzcj1Tk6hsuj1oOn/Xpu74dn505PlirSefRTYEUJ+REHQ3Vg4ojeAz5UIui9VB99V2REgUrzqVW9Oi3lsYkVkgPrMFzw7NPhLMu9cNLhET9C1VHPYrPG+pIK8SSOtVCi0GcvK/Fp86JmkWDZJoH6ObnGrDjWLa9jVbX6M25zefxvDfndXNMJiO2jWtV76NzW/2jdkdM1Wv2+nErYir3ZQNCdPnuIsU2RORElARVR/k0ol+YFTAsmIRafZne99FB4JtfPrO2fNFZtRsvOqu2YvHZdS36pvjz2PLa9ed/qYYpAtWQJ9jmrg2RUtNAzxymXOeBaDrIoqNZK4MtaTaMDxAWZJEnqZLiYuBd/Y3LpAbujMEeRZJVEsTXICXVrEgRMnBzL4gHtZVCj0uTAQSJyQDCJLWGc5Drob5wrJFGyxNMUSzPaNBHqfxGNSLIGCWDosFEwHFPqf5GOpPUGR3CSW9SE8opTggIjP76xlqQEAr0gasvjloRJJ8J71cbfhj34V65ISttjlK67q3A8e1Xvx/qiHoehEjt6JGvJ+PFCZPGRUGcQbBXpMRg3wfE0CCDbsij5fvp7vgeXmsmi1bvQcfUuvtvHUxtSZHn+TRvm+/R3fOo5wj3BgHxGOVTRkk27d29H79mBIxAHyDw8HWX1ElxkULCgRdzmTA3lCop1XlEFiKacKKFUkrNWjspmFK9ZAs285relBJgYixpQ1xvLz9+X7TXSZ0lngujAOm2TEooK8wUXANywgHHY9QQag01BRFRh4E0UVqYMUitMci/pHs9c2fqB4e7DtXym5/8OFJorAj7jq711gtPiUQWhHqi5kPthlQmhgTSmqQ7CYgCxxzGCNJ9KCHILEhIxHbLkvNCef1ak4+bl+WgoSoTelFHqEfSix3qSA5HqUW6WKCymEB7kdTRGDm48ux/Bs/GIF1VDc2Pexj4G9fY0uOa77sFRNiKGFq9Tx1X6+2fd0/k1ExW1ee8n1zXabjikhpC1VjZ9PZL8HFGoC8QoONDtPgRWTDBFnPDz2lDpII+ZAEBRFpNqgR1AjExwAY5ScGgmkLFSMHwOjUdHGm0CmJ+VO66TU0HVcDieTjhSN2FqUDkh4EgExMDN/eky0TavhyDOak5FFEnt5ss3qTpUEYvKa1Gh20GeYjm1kvmBwEV/6GVXyP+rdy+XbwhSzbEdPOSc+M4lBNpTlKad11+QUTUnrSf1yC2lSKgmy8+t3j67hXF63+7rvh3GTJifSaawIp8iGh1pOcQ1P9oiXTUEaoRos02+FeUCgSTtTJC0LcOi/j5J86ISZhjBiZSYoBsDNKtyCDv21Ki6e35+X7VbW/PbTquFSGxr/F5OV7PN/dvm3k4kdZDPe0ULr1Gt4QqEfG4Ta9HJOKpl6m39s29t88zAkagDxB49FtX1HHCUTuBLCjuQxZd9cZjcmeQkwiILaoGJQWBYGbgXNYFQh3hQENhoFhYXuGHa+6VFf2xMAtgHkCRsXzGv4qYIEGUD6ktSCo73XgNNZTdbigi5vDQlJQaD0YFrO+rZQ6AjG67dH7x+vNPFcXvf1UJEdLvIaUcJVH97m2lAF+VGeE7MXcIssKYwHPiHX02VNbGt37UqT6Ul8UgRUdEi6MgonI5jrfTgoXgA9ni6sOCn40MqDBU12J19qYjQDWYyxKpuzyYV4mAx3n/e7TFfq20HbFlaUJIoHdR64M/a1/CCBiBDyICMkO0r7v5+rCAU9T/6QvrGgoGMoAkGFRRKRtVK0HFbHw9KRceZ/VCmg6XGg426lLrZL0mJYbKuEVqhHoMtRlICfs1pMKkXGpXkCCqKkU5oVf7UGzUnagRYZWGzFBe4XYTEWFgwDZNag218ex9K4t3frahKP7z1ymClKpkJCL63buXJ091H62DxNpLikw0nbbR6LXSXw9VVJIQ3SToWoEqIk1HOpOUI/jgXmQyMmtQrb8zTYIFF8wQY9VZujlGq3EnpNRQDpkI8vY9IqJMfHoftVAem0mGvSShBll9EP+H/J6NgBHoQwTuv2ZxnXlKzEuCLEiFoURQMZAEgyoqBdLBSMAkWiaKooZw50EaEAyONcwB0XlACoDU2YqLzikWfmFGcdbsI6M+g2ngpb+6K1xsECDKARJj0IZ02JI+3KB9pPggIOb9MAmVetd3RWrYpVniISzXUkWQ3ptqG1T810YFZFSqIxSRVND/iYT+8NtfxMJ7zescNbqWq+dcboUU7ZHeTm2KIBmCCcHR545+d7/oiHAZRs+7ZOzIlnSIOtSiVCfuPz43S5TTImjVlRcWF540qxMZjRukrs3qJD1e6+6MUE8zJmKiSiCDhjrZTFLI5LIp2waRlC1qolaziWTYuEbvlBGkVOvDP2tfyggYgQ8qAvfXFtVxfrEUQnR9UL0DoiAgG9JwEAZmBSagRicIzWGCMOqq4TDfKHW6XhzGgWXnnlKcPvWQYupBe0RMGbZ7seT0ucXDMhEwOZdGpBAMzjgms0I4EBWOPOpNzPeB3DBEoK5Y9I4aEU435lKhiG5TfeeZe28p3vmn10siEhmhilQ3wsiQ5gMlk0EQDypG6TQIJYikdAhiM2eyLdZyJveGyw9nn+plEXL/4QDsiNeinkZNLcwXkbrEeKHGqyIiaka4/7DTsyZU6ld3bRgnSCtiZEgElFYiDSIqyQhCwuAQKkmpMv6e3mtCqhJJ899zuNu6IqbeE09DETXupVpO87383AgYgY8wApedcXw4zhj8IQy6dX9P9SUm0FITgjwYXPm1n0jiuuIx5uREmx4RhOo3V519cvHFaYcU00fuJSIaVLQPHxhdkicdsIvWe9m5mH/8tLBOY5/GgYelmloTNmyIii0mCLp143ZDBcVkXg3kuNwwGaxfdbNSc/+QSCgUEUSU1NAf3pESom2P0mkonuizJwVDGi1PqoVEknvvlbC3U//KaUiUDSlKTBQRZT2L+liubcWWepcC8qH+hXoMxVg6/yBs5jmBF/30Vuvz8DkwT4zfU0pIBFQlooNFRKxQSgqP3mmxSFvZ66ys42xZDacrEmna3yAIyEWF/1b/Dqgl1EyzUSDMAl2QUqtj4/hkKmhvdR/vMwJG4COKwOGD+9cgEeLi0+YUyy/8syADujsweTO2IpEgB5kUqIFcv+D04mopIVJypx09sZg+au9i5uh9iplj9ik+N3LPYrJU0aQDtLzy/v3VJblfcdh+Oxef3V+hrsmcs1jdrb+58Iy4FoqHVNY9MYn3guh8wDyftapFrV15Q/HLV7WkhmpXqJ5wzkV9iNQcRJTUULZbo4CilZFcgKgY5lPhAKSmA8lAJKQdMVRgliDtSB2LLgrRpUEpSFKWBPOpaFqbIj2mptUIdXNACaEcUZNY6OlMQfoThQcZQbzUjVZdubD48rxZkZZDCeVgUbgJIiO2o7WcQW7Smf8UISSRw1YnpE5klIillt9Dqy3E1BXR9LS/dLi1t7qu9xkBI/ARRoB29tNFINNHiZDKgFCmjdgz0m0nTTm4OGny+GLeUeOLU/R42oEDi6OHDSiOHr57MU0puRkiollj9y2OGb+ftp8JYoKMIKLDRESHiohGDdwx2vdDRpNESpOGaI2ZIf2Kow7oX0xu26WYMnRXXXO3YrHWBML4ABnQiPQdEQlpNEgGwoGQqAmFOeG3SQ3lnnG5nx7uNuzqqB3IJzdGpSYGwbDcOHUyVEx0Z1Dt65V16s4gIvm7tfdHzYq6FS4+3su7gv2KOKZ8HaMFaUecdM/dd0v0uUPxBRmJ0CHbRf6Ukr4AAAtUSURBVCfPDtIJNSTygYBQRcREdZEeq4XaWIuH9jOaB1PLf5IipNrWJqRmMoJQ8v172lLniq4FIqgypReW6gYpSWmpftWwVuuztfd0Tb9uBIzARxSBmaP2qc8cjbrZO8gFgkEpJVIaFKm3o4YOKKaKiIKMREQ8hsQgojnjB0sV7avj9yraD9yjmNS2m9TQpyNFN3HfTxUTtJbMJJFPg4xESEFG2je5rX+DjKbqutcu+FMN9FpUTxN1SYNBLBASNR/WSIp5P6XVmpQc+0nFQUK5tx3uQGo4tC+CfFAuEA/KBXLJxEE6krQkKUi6NeACpGaFwYOUJRNt0zY9Z3+E6mXM36JuRvCY/aQxsaCT8sT9xzLqqEts79cv+KI6RG/fICBIaMLexCe01s4npZY6qyNSYvnPkQF/GJ0D6CJQpsQ2xaDQ07GtyKh6//w+vDUCRsAIbFUESNXNEpmkULpNKbcZJTFlUpqslTKnHig1BCEdVBKRzjn24P2DiKZKSU0eNlDLPO9aktCfBAlN2PuPY72YSVoKmlRdKKMgow51lJTRAF2b6+9eXLPgS7J13xNzoqjJoHLo3IDxAPKpWqsxHGAk4Jjc8RsiY7mL3JUbowTEA+lAGkygxbwBaVC7gjhwBUaoHoZxgqapjcj7tM3HrVl+VdS5qHWt+ctlZVwVr3Me84yY+BrmC5HRHV87vzjmkFGhfhIRiYSkiCbus1NxiJbEZt+YFrWj6heflz9gfR6IqUoiPRFOV69Xr9F4zITR0llXvb8fGwEjYAS2KgJaBTPIaLbSbARqB2KiBjQDYpJSmqzUHGQ0fcQeoYhQUSiiYxTTpIiOHLp7pOUm7ruzSOhTIqBEQuP3+mQxbk8NvFJILcmoVEek6bj2zJGDitmj9yqumX96uO1Ip5Fi++WPXgzlk9sKoYRoJUQ9iFQck04TCT0mK3mq3XzvoduieWk2XmCcwHyBsSC3BYIwMEygYDBYUOMhmMhbjbRfr3Ocgloa56W4JIiHa1WvF3U22d5pcEurorlHjA0SGSmzAkaGQ/bdKVQR6oi0HRNjSdXRIRriafWlq4NDHTs4MVzHcFyDRLJq0rYr8qnubz6v8rzW6t7eZwSMgBHYqghokbEaJHQModrPMeOIDmIiBQcZRY1IqTmIiGNSeu4zxZThe4QamiDCgYTG772T0k6JhMYO4hf/jiKkHUVG/Vooo37FFNWNpg4fEGQ0a9SexRyR4Fy9j2XnnKyuDt8OhxpW87x2UcyBEgElElofNnQMBGltojsi5Zbt4dmlh0WcSbMQCSQRPenk1iOFlkJGCpFGdEavbMNgoefZaJGPp58dtu1OsazpuV7nepg+rjnvtGLu4WODJBj0UTeQD4qIFB2RyQgjQ9VZ1/zlSxXVOT/W4NGxPK4QybseR/2m6qArSavLc6yKmiH3cyNgBN4LBDAxzFW6bY4I4NiDB0ck1ZOIabaICbv2bJHEsSIhjkExkZpDEWHfDhLaayeRTmcSYgXN0QN3kHX5Y1E3olaU60UYGIh2GRhIz0FEx47bt/i8rn/8BN7P4OLs2Z8NKzjzkDAOkHrboA4NmBAgIIwHeZIs9R1Wa4WAUD80RIV8WA4c0ggiCXJIy2/Qs45JtHQCx8F3WxfBaxE6juMJzm3ueQfpYEVPW/rgpWO4/gVfmNmhVkoyoA6EEsK8QIouk9HIXdOibqigrr7/qCOVyijW3CF1R11J0SXJ9ERCvN6Ftbur9+H9RsAIGIE+ReD4iQfUUTvUgHJkhxxkpNeLEyYOKeaKJKaP2qc4XG65Q/frFyREGo5ABSUlJAIqSWjU7nKJDVD6STGpJJ/J2k5p21VqSDUigvSfnHmk5+ZyL90Dcjx2wpBIAx590J7FTUvmR20HxYPZgGUhWD8oExC1nCCg65oIqCQfiANSgHCiOeol50X7Ihqk0lSV7bJzTok5U8yb6gj2peB1onbuqcUdly+M8+nyvVLXWqkOFHShaAQNWLW/Jgv80rNOKuYcNqYlSUAeKKHRUkkEaocu03KmEbWevuSyAWiN65CyQ1GFquoN8ZTHZOebbdc9oe3XjYAR2OoIHNk2oIbigQQaqbrSrj1rzGcKCAE1hBKChEjJUQ8iBUeM3mMHWbiJP4rlmlm2OUhot7R88wj92p8sAsI9F0pIJAQBzVCdaA5GiFIRnRBEpPeh7Uzd96hhKQXIPeZNnhApNlJuLA3Btnk5CNTPPUs7Fh4M8hFJQBqZcK4862RNxJ1eHHfEuOKMWe21KrhYj3u1UmgXg/3UscOLHL1VKJgRIKRGayA9V21ns0wE2MIV3SokyIf3FtvyPoOdmqv+GfixETAC7ycC00U2GBLCpi3TAlsIgf0QUru6K2BQgBiy4hmxmyZrqiBPGi4rILYjNImT4LUoyCuNNF3mhFmayzRjxKCUllP9CfIhLXeiVNfxKK+Dh8S9JqsOxTyl0QM/rmskxTBM1yBIebEMBKSTajIL43mk3CrKp0o+533+c0E+WQVUB+JWmMeg3gXh9JZkNvW4rG507z5ZbyerppKgIKmOEPnYMdfqm/c+I2AE3ncEDm/r304dCNKZNmKvcMlN1ZZ9KCOMCiijI2TfTkSxowhnB5HNxzRZc/timFJEWqK5GKotj+M5W/YpxuzxiSAeUnHHSXXNO6ytOG3SQcW8Q9uK41BEinbd53BdH0LLJMb1InSNthQM1gys7Tdq5Vs1aK3ddPE59UiznZPSYqgeopl8QnEo/cVA3JvBOO7TZKPeVJLZpOP7iIje9z8mvwEjYASMQF8goJRbDfPBKEVHKk7PlYYbmVNwKKBSGUEcxHBC6oXISiYIqiSkaQcOqs87fKiIaFhxqojoRG3nKDV45NCB4biL6+jcyjl1EVCDfPris23ONYKURGIxvwdyytGX6omUmTsUbM7X43OMgBH4sCMQg3CZ3hnab7s6ZJNJppl0Yj8qpiQetkEkFTLJg23bp7eriXiIuo5jEM6Ek1NJ7fnYbQ3jsmloByFtpnJqqDbOtyLa1r5mvx8jYAQ+KAhAFt3FB+VzbMn7HFwS9QEiFKKakmuQTWkWqD4vnWuRatxWSXdLcPG5RsAIGAEj8D4j0B1Bm3je5y/HtzcCRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbACBgBI2AEjIARMAJGwAgYASNgBIyAETACRsAIGAEjYASMgBEwAkbgw43A/wPcLkcE7ES8wQAAAABJRU5ErkJggg==" alt="빨리하자"> 자산관리 <b>빨리하자</b></span></div>
  <header>
    <h1><span class="dot">●</span> 내 자산관리 대시보드</h1>
    <div class="updated">업데이트 <b id="updated">불러오는 중…</b> · 60초마다 자동</div>
  </header>
  <div style="display:flex;justify-content:flex-end;gap:8px;margin:8px 2px 0">
    <button class="btn ghost" id="btn-export" style="padding:6px 12px;font-size:12px">💾 내보내기(백업)</button>
    <button class="btn ghost" id="btn-import" style="padding:6px 12px;font-size:12px">📂 불러오기(복원)</button>
    <button class="btn ghost" id="btn-logout" style="padding:6px 12px;font-size:12px;display:none">🚪 로그아웃</button>
    <input type="file" id="file-import" accept="application/json,.json" style="display:none">
  </div>
  <div class="tabs">
    <div class="tab active" data-tab="market">📈 시장현황</div>
    <div class="tab" data-tab="asset">💼 종합(내 주식)</div>
    <div class="tab" data-tab="networth">🏦 자산현황</div>
    <div class="tab" data-tab="ledger">📒 가계부</div>
  </div>
  <div class="members" id="member-bar" style="display:none">
    <span class="mlabel">가족 보기</span>
    <span id="member-btns"></span>
    <button class="mbtn add" id="member-add">＋ 가족 추가</button>
    <button class="mbtn add" id="group-add">＋ 합치기 탭</button>
  </div>
  <div class="err" id="err"></div>
  <div id="save-warn" style="display:none;background:#2a2010;border:1px solid #5a4a1a;color:#f5c451;
    padding:11px 15px;border-radius:10px;font-size:13px;margin-top:10px;line-height:1.6">
    ⚠️ 지금 <b>파일 저장</b>이 잘 안 되고 있어요. 하지만 <b>입력하신 자료는 이 브라우저 안에 안전하게 백업</b>돼 있으니 사라지지 않아요.
    폴더의 <b>「저장진단」</b>을 실행해서 원인을 확인해 주세요. (자세한 건 아래 사용법 참고)
  </div>

  <!-- 탭1 시장현황 -->
  <div class="page active" id="page-market">
    <div class="sec-title">글로벌 지수</div>
    <div class="grid idx-grid" id="indices"></div>
    <div class="sec-title">환율 · 금 · 가상자산</div>
    <div class="grid idx-grid" id="assets"></div>
    <div class="sec-title">한국 · 미국 금리</div>
    <div class="rate-wrap">
      <div class="rate-card"><h3>🇰🇷 한국 금리</h3><div id="rates_kr"></div></div>
      <div class="rate-card"><h3>🇺🇸 미국 금리</h3><div id="rates_us"></div></div>
    </div>
    <div class="sec-title">투자심리 · 변동성</div>
    <div class="bottom-wrap">
      <div class="card"><div class="top"><span class="name">공포탐욕지수</span></div><div id="fg"></div></div>
      <div class="card"><div class="top"><span class="name">VIX 변동성지수</span>
        <span class="country">S&P500 변동성</span></div><div id="vix"></div></div>
    </div>
  </div>

  <!-- 탭2 종합(내 주식) -->
  <div class="page" id="page-asset">
    <div class="sec-title">내 주식 요약 (실시간)</div>
    <div class="grid stat-grid" id="asset-stats"></div>
    <div class="sec-title">주식 추가</div>
    <div class="form">
      <div class="fld"><label>가족</label><select id="s-member"></select></div>
      <div class="fld"><label>증권사</label><input id="s-broker" list="brokers" placeholder="예: 키움증권" size="8">
        <datalist id="brokers"><option>키움증권</option><option>한국투자증권</option><option>삼성증권</option>
          <option>미래에셋증권</option><option>NH투자증권</option><option>KB증권</option><option>신한투자증권</option>
          <option>토스증권</option><option>대신증권</option></datalist></div>
      <div class="fld"><label>계좌종류</label><input id="s-account" list="accounts" placeholder="예: 일반계좌" size="8">
        <datalist id="accounts"><option>일반계좌</option><option>연금계좌</option><option>ISA계좌</option>
          <option>국내계좌</option><option>해외계좌</option></datalist></div>
      <div class="fld"><label>종목명</label><input id="s-name" placeholder="예: 삼성전자" size="8"></div>
      <div class="fld"><label>시장</label>
        <select id="s-market"><option>코스피</option><option>코스닥</option><option>미국주식</option><option>암호화폐</option><option>금현물</option></select></div>
      <div class="fld"><label>종목코드/티커</label><input id="s-code" placeholder="예: 005930" size="9"></div>
      <div class="fld"><label>수량</label><input id="s-qty" data-comma placeholder="10" size="6"></div>
      <div class="fld"><label>평균매입가</label><input id="s-avg" data-comma placeholder="70000" size="8"></div>
      <button class="btn" id="s-add">＋ 추가</button>
    </div>
    <div class="hint">코스피/코스닥은 <b>종목코드 6자리</b>(삼성전자 005930), 미국주식은 <b>티커</b>(AAPL),
      암호화폐는 <b>심볼</b>(BTC, ETH). 증권사·계좌종류별로 묶어서 보여드려요.</div>
    <div class="tbl-wrap" id="stock-tbl"></div>
    <div class="sec-title">계좌별 매입원금 · 수익 (원금 위에 수익이 쌓여 평가액)</div>
    <div class="chart-card"><div id="acct-cp"></div></div>
  </div>

  <!-- 탭3 자산현황 -->
  <div class="page" id="page-networth">
    <div class="month-nav">
      <button class="nav-btn" id="nw-prev">‹</button>
      <div class="m" id="nw-month"></div>
      <button class="nav-btn" id="nw-next">›</button>
    </div>
    <div class="month-nav" style="margin:0 0 10px">
      <button class="btn ghost" id="nw-copy">지난 달 항목 불러오기 (금액 제외)</button>
      <span class="autosave" id="nw-saved"></span>
    </div>
    <div class="grid stat-grid" id="nw-stats"></div>
    <div class="hint" id="nw-hint-all" style="display:none;color:#f5c451">합산 보기(‘전체’ · 합친 탭)는 <b>읽기 전용</b>이에요.
      입력하려면 위 <b>가족 보기</b>에서 가족을 <b>한 명</b> 골라 주세요.</div>
    <div class="hint">각 항목에 <b>세부 내역</b>을 자유롭게 추가하세요(예: 부동산 → 우리집·상가).
      <b>투자</b>에는 종합 탭의 주식이 <b>계좌별로 자동</b>으로 들어가요. 입력하면 <b>자동 저장</b>돼요.</div>
    <div class="sec-title">이 달 자산 (숫자는 원 단위)</div>
    <div class="members" id="nw-cat-tabs" style="margin:0 0 14px"></div>
    <div class="nw-grid" id="nw-cats"></div>
    <div class="two" style="margin-top:14px">
      <div class="chart-card"><h3>순자산 추이 (월별)</h3><div class="chart-scroll" id="nw-trend"></div></div>
      <div class="chart-card"><h3>이 달 자산 구성</h3><div id="nw-donut"></div></div>
    </div>
  </div>

  <!-- 탭4 가계부 -->
  <div class="page" id="page-ledger">
    <div class="month-nav">
      <button class="nav-btn" id="prev-m">‹</button>
      <div class="m" id="cur-month"></div>
      <button class="nav-btn" id="next-m">›</button>
    </div>
    <div class="sec-title">이 달 자산 기록 (직접 입력 · 매월 고정 저장)</div>
    <div class="form">
      <div class="fld"><label>총자산(원)</label><input id="ma-total" data-comma placeholder="0"></div>
      <div class="fld"><label>부채(원)</label><input id="ma-debt" data-comma placeholder="0"></div>
      <div class="fld"><label>순자산 (총자산−부채, 자동)</label>
        <input id="ma-net" readonly style="background:#12303a;color:#5fd0e0;font-weight:700;"></div>
      <span class="autosave" id="ma-saved"></span>
    </div>
    <div class="hint">자산현황의 <b>투자는 실시간</b>이라 매월 값이 바뀌어요. 여기에 그 달의 총자산·부채를
      직접 적어두면 <b>그 달 숫자로 고정</b>돼서 나중에 비교하기 좋아요. 입력하면 자동 저장돼요.</div>
    <div class="grid stat-grid" id="ledger-stats"></div>
    <div class="chart-card" style="margin:14px 0"><h3>월별 수입 vs 지출</h3><div class="chart-scroll" id="l-barchart"></div></div>
    <div class="two" style="margin:14px 0">
      <div class="chart-card"><h3>이 달 수입 구성</h3><div id="l-donut-inc"></div></div>
      <div class="chart-card"><h3>이 달 지출 구성</h3><div id="l-donut"></div></div>
    </div>
    <div class="sec-title">내역 추가</div>
    <div class="form">
      <div class="fld"><label>가족</label><select id="l-member"></select></div>
      <div class="fld"><label>날짜</label><input id="l-date" type="date"></div>
      <div class="fld"><label>구분</label>
        <select id="l-type"><option>변동지출</option><option>고정지출</option><option>수입</option></select></div>
      <div class="fld"><label>분류</label>
        <div style="display:flex;gap:4px;align-items:center">
          <select id="l-cat"></select>
          <button class="btn ghost" id="l-cat-add" title="분류 추가" style="padding:9px 11px;font-weight:700">＋</button>
        </div></div>
      <div class="fld"><label>금액(원)</label><input id="l-amt" data-comma placeholder="15000" size="8"></div>
      <div class="fld"><label>메모</label><input id="l-memo" placeholder="예: 점심 식사" size="11"></div>
      <button class="btn" id="l-add">＋ 추가</button>
      <button class="btn ghost" id="l-cancel" style="display:none">취소</button>
    </div>
    <div class="sec-title">이 달 내역</div>
    <div class="tbl-wrap" id="ledger-tbl"></div>
  </div>

  <footer>
    데이터 출처: 지수·주가·금·코인·VIX·환율 — 야후 파이낸스 / 금리 — 네이버 금융 /
    공포탐욕지수 — CNN·alternative.me<br>
    ※ 투자 참고용입니다. 투자 판단과 책임은 본인에게 있어요. 내 기록은 이 PC 안에만 저장됩니다.
  </footer>
</div>

<script>
const $ = s => document.querySelector(s);
function cls(v){ return v>0?"up":(v<0?"down":"flat"); }
function arrow(v){ return v>0?"▲":(v<0?"▼":"―"); }
function fmt(n,d){ if(n===null||n===undefined||isNaN(n)) return "-";
  return Number(n).toLocaleString("ko-KR",{minimumFractionDigits:d,maximumFractionDigits:d}); }
function won(n){ if(n===null||n===undefined||isNaN(n)) return "-";
  return Math.round(n).toLocaleString("ko-KR")+"원"; }
function manwon(n){ // 만원 단위 짧게
  if(n===null||n===undefined||isNaN(n)) return "-";
  const m=Math.round(n/10000); return m.toLocaleString("ko-KR")+"만"; }
function showErr(m){ const e=$("#err"); e.style.display="block"; e.textContent=m; }
function clearErr(){ $("#err").style.display="none"; }

// ===== 숫자 입력칸에 천단위 쉼표 자동 =====
function groupNum(str){ str=String(str==null?"":str); const neg=str.trim().charAt(0)==="-";
  str=str.replace(/[^0-9.]/g,""); const dot=str.indexOf(".");
  let ip,dp=null;
  if(dot>=0){ ip=str.slice(0,dot).replace(/\./g,""); dp=str.slice(dot+1).replace(/\./g,""); }
  else ip=str;
  ip=ip.replace(/^0+(?=\d)/,"");
  const g=ip.replace(/\B(?=(\d{3})+(?!\d))/g,",");
  return (neg?"-":"")+(dot>=0?g+"."+dp:g); }
function numVal(sel){ const el=typeof sel==="string"?$(sel):sel; if(!el) return NaN;
  return parseFloat(String(el.value).replace(/,/g,"")); }
function setNum(sel,v){ const el=typeof sel==="string"?$(sel):sel; if(!el) return;
  el.value=(v===""||v===null||v===undefined||isNaN(v))?"":groupNum(String(v)); }
function attachComma(el){ if(!el||el._comma) return; el._comma=1;
  el.type="text"; el.setAttribute("inputmode","decimal"); el.setAttribute("autocomplete","off");
  el.addEventListener("input",()=>{ const before=el.value.slice(0,el.selectionStart||0);
    const nb=(before.match(/[0-9]/g)||[]).length; el.value=groupNum(el.value);
    let pos=0,seen=0; while(pos<el.value.length&&seen<nb){ const c=el.value.charCodeAt(pos); if(c>=48&&c<=57)seen++; pos++; }
    if(el.setSelectionRange){ try{el.setSelectionRange(pos,pos);}catch(e){} } }); }
function commaInit(root){ (root||document).querySelectorAll("input[data-comma]").forEach(attachComma); }

// 네트워크 요청 (실패하면 자동으로 몇 번 더 시도해서 간헐적 끊김을 넘김)
async function fetchJSON(url, opts, tries=3){
  let last;
  for(let i=0;i<tries;i++){
    try{
      const ctrl=new AbortController();
      const to=setTimeout(()=>ctrl.abort(), 20000);
      const r=await fetch(url, Object.assign({cache:"no-store", signal:ctrl.signal}, opts||{}));
      clearTimeout(to);
      if(!r.ok) throw new Error("HTTP "+r.status);
      return await r.json();
    }catch(e){
      last=e;
      if(i<tries-1) await new Promise(res=>setTimeout(res, 500*(i+1)));
    }
  }
  throw last;
}

// ===== 브라우저 이중 백업 (서버 저장이 실패해도 자료가 안 사라지게) =====
const LS={holdings:"awm_holdings_v1", ledger:"awm_ledger_v1", networth:"awm_networth_v1", members:"awm_members_v1", groups:"awm_groups_v1", cats:"awm_cats_v1", manual:"awm_manual_v1", lcats:"awm_lcats_v1"};
function lsGet(k){ try{ const v=localStorage.getItem(k); return v==null?null:JSON.parse(v); }catch(e){ return null; } }
function lsSet(k,v){ try{ localStorage.setItem(k, JSON.stringify(v)); return true; }catch(e){ return false; } }
let serverSaveFailed=false;
function markSaveFail(){ serverSaveFailed=true; const w=$("#save-warn"); if(w) w.style.display="block"; }
function markSaveOk(){ if(!serverSaveFailed) return; }

const PALETTE=["#f5c451","#4d8dff","#37c26a","#c58bff","#5fd0e0","#ff8f8f","#ffb060","#8fd44d","#e879c9","#7aa0ff"];

// ===== SVG 차트 =====
function svgDonut(items){
  const arr=items.filter(i=>i.value>0);
  const total=arr.reduce((s,i)=>s+i.value,0);
  if(total<=0) return `<div class="empty">표시할 데이터가 없어요.</div>`;
  const R=72,r=46,cx=90,cy=90; let a0=-Math.PI/2,paths="";
  arr.forEach(it=>{
    const frac=it.value/total, a1=a0+frac*2*Math.PI, big=frac>0.5?1:0;
    const p=(ra,an)=>[cx+ra*Math.cos(an),cy+ra*Math.sin(an)];
    const[x0,y0]=p(R,a0),[x1,y1]=p(R,a1),[xi1,yi1]=p(r,a1),[xi0,yi0]=p(r,a0);
    paths+=`<path d="M${x0} ${y0} A${R} ${R} 0 ${big} 1 ${x1} ${y1} L${xi1} ${yi1} A${r} ${r} 0 ${big} 0 ${xi0} ${yi0} Z" fill="${it.color}"/>`;
    a0=a1;
  });
  const legend=arr.map(i=>`<div class="lg"><span class="sw" style="background:${i.color}"></span>${i.label}
    <b>${won(i.value)}</b><span class="pc">${(i.value/total*100).toFixed(0)}%</span></div>`).join("");
  return `<div class="donut-wrap"><svg viewBox="0 0 180 180" width="170" height="170">${paths}
    <text x="90" y="86" text-anchor="middle" fill="#8a94a6" font-size="11">합계</text>
    <text x="90" y="104" text-anchor="middle" fill="#e8edf4" font-size="13" font-weight="700">${manwon(total)}원</text>
    </svg><div class="legend">${legend}</div></div>`;
}
function svgTrend(points){ // [{label, net}]
  if(!points.length) return `<div class="empty">저장된 달이 없어요. 자산현황을 저장하면 추이가 그려져요.</div>`;
  const W=Math.max(360,points.length*90), H=230, padL=54,padR=20,padT=16,padB=34;
  const vals=points.map(p=>p.net); let max=Math.max(...vals,0),min=Math.min(...vals,0);
  if(max===min){max+=1;min-=1;} const rng=max-min;
  const X=i=>padL+(points.length===1?(W-padL-padR)/2:i/(points.length-1)*(W-padL-padR));
  const Y=v=>padT+(1-(v-min)/rng)*(H-padT-padB);
  let grid="";
  for(let g=0;g<=3;g++){ const v=min+rng*g/3, y=Y(v);
    grid+=`<line x1="${padL}" y1="${y}" x2="${W-padR}" y2="${y}" stroke="#242c3a"/>
      <text x="${padL-6}" y="${y+4}" text-anchor="end" fill="#6b7484" font-size="10">${manwon(v)}</text>`; }
  const pts=points.map((p,i)=>[X(i),Y(p.net)]);
  const line=pts.map((p,i)=>(i?"L":"M")+p[0]+" "+p[1]).join(" ");
  const area=line+` L${pts[pts.length-1][0]} ${H-padB} L${pts[0][0]} ${H-padB} Z`;
  let dots=pts.map((p,i)=>`<circle cx="${p[0]}" cy="${p[1]}" r="4" fill="#f5c451"/>
    <text x="${p[0]}" y="${p[1]-10}" text-anchor="middle" fill="#e8edf4" font-size="10" font-weight="700">${manwon(points[i].net)}</text>
    <text x="${p[0]}" y="${H-padB+16}" text-anchor="middle" fill="#8a94a6" font-size="10">${points[i].label.slice(2)}</text>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">${grid}
    <path d="${area}" fill="url(#g1)" opacity="0.25"/>
    <path d="${line}" fill="none" stroke="#f5c451" stroke-width="2.5"/>
    <defs><linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#f5c451"/><stop offset="1" stop-color="#f5c451" stop-opacity="0"/></linearGradient></defs>
    ${dots}</svg>`;
}
function svgGroupBars(months){ // [{label, income, expense}]
  if(!months.length) return `<div class="empty">가계부 내역을 넣으면 그래프가 그려져요.</div>`;
  const W=Math.max(360,months.length*88),H=230,padL=54,padR=14,padT=16,padB=34;
  const max=Math.max(...months.flatMap(m=>[m.income,m.expense]),1);
  const Y=v=>padT+(1-v/max)*(H-padT-padB);
  const bw=18, grp=(W-padL-padR)/months.length;
  let grid="";
  for(let g=0;g<=3;g++){ const v=max*g/3,y=Y(v);
    grid+=`<line x1="${padL}" y1="${y}" x2="${W-padR}" y2="${y}" stroke="#242c3a"/>
      <text x="${padL-6}" y="${y+4}" text-anchor="end" fill="#6b7484" font-size="10">${manwon(v)}</text>`; }
  let bars=months.map((m,i)=>{
    const cx=padL+grp*i+grp/2;
    const yi=Y(m.income),ye=Y(m.expense);
    return `<rect x="${cx-bw-2}" y="${yi}" width="${bw}" height="${H-padB-yi}" rx="3" fill="#ff5b5b"/>
      <rect x="${cx+2}" y="${ye}" width="${bw}" height="${H-padB-ye}" rx="3" fill="#4d8dff"/>
      <text x="${cx}" y="${H-padB+16}" text-anchor="middle" fill="#8a94a6" font-size="10">${m.label.slice(2)}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">${grid}${bars}</svg>
    <div class="legend" style="display:flex;gap:16px;margin-top:6px">
      <div class="lg"><span class="sw" style="background:#ff5b5b"></span>수입</div>
      <div class="lg"><span class="sw" style="background:#4d8dff"></span>지출</div></div>`;
}
function svgVenn(items){ // [{label, value, pl, plpct, color}]
  const arr=items.filter(i=>i.value>0);
  if(!arr.length) return `<div class="empty">주식을 추가하면 계좌종류별로 평가금액·수익을 보여드려요.</div>`;
  const n=arr.length, maxV=Math.max(...arr.map(i=>i.value));
  const W=560, H=(n<=2?260:340), cx=280, cy=H/2;
  const minR=44, maxR=(n<=2?90:80);
  const clusterR = (n===1?0 : n===2?66 : 96);
  const rad=v=> minR+(maxR-minR)*Math.sqrt(v/maxV);
  let circles="", labels="";
  arr.forEach((it,idx)=>{
    const ang=-Math.PI/2 + idx*2*Math.PI/n;
    const px=cx+clusterR*Math.cos(ang), py=cy+clusterR*Math.sin(ang), r=rad(it.value);
    circles+=`<circle cx="${px}" cy="${py}" r="${r}" fill="${it.color}" fill-opacity="0.42" stroke="${it.color}" stroke-width="2"/>`;
    const plc=it.pl>=0?"#ff5b5b":"#4d8dff";
    labels+=`<text x="${px}" y="${py-7}" text-anchor="middle" fill="#ffffff" font-size="14" font-weight="700">${it.label}</text>
      <text x="${px}" y="${py+11}" text-anchor="middle" fill="#e8edf4" font-size="12.5">${manwon(it.value)}원</text>
      <text x="${px}" y="${py+28}" text-anchor="middle" fill="${plc}" font-size="11.5" font-weight="700">${it.pl>=0?"+":""}${it.plpct.toFixed(1)}%</text>`;
  });
  const legend=arr.map(i=>{ const plc=i.pl>=0?"up":"down";
    return `<div class="lg"><span class="sw" style="background:${i.color}"></span>${i.label}
      <b>${won(i.value)}</b> <span class="${plc}" style="font-size:12px">${i.pl>=0?"+":""}${won(i.pl)} (${i.pl>=0?"+":""}${i.plpct.toFixed(1)}%)</span></div>`; }).join("");
  return `<div class="donut-wrap"><svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:${W}px">${circles}${labels}</svg>
    <div class="legend">${legend}</div></div>`;
}

// 매입원금·수익 가로 막대 (원금 회색 + 수익 빨강 / 손실 파랑)
function barsCostProfit(items){
  const arr=items.filter(i=>i.cost>0||i.value>0);
  if(!arr.length) return `<div class="empty">주식을 추가하면 계좌별 원금·수익을 보여드려요.</div>`;
  const maxScale=Math.max(...arr.map(i=>Math.max(i.cost,i.value)),1);
  const rows=arr.map(i=>{
    const pl=i.value-i.cost, pct=i.cost?(pl/i.cost*100):0, gain=pl>=0;
    const grayW=(gain?i.cost:i.value)/maxScale*100;
    const colorW=Math.abs(pl)/maxScale*100;
    return `<div class="cp-row">
      <div class="cp-top"><span class="cp-label">${i.label}</span>
        <span class="cp-val">평가 ${won(i.value)}</span></div>
      <div class="cp-bar">
        <div class="cp-seg cp-cost" style="width:${grayW}%"></div>
        <div class="cp-seg ${gain?'cp-up':'cp-down'}" style="width:${colorW}%"></div></div>
      <div class="cp-sub">매입원금 ${won(i.cost)} ·
        <span class="${gain?'up':'down'}">수익 ${gain?'+':'-'}${won(Math.abs(pl))} (${gain?'+':''}${pct.toFixed(1)}%)</span></div>
    </div>`;
  }).join("");
  return `<div class="cp-legend"><span><i class="cp-sw cp-cost"></i>매입원금(넣은 돈)</span>
    <span><i class="cp-sw cp-up"></i>수익</span><span><i class="cp-sw cp-down"></i>손실</span></div>${rows}`;
}

// ===== 시장현황 =====
function idxCard(it){
  const c=cls(it.pct);
  const chg=(it.change===null)?"-":`${arrow(it.change)} ${fmt(Math.abs(it.change),it.dec)} (${fmt(Math.abs(it.pct),2)}%)`;
  return `<div class="card"><div class="top"><span class="name">${it.name}</span>
    <span class="country">${it.country}</span></div><div class="price">${fmt(it.price,it.dec)}</div>
    <div class="chg ${c}">${chg}</div></div>`;
}
function rateRows(list){ return list.map(r=>{
  const c=cls(r.change);
  const chg=(r.change===null)?"":`<div class="rate-chg ${c}">${arrow(r.change)} ${fmt(Math.abs(r.change),3)}%p</div>`;
  return `<div class="rate-row"><div class="rate-label"><span class="tag ${r.tag}">${r.tag}</span>${r.label}</div>
    <div class="rate-val"><div class="rate-num">${fmt(r.price,3)}%</div>${chg}</div></div>`; }).join(""); }
function fgBlock(fg){
  if(!fg) return `<div class="gauge-num flat">-</div><div class="gauge-rating flat">불러오지 못했어요</div>`;
  const kr={"Extreme Fear":"극도의 공포","Fear":"공포","Neutral":"중립","Greed":"탐욕","Extreme Greed":"극도의 탐욕"};
  const label=kr[fg.rating]||fg.rating||""; let color="#e8d44d";
  if(fg.score<25)color="#ff5b5b";else if(fg.score<45)color="#ff9d3b";
  else if(fg.score<55)color="#e8d44d";else if(fg.score<75)color="#8fd44d";else color="#37c26a";
  return `<div class="gauge-num" style="color:${color}">${fg.score}</div>
    <div class="gauge-rating" style="color:${color}">${label}</div>
    <div class="gauge-bar"><div class="gauge-mark" style="left:${fg.score}%"></div></div>
    <div class="gauge-scale"><span>0 공포</span><span>50 중립</span><span>100 탐욕</span></div>
    <div class="src">${fg.source||""}</div>`;
}
function vixBlock(v){
  if(!v) return `<div class="vix-num flat">-</div><div class="vix-state flat">불러오지 못했어요</div>`;
  const p=v.price; let s,color,desc;
  if(p<15){s="안정";color="#37c26a";desc="시장이 비교적 잔잔한 상태예요.";}
  else if(p<20){s="보통";color="#8fd44d";desc="평소 수준의 변동성이에요.";}
  else if(p<30){s="주의";color="#ff9d3b";desc="변동성이 커지고 있어요. 조심하세요.";}
  else{s="공포";color="#ff5b5b";desc="시장 불안이 큰 상태예요.";}
  const c=cls(v.change);
  const chg=(v.change===null)?"":`${arrow(v.change)} ${fmt(Math.abs(v.change),2)} (${fmt(Math.abs(v.pct),2)}%)`;
  return `<div class="vix-num" style="color:${color}">${fmt(p,2)}</div>
    <div class="vix-state" style="color:${color}">${s}</div>
    <div class="chg ${c}" style="text-align:center;margin-top:6px">${chg}</div>
    <div class="vix-desc">${desc}<br><span style="color:#6b7484">보통 20 아래면 안정, 30 위면 불안으로 봅니다.</span></div>`;
}
async function loadMarket(){
  const d=await fetchJSON("/api/market");
  $("#updated").textContent=d.updated+" (KST)";
  $("#indices").innerHTML=(d.indices||[]).map(idxCard).join("");
  $("#assets").innerHTML=[d.fx,...(d.assets||[])].filter(Boolean).map(idxCard).join("");
  $("#rates_kr").innerHTML=rateRows(d.rates_kr||[]);
  $("#rates_us").innerHTML=rateRows(d.rates_us||[]);
  $("#fg").innerHTML=fgBlock(d.fear_greed); $("#vix").innerHTML=vixBlock(d.vix);
}

// ===== 종합(내 주식) =====
let holdings=[], liveCache={total_krw:0};
async function loadHoldings(){ const srv=await fetchJSON("/api/portfolio_raw").catch(()=>undefined);
  const bak=lsGet(LS.holdings);
  if(srv&&srv.length) holdings=srv;            // 서버에 자료 있으면 우선(폰·PC 동기화)
  else if(bak&&bak.length) holdings=bak;        // 서버 비었으면 백업(→ 아래 restore가 서버로 올림)
  else holdings=(srv!==undefined?(srv||[]):(bak||[]));
  lsSet(LS.holdings, holdings); }
async function saveHoldings(){ lsSet(LS.holdings, holdings);   // 1) 브라우저 백업 (항상 성공)
  try{ await fetchJSON("/api/portfolio_raw",{method:"POST",
    headers:{"Content-Type":"application/json"},body:JSON.stringify(holdings)}); }
  catch(e){ markSaveFail(); throw e; } }
async function loadAsset(){
  const d=await fetchJSON("/api/portfolio_live");
  liveCache=d;
  // 가족 필터 (원래 순번 i는 삭제용으로 유지)
  const view=(d.rows||[]).map((r,i)=>({r,i})).filter(x=>memberMatch(x.r.member));
  let tVal=0,tCost=0;
  view.forEach(x=>{ tVal+=(x.r.val_krw||0); tCost+=(x.r.cost_krw||0); });
  const tPl=tVal-tCost, tPct=tCost?(tPl/tCost*100):0, plc=cls(tPl);
  const who=curMember==="전체"?"전체 가족":curMember;
  $("#asset-stats").innerHTML=`
    <div class="stat"><div class="lab">평가액 합계 (${who})</div><div class="big">${won(tVal)}</div>
      <div class="sub">투자원금 ${won(tCost)}</div></div>
    <div class="stat"><div class="lab">평가손익 합계</div>
      <div class="big ${plc}">${tPl>=0?"+":"-"}${won(Math.abs(tPl))}</div>
      <div class="sub">수익률 ${tPct>=0?"+":""}${tPct.toFixed(2)}%</div></div>
    <div class="stat"><div class="lab">기준 환율</div><div class="big">${fmt(d.usdkrw,1)}원</div>
      <div class="sub">1달러 기준</div></div>`;
  // 증권사·계좌종류별 그룹
  const groups={};
  view.forEach(({r,i})=>{ const k=(r.broker||"기타")+" · "+(r.account||"기타");
    (groups[k]=groups[k]||[]).push({r,i}); });
  let html=`<table><thead><tr><th class="l">종목</th><th>수량</th><th>평균가</th><th>현재가</th>
    <th>평가액(원)</th><th>손익</th><th>손익률</th><th></th></tr></thead><tbody>`;
  if(view.length===0){ html+=`<tr><td colspan="8" class="empty">${curMember==="전체"?"아직 등록한 주식이 없어요. 위에서 추가해 보세요.":curMember+" 이름으로 등록한 주식이 없어요."}</td></tr>`; }
  Object.keys(groups).forEach(key=>{
    const gr=groups[key];
    const sval=gr.reduce((s,x)=>s+(x.r.val_krw||0),0);
    const scost=gr.reduce((s,x)=>s+(x.r.cost_krw||0),0);
    const spl=sval-scost, spct=scost?(spl/scost*100):0, sc=cls(spl);
    html+=`<tr class="brk-row"><td class="l">🏢 ${key}</td><td colspan="3"></td>
      <td>${won(sval)}</td>
      <td class="${sc}">${spl>=0?"+":"-"}${won(Math.abs(spl))}</td>
      <td class="${sc}">${spct>=0?"+":""}${spct.toFixed(2)}%</td><td></td></tr>`;
    gr.forEach(({r,i})=>{
      const usd=r.currency==="USD"; const unit=usd?"$":"₩"; const dp=usd?2:0; const c=cls(r.pl);
      html+=`<tr data-i="${i}"><td class="l"><b>${r.name||"-"}</b> <span style="color:#6b7484;font-size:12px">${r.market} ${r.code}</span></td>
        <td class="c-qty" data-label="수량">${fmt(r.qty,0)}</td><td class="c-avg" data-label="평균가">${unit}${fmt(r.avg,dp)}</td>
        <td data-label="현재가">${r.price===null?"-":unit+fmt(r.price,dp)}</td><td data-label="평가액">${won(r.val_krw)}</td>
        <td class="${c}" data-label="손익">${r.pl===null?"-":(r.pl>=0?"+":"-")+unit+fmt(Math.abs(r.pl),dp)}</td>
        <td class="${c}" data-label="손익률">${r.plpct===null?"-":(r.plpct>=0?"+":"")+fmt(r.plpct,2)+"%"}</td>
        <td class="c-act"><button class="mini-btn edit" onclick="editHolding(${i})">✏️</button> <button class="mini-btn" onclick="delHolding(${i})">삭제</button></td></tr>`;
    });
  });
  if(view.length>0){
    html+=`<tr class="tot-row"><td class="l">합계</td><td colspan="3"></td>
      <td>${won(tVal)}</td><td>${tPl>=0?"+":"-"}${won(Math.abs(tPl))}</td>
      <td>${tPct>=0?"+":""}${tPct.toFixed(2)}%</td><td></td></tr>`;
  }
  html+=`</tbody></table>`; $("#stock-tbl").innerHTML=html;
  // 계좌종류별 집계 → 매입원금·수익 막대 (가족 필터 반영)
  const accs={};
  view.forEach(({r})=>{ const a=r.account||"기타"; const o=accs[a]=accs[a]||{val:0,cost:0};
    o.val+=(r.val_krw||0); o.cost+=(r.cost_krw||0); });
  const cp=Object.keys(accs).map(a=>({label:a, cost:accs[a].cost, value:accs[a].val}));
  $("#acct-cp").innerHTML=barsCostProfit(cp);
}
window.delHolding=async(i)=>{
  const removed=holdings.splice(i,1);
  try{ await saveHoldings(); clearErr(); }
  catch(e){ holdings.splice(i,0,...removed); showErr("삭제 저장에 실패했어요. 잠시 뒤 다시 시도해 주세요."); return; }
  loadAsset().catch(()=>{});  // 시세는 따로
};
// 수량·평균가 바로 수정 (인라인)
window.editHolding=(i)=>{
  const h=holdings[i]; if(!h) return;
  const tr=document.querySelector('#stock-tbl tr[data-i="'+i+'"]'); if(!tr) return;
  tr.querySelector(".c-qty").innerHTML='<input class="ed-qty" value="'+groupNum(h.qty)+'" style="width:66px;padding:5px;text-align:right">';
  tr.querySelector(".c-avg").innerHTML='<input class="ed-avg" value="'+groupNum(h.avg)+'" style="width:88px;padding:5px;text-align:right">';
  tr.querySelector(".c-act").innerHTML='<button class="mini-btn save" onclick="saveEdit('+i+')">저장</button> <button class="mini-btn" onclick="loadAsset()">취소</button>';
  attachComma(tr.querySelector(".ed-qty")); attachComma(tr.querySelector(".ed-avg"));
  const q=tr.querySelector(".ed-qty"); if(q){ q.focus(); q.select(); }
};
window.saveEdit=async(i)=>{
  const tr=document.querySelector('#stock-tbl tr[data-i="'+i+'"]'); if(!tr||!holdings[i]) return;
  const q=numVal(tr.querySelector(".ed-qty")), a=numVal(tr.querySelector(".ed-avg"));
  if(isNaN(q)||isNaN(a)){ alert("수량과 평균가를 숫자로 입력해 주세요."); return; }
  holdings[i].qty=q; holdings[i].avg=a;
  try{ await saveHoldings(); clearErr(); }
  catch(e){ showErr("수정 저장에 실패했어요. 잠시 뒤 다시 시도해 주세요."); return; }
  loadAsset().catch(()=>{});
};
$("#s-add").onclick=async()=>{
  const market=$("#s-market").value, isGold=(market==="금현물");
  const code=$("#s-code").value.trim(), name=$("#s-name").value.trim();
  const qty=numVal("#s-qty"), avg=numVal("#s-avg");
  if((!isGold && !code)||isNaN(qty)||isNaN(avg)){
    alert(isGold?"수량(그램)과 평균매입가(원/g)를 입력해 주세요.":"종목코드/티커, 수량, 평균매입가를 입력해 주세요."); return; }
  const item={name:name||(isGold?"금 현물":code), member:$("#s-member").value,
    broker:$("#s-broker").value.trim()||"기타",
    account:$("#s-account").value.trim()||"기타",
    market, code:code, qty, avg};
  const btn=$("#s-add"); const old=btn.textContent; btn.textContent="저장 중…"; btn.disabled=true;
  holdings.push(item);
  try{
    await saveHoldings();       // 1) 저장 먼저 (파일 기록이라 빠르고 안정적)
    clearErr();
    ["s-name","s-code","s-qty","s-avg"].forEach(id=>$("#"+id).value="");
  }catch(e){
    holdings.pop();
    showErr("저장에 실패했어요. 잠시 뒤 다시 [＋ 추가]를 눌러 주세요. ("+e+")");
    btn.textContent=old; btn.disabled=false; return;
  }
  btn.textContent=old; btn.disabled=false;
  // 2) 시세는 따로 불러오기 — 느리거나 실패해도 저장은 이미 끝났어요
  loadAsset().catch(()=>{ showErr("저장은 됐어요 ✓ 시세는 잠시 뒤 자동으로 다시 불러올게요."); });
};
const codeHints={"코스피":"예: 005930","코스닥":"예: 247540","미국주식":"예: AAPL","암호화폐":"예: BTC","금현물":"코드 없이 비워두세요"};
$("#s-market").onchange=()=>{ const g=$("#s-market").value==="금현물";
  $("#s-code").placeholder=codeHints[$("#s-market").value]||""; $("#s-code").disabled=g;
  $("#s-qty").placeholder=g?"그램(g)":"10"; $("#s-avg").placeholder=g?"원/g":"70000"; };

// ===== 자산현황 (가족별 · 세부항목) =====
let networth={}, nwMonth=(new Date()).toISOString().slice(0,7), nwCatView="전체";
const NW_DEFAULT_CATS=["부동산","현금","저축","투자","연금","보험"];
let nwCats=[...NW_DEFAULT_CATS];        // 자산 분류(사용자 추가 가능)
function nwAll(){ return [...nwCats,"부채"]; }   // 자산 + 부채
function renderNwCatTabs(){
  const tabs=["전체",...nwAll()].map(c=>{
    const removable = !NW_DEFAULT_CATS.includes(c) && c!=="부채" && c!=="전체";
    const x = removable ? `<span class="mx" data-c="${c}" title="분류 삭제">✕</span>` : "";
    return `<span class="mbtn${c===nwCatView?" active":""}" data-c="${c}">${c}${x}</span>`;
  }).join("");
  $("#nw-cat-tabs").innerHTML=tabs+`<button class="mbtn add" id="nw-cat-add">＋ 분류 추가</button>`;
  $("#nw-cat-tabs").querySelectorAll(".mbtn[data-c]").forEach(el=>{
    el.onclick=()=>{ nwCatView=el.dataset.c; renderNetworth(); }; });
  $("#nw-cat-tabs").querySelectorAll(".mx").forEach(el=>{
    el.onclick=(e)=>{ e.stopPropagation(); removeNwCat(el.dataset.c); }; });
  const addBtn=$("#nw-cat-add"); if(addBtn) addBtn.onclick=addNwCat;
}
async function addNwCat(){
  const name=(prompt("추가할 분류 이름을 적어 주세요 (예: 자동차, 귀금속, 대여금)")||"").trim();
  if(!name) return;
  if(name==="전체"||name==="부채"||nwCats.includes(name)){ alert("이미 있는 분류예요."); return; }
  nwCats.push(name); await saveMembers(); nwCatView=name; renderNetworth();
}
async function removeNwCat(c){
  // 어느 가족·달에든 항목이 있으면 삭제 막기 (자료 보호)
  let has=false;
  Object.values(networth).forEach(mm=>Object.values(mm||{}).forEach(s=>{ if((s[c]||[]).length) has=true; }));
  if(has){ alert("‘"+c+"’ 분류에 입력된 항목이 있어요.\n먼저 항목을 다른 분류로 옮기거나 지운 뒤에 삭제해 주세요."); return; }
  if(!confirm("‘"+c+"’ 분류를 삭제할까요?")) return;
  nwCats=nwCats.filter(x=>x!==c); if(nwCatView===c) nwCatView="전체";
  await saveMembers(); renderNetworth();
}
async function loadNetworth(){ const srv=await fetchJSON("/api/networth").catch(()=>undefined);
  const bak=lsGet(LS.networth);
  if(srv&&Object.keys(srv).length) networth=srv;
  else if(bak&&Object.keys(bak).length) networth=bak;
  else networth=(srv!==undefined?(srv||{}):(bak||{}));
  lsSet(LS.networth, networth); }
async function saveNetworth(){ lsSet(LS.networth, networth);
  try{ await fetchJSON("/api/networth",{method:"POST",
    headers:{"Content-Type":"application/json"},body:JSON.stringify(networth)}); }
  catch(e){ markSaveFail(); throw e; } }
function nwShift(delta){ saveNetworthNow(); let[y,m]=nwMonth.split("-").map(Number); m+=delta;
  if(m<1){m=12;y--;} if(m>12){m=1;y++;} nwMonth=`${y}-${String(m).padStart(2,"0")}`; renderNetworth(); }
$("#nw-prev").onclick=()=>nwShift(-1); $("#nw-next").onclick=()=>nwShift(1);
// 데이터 확보 (모든 분류를 배열로)
function nwEnsure(member,month){
  networth[member]=networth[member]||{};
  const s=networth[member][month]=networth[member][month]||{};
  nwAll().forEach(c=>{ if(!Array.isArray(s[c])) s[c]=[]; });
  return s;
}
// 특정 가족의 주식을 계좌별로 묶어 반환 (투자 자동연동)
function liveStockRows(member){
  const rows=(liveCache.rows||[]).filter(r=> (r.member||"공용")===member);
  const g={};
  rows.forEach(r=>{ const k=(r.broker||"기타")+"·"+(r.account||"기타"); g[k]=(g[k]||0)+(r.val_krw||0); });
  return Object.keys(g).map(k=>({name:k,amount:g[k]}));
}
// 현재 보기(가족 필터)의 분류별 항목 목록
function nwViewCats(){
  const cats={}; nwAll().forEach(c=>cats[c]=[]);
  const list = currentMembers();
  list.forEach(mem=>{
    const s=(networth[mem]||{})[nwMonth]||{};
    nwAll().forEach(c=>(s[c]||[]).forEach(it=>cats[c].push({name:it.name,amount:Number(it.amount)||0,manual:true,mem})));
    liveStockRows(mem).forEach(x=>cats["투자"].push({name:"[주식] "+x.name,amount:x.amount,manual:false,mem}));
  });
  return cats;
}
function nwCatSum(cats,cat){ return cats[cat].reduce((a,b)=>a+b.amount,0); }
// 자동 저장 (디바운스)
let nwSaveTimer=null;
function scheduleNwSave(){ $("#nw-saved").textContent="저장 중…"; clearTimeout(nwSaveTimer);
  nwSaveTimer=setTimeout(saveNetworthNow,700); }
async function saveNetworthNow(){ clearTimeout(nwSaveTimer);
  try{ await saveNetworth(); $("#nw-saved").textContent="저장됨 ✓"; clearErr(); }
  catch(e){ $("#nw-saved").textContent="저장 실패 — 잠시 뒤 자동 재시도"; } }
$("#nw-copy").onclick=()=>{
  if(isAggregateScope()) return;
  const ms=Object.keys(networth[curMember]||{}).filter(m=>m<nwMonth).sort();
  if(!ms.length){ alert("이전에 저장한 달이 없어요."); return; }
  const src=(networth[curMember]||{})[ms[ms.length-1]]||{};
  const dst=nwEnsure(curMember,nwMonth);
  // 항목 이름만 가져오고 금액은 빈 칸으로 (새 달 값은 직접 입력)
  nwAll().forEach(c=>{ dst[c]=(src[c]||[]).map(it=>({name:it.name,amount:0})); });
  saveNetworthNow(); renderNetworth();
};
function renderNetworth(){
  $("#nw-month").textContent=nwMonth;
  const isAll=isAggregateScope();
  $("#nw-hint-all").style.display=isAll?"block":"none";
  $("#nw-copy").style.display=isAll?"none":"inline-block";
  $("#nw-saved").textContent="";
  renderNwCatTabs();
  const cats=nwViewCats();
  let html="";
  nwAll().forEach(cat=>{
    if(nwCatView!=="전체" && cat!==nwCatView) return;   // 선택한 분류만 보기
    const sub=nwCatSum(cats,cat); const stc=cat==="부채"?"down":"";
    html+=`<div class="nw-cat"><h4>${cat} <span class="st ${stc}" data-stfor="${cat}">${won(sub)}</span></h4>`;
    // 자동(주식) 행 먼저 표시
    cats[cat].forEach(it=>{ if(it.manual===false){
      html+=`<div class="nw-item"><span class="auto">🔗 ${it.name}${isAll?" ("+it.mem+")":""}</span><span class="aval">${won(it.amount)}</span></div>`; }});
    if(isAll){
      cats[cat].forEach(it=>{ if(it.manual){
        html+=`<div class="nw-item"><span class="auto">${it.name||"(이름없음)"} <span style="color:#6b7484">(${it.mem})</span></span><span class="aval">${won(it.amount)}</span></div>`; }});
      if(cats[cat].length===0) html+=`<div class="nw-item"><span class="auto" style="color:#6b7484">내역 없음</span></div>`;
    } else {
      const s=(networth[curMember]||{})[nwMonth]||{};
      (s[cat]||[]).forEach((it,idx)=>{
        const nmv=(it.name||"").replace(/&/g,'&amp;').replace(/"/g,'&quot;');
        html+=`<div class="nw-item" data-cat="${cat}" data-idx="${idx}">
          <input class="nm" placeholder="항목명" value="${nmv}">
          <input class="am" data-comma placeholder="0" value="${it.amount?groupNum(it.amount):''}">
          <select class="mv" title="다른 분류로 옮기기">${nwAll().map(c=>`<option${c===cat?" selected":""}>${c}</option>`).join("")}</select>
          <button class="mini-btn nw-del">✕</button></div>`;
      });
      html+=`<button class="nw-add" data-cat="${cat}">＋ 항목 추가</button>`;
    }
    html+=`</div>`;
  });
  $("#nw-cats").innerHTML=html;
  if(!isAll) bindNwEditors();
  updateNwTotals();
}
function bindNwEditors(){
  $("#nw-cats").querySelectorAll(".nw-item[data-cat]").forEach(row=>{
    const cat=row.dataset.cat, idx=+row.dataset.idx;
    const nm=row.querySelector(".nm"), am=row.querySelector(".am"); attachComma(am);
    nm.oninput=()=>{ nwEnsure(curMember,nwMonth)[cat][idx].name=nm.value; scheduleNwSave(); };
    am.addEventListener("input",()=>{ nwEnsure(curMember,nwMonth)[cat][idx].amount=numVal(am)||0; updateNwTotals(); scheduleNwSave(); });
    const mv=row.querySelector(".mv");
    if(mv) mv.onchange=()=>{ const to=mv.value; if(to===cat) return;
      const s=nwEnsure(curMember,nwMonth); const item=s[cat].splice(idx,1)[0];
      s[to].push(item); saveNetworthNow(); renderNetworth(); };
    row.querySelector(".nw-del").onclick=()=>{ nwEnsure(curMember,nwMonth)[cat].splice(idx,1); saveNetworthNow(); renderNetworth(); };
  });
  $("#nw-cats").querySelectorAll(".nw-add").forEach(btn=>{
    btn.onclick=()=>{ const c=btn.dataset.cat; nwEnsure(curMember,nwMonth)[c].push({name:"",amount:0});
      renderNetworth();
      const rows=$("#nw-cats").querySelectorAll(`.nw-item[data-cat="${c}"] .nm`);
      if(rows.length) rows[rows.length-1].focus();
    };
  });
}
function updateNwTotals(){
  const cats=nwViewCats();
  nwAll().forEach(cat=>{ const el=$("#nw-cats").querySelector(`[data-stfor="${cat}"]`);
    if(el) el.textContent=won(nwCatSum(cats,cat)); });
  const asset=nwCats.reduce((a,c)=>a+nwCatSum(cats,c),0);
  const debt=nwCatSum(cats,"부채");
  const who=curMember==="전체"?"전체 가족":curMember;
  $("#nw-stats").innerHTML=`
    <div class="stat"><div class="lab">총자산 (${who})</div><div class="big">${won(asset)}</div></div>
    <div class="stat"><div class="lab">부채</div><div class="big down">${won(debt)}</div></div>
    <div class="stat"><div class="lab">순자산 (총자산−부채)</div>
      <div class="big ${asset-debt>=0?'up':'down'}">${won(asset-debt)}</div></div>`;
  // 추이
  const list=currentMembers();
  const mset=new Set(); list.forEach(mem=>Object.keys(networth[mem]||{}).forEach(m=>mset.add(m)));
  const trend=[...mset].sort().map(m=>{
    let a=0,d=0;
    list.forEach(mem=>{ const s=(networth[mem]||{})[m]||{};
      nwCats.forEach(c=>(s[c]||[]).forEach(it=>a+=Number(it.amount)||0));
      (s["부채"]||[]).forEach(it=>d+=Number(it.amount)||0);
      a+=liveStockRows(mem).reduce((x,y)=>x+y.amount,0); });
    return {label:m, net:a-d};
  });
  $("#nw-trend").innerHTML=svgTrend(trend);
  // 도넛 (분류별 자산 구성)
  const donut=nwCats.map((c,i)=>({label:c,value:nwCatSum(cats,c),color:PALETTE[i%PALETTE.length]}));
  $("#nw-donut").innerHTML=svgDonut(donut);
}

// ===== 가계부 =====
let ledger=[], curMonth=(new Date()).toISOString().slice(0,7);
const CATS={
  "수입":["급여","사업","이자/배당","용돈","기타"],
  "고정지출":["주거/월세","공과금","통신비","보험료","교육비","구독료","대출이자","기타"],
  "변동지출":["식비","생활용품","교통","의료","여가","쇼핑","외식","경조사","기타"]};
let ledgerCats={};   // 사용자 추가 분류 {구분:[...]}
function catsFor(t){
  const base=(CATS[t]||[]).filter(c=>c!=="기타");
  const custom=(ledgerCats[t]||[]).filter(c=>!base.includes(c) && c!=="기타");
  return [...base, ...custom, "기타"];
}
function fillCats(){ const t=$("#l-type").value; const cur=$("#l-cat").value;
  const list=catsFor(t);
  $("#l-cat").innerHTML=list.map(c=>`<option>${c}</option>`).join("");
  if(cur && list.includes(cur)) $("#l-cat").value=cur; }
$("#l-type").onchange=fillCats;
$("#l-cat-add").onclick=async()=>{
  const t=$("#l-type").value;
  const name=(prompt("‘"+t+"’에 추가할 분류 이름을 적어 주세요 (예: 반려동물, 미용)")||"").trim();
  if(!name) return;
  if(catsFor(t).includes(name)){ alert("이미 있는 분류예요."); return; }
  ledgerCats[t]=ledgerCats[t]||[]; ledgerCats[t].push(name);
  await saveMembers(); fillCats(); $("#l-cat").value=name; };
async function loadLedger(){ const srv=await fetchJSON("/api/ledger").catch(()=>undefined);
  const bak=lsGet(LS.ledger);
  if(srv&&srv.length) ledger=srv;
  else if(bak&&bak.length) ledger=bak;
  else ledger=(srv!==undefined?(srv||[]):(bak||[]));
  lsSet(LS.ledger, ledger); }
async function saveLedger(){ lsSet(LS.ledger, ledger);
  try{ await fetchJSON("/api/ledger",{method:"POST",
    headers:{"Content-Type":"application/json"},body:JSON.stringify(ledger)}); }
  catch(e){ markSaveFail(); throw e; } }
// ---- 이 달 자산 기록 (직접 입력 · 월별 고정) ----
let manualAssets={};
async function loadManual(){ const srv=await fetchJSON("/api/monthly").catch(()=>undefined);
  const bak=lsGet(LS.manual);
  if(srv&&Object.keys(srv).length) manualAssets=srv;
  else if(bak&&Object.keys(bak).length) manualAssets=bak;
  else manualAssets=(srv!==undefined?(srv||{}):(bak||{}));
  lsSet(LS.manual, manualAssets); }
async function saveManual(){ lsSet(LS.manual, manualAssets);
  try{ await fetchJSON("/api/monthly",{method:"POST",
    headers:{"Content-Type":"application/json"},body:JSON.stringify(manualAssets)}); }
  catch(e){ markSaveFail(); } }
let maSaveTimer=null;
function scheduleManualSave(){ $("#ma-saved").textContent="저장 중…"; clearTimeout(maSaveTimer);
  maSaveTimer=setTimeout(async()=>{ await saveManual(); $("#ma-saved").textContent="저장됨 ✓"; }, 700); }
function renderManual(){
  const s=manualAssets[curMonth]||{};
  const total=Number(s.total)||0, debt=Number(s.debt)||0;
  setNum("#ma-total", s.total?s.total:"");
  setNum("#ma-debt", s.debt?s.debt:"");
  $("#ma-net").value = won(total-debt);
}
function maUpdate(){
  const total=numVal("#ma-total")||0, debt=numVal("#ma-debt")||0;
  manualAssets[curMonth]={total, debt};
  $("#ma-net").value=won(total-debt);
  scheduleManualSave();
}
$("#ma-total").oninput=maUpdate; $("#ma-debt").oninput=maUpdate;
function shiftMonth(delta){ let[y,m]=curMonth.split("-").map(Number); m+=delta;
  if(m<1){m=12;y--;} if(m>12){m=1;y++;} curMonth=`${y}-${String(m).padStart(2,"0")}`; renderLedger(); }
$("#prev-m").onclick=()=>shiftMonth(-1); $("#next-m").onclick=()=>shiftMonth(1);
let editingLedgerIdx=null;
function cancelLedgerEdit(){ editingLedgerIdx=null; $("#l-add").textContent="＋ 추가";
  $("#l-cancel").style.display="none"; $("#l-amt").value=""; $("#l-memo").value=""; }
window.editLedger=(i)=>{ const e=ledger[i]; if(!e) return;
  $("#l-date").value=e.date||$("#l-date").value;
  if([...$("#l-member").options].some(o=>o.value===(e.member||""))) $("#l-member").value=e.member||"";
  $("#l-type").value=e.type||"변동지출"; fillCats();
  const cat=e.category||""; const sel=$("#l-cat");
  if(cat && ![...sel.options].some(o=>o.value===cat)){ const op=document.createElement("option"); op.value=cat; op.textContent=cat; sel.appendChild(op); }
  if(cat) sel.value=cat;
  setNum("#l-amt", e.amount); $("#l-memo").value=e.memo||"";
  editingLedgerIdx=i; $("#l-add").textContent="✔ 수정 저장"; $("#l-cancel").style.display="";
  $("#l-date").scrollIntoView({behavior:"smooth",block:"center"}); };
$("#l-cancel").onclick=cancelLedgerEdit;
$("#l-add").onclick=async()=>{
  const date=$("#l-date").value, amt=numVal("#l-amt");
  if(!date||isNaN(amt)){ alert("날짜와 금액을 입력해 주세요."); return; }
  const rec={date, member:$("#l-member").value, type:$("#l-type").value,
    category:$("#l-cat").value, amount:amt, memo:$("#l-memo").value.trim()};
  if(editingLedgerIdx!==null){
    const bak=ledger[editingLedgerIdx]; ledger[editingLedgerIdx]=rec;
    try{ await saveLedger(); clearErr(); cancelLedgerEdit(); curMonth=date.slice(0,7); renderLedger(); }
    catch(e){ ledger[editingLedgerIdx]=bak; showErr("수정 저장에 잠깐 실패했어요. 다시 눌러 주세요. ("+e+")"); }
    return;
  }
  ledger.push(rec);
  try{ await saveLedger(); clearErr(); $("#l-amt").value=""; $("#l-memo").value="";
    curMonth=date.slice(0,7); renderLedger(); }
  catch(e){ ledger.pop(); showErr("저장에 잠깐 실패했어요. 다시 [＋ 추가]를 눌러 주세요. ("+e+")"); }
};
window.delLedger=async(i)=>{ ledger.splice(i,1); await saveLedger(); renderLedger(); };
function renderLedger(){
  $("#cur-month").textContent=curMonth;
  renderManual();
  const items=ledger.map((e,i)=>({e,i}))
    .filter(x=>(x.e.date||"").slice(0,7)===curMonth && memberMatch(x.e.member))
    .sort((a,b)=>(a.e.date<b.e.date?1:-1));
  let inc=0,fix=0,vary=0;
  items.forEach(x=>{ const a=Number(x.e.amount)||0;
    if(x.e.type==="수입")inc+=a; else if(x.e.type==="고정지출")fix+=a; else vary+=a; });
  const exp=fix+vary, bal=inc-exp;
  $("#ledger-stats").innerHTML=`
    <div class="stat"><div class="lab">수입</div><div class="big up">${won(inc)}</div></div>
    <div class="stat"><div class="lab">고정지출</div><div class="big" style="color:#f5c451">${won(fix)}</div></div>
    <div class="stat"><div class="lab">변동지출</div><div class="big down">${won(vary)}</div></div>
    <div class="stat"><div class="lab">수지 (수입−지출)</div>
      <div class="big ${bal>=0?'up':'down'}">${bal>=0?"+":""}${won(bal)}</div></div>`;
  // 월별 수입 vs 지출 (최근 6개월)
  const mmap={};
  ledger.forEach(e=>{ const m=(e.date||"").slice(0,7); if(!m||!memberMatch(e.member))return;
    const d=mmap[m]=mmap[m]||{income:0,expense:0}; const a=Number(e.amount)||0;
    if(e.type==="수입")d.income+=a; else d.expense+=a; });
  const ms=Object.keys(mmap).sort().slice(-6);
  $("#l-barchart").innerHTML=svgGroupBars(ms.map(m=>({label:m,income:mmap[m].income,expense:mmap[m].expense})));
  // 이 달 지출 구성 도넛 (분류별, 고정+변동)
  const cmap={};
  items.forEach(x=>{ if(x.e.type==="수입")return; const k=(x.e.type==="고정지출"?"[고정] ":"[변동] ")+(x.e.category||"기타");
    cmap[k]=(cmap[k]||0)+(Number(x.e.amount)||0); });
  const donut=Object.keys(cmap).map((k,i)=>({label:k,value:cmap[k],color:PALETTE[i%PALETTE.length]}));
  $("#l-donut").innerHTML=svgDonut(donut);
  // 이 달 수입 구성 도넛 (분류별)
  const imap={};
  items.forEach(x=>{ if(x.e.type!=="수입")return; const k=x.e.category||"기타";
    imap[k]=(imap[k]||0)+(Number(x.e.amount)||0); });
  const donutInc=Object.keys(imap).map((k,i)=>({label:k,value:imap[k],color:PALETTE[i%PALETTE.length]}));
  $("#l-donut-inc").innerHTML=svgDonut(donutInc);
  // 표
  let html=`<table><thead><tr><th class="l">날짜</th><th class="l">가족</th><th class="l">구분</th><th class="l">분류</th>
    <th class="l">메모</th><th>금액</th><th></th></tr></thead><tbody>`;
  if(items.length===0){ html+=`<tr><td colspan="7" class="empty">이 달 내역이 없어요. 위에서 추가해 보세요.</td></tr>`; }
  items.forEach(x=>{ const e=x.e; const c=e.type==="수입"?"up":"down";
    html+=`<tr><td class="l ldate">${e.date}</td><td class="l" data-label="가족">${e.member||"공용"}</td>
      <td class="l" data-label="구분"><span class="pill ${e.type}">${e.type}</span></td>
      <td class="l" data-label="분류">${e.category||"-"}</td><td class="l" data-label="메모">${e.memo||""}</td>
      <td class="${c}" data-label="금액">${e.type==="수입"?"+":"-"}${won(e.amount)}</td>
      <td class="c-act"><button class="mini-btn edit" onclick="editLedger(${x.i})">수정</button> <button class="mini-btn" onclick="delLedger(${x.i})">삭제</button></td></tr>`; });
  html+=`</tbody></table>`; $("#ledger-tbl").innerHTML=html;
}

// ===== 탭/가족/새로고침 =====
let curTab="market", curMember="전체", members=["남편","아내","자녀"], groups=[];
document.querySelectorAll(".tab").forEach(t=>{ t.onclick=()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
  document.querySelectorAll(".page").forEach(x=>x.classList.remove("active"));
  t.classList.add("active"); $("#page-"+t.dataset.tab).classList.add("active");
  curTab=t.dataset.tab;
  $("#member-bar").style.display = (curTab==="market") ? "none" : "flex";
  refresh(); }; });
// 현재 보기 범위에 속한 가족 목록 / 합산(읽기전용)인지
function currentMembers(){
  if(curMember==="전체") return members;
  const g=groups.find(x=>x.name===curMember);
  if(g) return g.members.filter(m=>members.includes(m));
  return [curMember];
}
function isAggregateScope(){ return curMember==="전체" || groups.some(g=>g.name===curMember); }
function memberMatch(m){ if(curMember==="전체") return true; return currentMembers().includes(m||"공용"); }
// 가족 관리
async function loadMembers(){ const d=await fetchJSON("/api/members").catch(()=>undefined);
  const srvM=(d&&d.members&&d.members.length)?d.members:null;
  const srvG=(d&&Array.isArray(d.groups))?d.groups:null;
  const srvC=(d&&Array.isArray(d.assetCats)&&d.assetCats.length)?d.assetCats:null;
  const srvLC=(d&&d.ledgerCats&&typeof d.ledgerCats==="object")?d.ledgerCats:null;
  const bakM=lsGet(LS.members), bakG=lsGet(LS.groups), bakC=lsGet(LS.cats), bakLC=lsGet(LS.lcats);
  if(srvM){                                     // 서버에 가족설정 있으면 서버 우선(동기화)
    members=srvM; groups=srvG||[]; nwCats=srvC||[...NW_DEFAULT_CATS]; ledgerCats=srvLC||{};
  }else if(bakM&&bakM.length){                  // 서버 비었으면 백업
    members=bakM; groups=bakG||[]; nwCats=(bakC&&bakC.length)?bakC:[...NW_DEFAULT_CATS]; ledgerCats=bakLC||{};
  }else{
    members=["남편","아내","자녀"]; groups=[]; nwCats=[...NW_DEFAULT_CATS]; ledgerCats={};
  }
  lsSet(LS.members, members); lsSet(LS.groups, groups); lsSet(LS.cats, nwCats); lsSet(LS.lcats, ledgerCats); }
async function saveMembers(){ lsSet(LS.members, members); lsSet(LS.groups, groups); lsSet(LS.cats, nwCats); lsSet(LS.lcats, ledgerCats);
  try{ await fetchJSON("/api/members",{method:"POST",
    headers:{"Content-Type":"application/json"},body:JSON.stringify({members,groups,assetCats:nwCats,ledgerCats})}); }
  catch(e){ markSaveFail(); } }
function renderMemberBar(){
  const valid = curMember==="전체" || members.includes(curMember) || groups.some(g=>g.name===curMember);
  if(!valid) curMember="전체";
  const memPills=["전체",...members].map(m=>{
    const active=m===curMember?" active":"";
    const x=m==="전체"?"":`<span class="mx" data-m="${m}" data-kind="member" title="가족에서 빼기">✕</span>`;
    return `<span class="mbtn${active}" data-scope="${m}">${m}${x}</span>`;
  });
  const grpPills=groups.map(g=>{
    const active=g.name===curMember?" active":"";
    return `<span class="mbtn grp${active}" data-scope="${g.name}">${g.name}<span class="mx" data-m="${g.name}" data-kind="group" title="합친 탭 삭제">✕</span></span>`;
  });
  $("#member-btns").innerHTML=[...memPills,...grpPills].join("");
  $("#member-btns").querySelectorAll(".mbtn").forEach(el=>{ el.onclick=()=>selectMember(el.dataset.scope); });
  $("#member-btns").querySelectorAll(".mx").forEach(el=>{ el.onclick=(e)=>{ e.stopPropagation();
    if(el.dataset.kind==="group") removeGroup(el.dataset.m); else removeMember(el.dataset.m); }; });
  const opts=members.map(m=>`<option>${m}</option>`).join("");
  if($("#s-member")) $("#s-member").innerHTML=opts;
  if($("#l-member")) $("#l-member").innerHTML=opts;
}
function selectMember(m){ curMember=m; renderMemberBar();
  if(curTab==="asset") loadAsset().catch(()=>{});
  else if(curTab==="networth") renderNetworth();
  else if(curTab==="ledger") renderLedger(); }
async function removeMember(m){
  if(!confirm("‘"+m+"’ 가족을 삭제할까요?\n\n정말로 삭제를 원하시나요?\n(입력한 자료는 남아있고, 가족 보기 목록에서만 사라져요)")) return;
  members=members.filter(x=>x!==m); groups.forEach(g=>g.members=g.members.filter(x=>x!==m));
  if(curMember===m) curMember="전체";
  await saveMembers(); renderMemberBar(); refresh();
}
async function removeGroup(name){
  if(!confirm("‘"+name+"’ 합친 탭을 삭제할까요?\n\n정말로 삭제를 원하시나요?\n(합치기 설정만 없어지고, 각 가족의 자료는 그대로예요)")) return;
  groups=groups.filter(g=>g.name!==name); if(curMember===name) curMember="전체";
  await saveMembers(); renderMemberBar(); refresh();
}
$("#member-add").onclick=async()=>{
  const name=(prompt("추가할 가족 이름을 적어 주세요 (예: 첫째, 둘째, 부모님)")||"").trim();
  if(!name) return;
  if(name==="전체"||members.includes(name)||groups.some(g=>g.name===name)){ alert("이미 있는 이름이에요."); return; }
  members.push(name); await saveMembers(); renderMemberBar();
};
$("#group-add").onclick=async()=>{
  if(members.length<2){ alert("합치려면 가족이 2명 이상 있어야 해요."); return; }
  const raw=(prompt("합쳐서 볼 가족을 쉼표로 적어 주세요 (예: 남편,아내)\n\n지금 가족: "+members.join(", "))||"").trim();
  if(!raw) return;
  const picked=raw.split(",").map(s=>s.trim()).filter(s=>members.includes(s));
  if(picked.length<2){ alert("가족 이름을 2명 이상 정확히 적어 주세요. (예: 남편,아내)"); return; }
  const name=picked.join("+");
  if(members.includes(name)||groups.some(g=>g.name===name)){ alert("이미 있는 탭이에요."); return; }
  groups.push({name, members:picked}); await saveMembers(); selectMember(name);
};
async function ensureLive(){ try{ liveCache=await fetchJSON("/api/portfolio_live"); }catch(e){} }
// 서버가 자료를 잃었을 때만(불러오기 성공 + 서버가 비어있음 + 백업엔 자료 있음) 백업을 서버에 되살림.
// 불러오기가 '실패'한 경우엔 서버 상태를 모르니 절대 덮어쓰지 않음.
async function restoreServerIfLost(){
  try{
    const sh=await fetchJSON("/api/portfolio_raw").catch(()=>undefined);
    if(sh!==undefined && !(sh&&sh.length) && holdings&&holdings.length) await saveHoldings().catch(()=>{});
    const sl=await fetchJSON("/api/ledger").catch(()=>undefined);
    if(sl!==undefined && !(sl&&sl.length) && ledger&&ledger.length) await saveLedger().catch(()=>{});
    const sn=await fetchJSON("/api/networth").catch(()=>undefined);
    if(sn!==undefined && !(sn&&Object.keys(sn).length) && networth&&Object.keys(networth).length) await saveNetworth().catch(()=>{});
    const sm=await fetchJSON("/api/members").catch(()=>undefined);
    if(sm!==undefined && !(sm&&sm.members&&sm.members.length) && members&&members.length) await saveMembers().catch(()=>{});
    const sma=await fetchJSON("/api/monthly").catch(()=>undefined);
    if(sma!==undefined && !(sma&&Object.keys(sma).length) && Object.keys(manualAssets).length) await saveManual().catch(()=>{});
  }catch(e){}
}
async function refresh(silent){
  try{ if(!silent) clearErr();
    if(curTab==="market") await loadMarket();
    else if(curTab==="asset") await loadAsset();
    else if(curTab==="networth"){ await ensureLive(); renderNetworth(); }
    else if(curTab==="ledger") renderLedger();
  }catch(e){ if(!silent) showErr("데이터를 불러오지 못했어요. 인터넷 연결을 확인하고 잠시 뒤 새로고침(F5) 해주세요. ("+e+")"); }
}
// ===== 내보내기 / 불러오기 (기기·앱 사이 자료 옮기기) =====
function exportData(){
  const dump={ _app:"내자산관리", _ts:new Date().toISOString(),
    holdings, ledger, networth, monthly:manualAssets,
    members, groups, assetCats:nwCats, ledgerCats };
  const blob=new Blob([JSON.stringify(dump,null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download="자산백업_"+new Date().toISOString().slice(0,10)+".json";
  document.body.appendChild(a); a.click(); a.remove();
}
async function importData(file){
  let d; try{ d=JSON.parse(await file.text()); }
  catch(e){ alert("파일을 읽을 수 없어요. 백업 파일(.json)이 맞는지 확인해 주세요."); return; }
  if(!(d.holdings||d.networth||d.ledger)){ alert("이 파일은 자산 백업 파일이 아닌 것 같아요."); return; }
  if(!confirm("불러오면 지금 이 앱의 자료가 이 파일 내용으로 바뀌어요.\n(폰↔PC 연동 중이면 다른 기기에도 반영돼요)\n계속할까요?")) return;
  if(Array.isArray(d.holdings)) holdings=d.holdings;
  if(Array.isArray(d.ledger)) ledger=d.ledger;
  if(d.networth&&typeof d.networth==="object") networth=d.networth;
  if(d.monthly&&typeof d.monthly==="object") manualAssets=d.monthly;
  if(Array.isArray(d.members)&&d.members.length) members=d.members;
  if(Array.isArray(d.groups)) groups=d.groups;
  if(Array.isArray(d.assetCats)&&d.assetCats.length) nwCats=d.assetCats;
  if(d.ledgerCats&&typeof d.ledgerCats==="object") ledgerCats=d.ledgerCats;
  try{ await Promise.all([saveHoldings(),saveLedger(),saveNetworth(),saveManual(),saveMembers()]); }catch(e){}
  alert("불러오기 완료! 🎉 화면을 새로 불러올게요.");
  location.reload();
}
$("#btn-export").onclick=exportData;
$("#btn-import").onclick=()=>$("#file-import").click();
$("#file-import").onchange=(e)=>{ const f=e.target.files[0]; e.target.value=""; if(f) importData(f); };
if(window.MULTIUSER){ const lo=$("#btn-logout"); lo.style.display=""; lo.onclick=()=>{ location.href="/logout"; }; }
async function init(){
  $("#l-date").value=new Date().toISOString().slice(0,10);
  commaInit();
  await loadMembers(); renderMemberBar(); fillCats();
  await Promise.all([loadHoldings(),loadNetworth(),loadLedger(),loadManual(),ensureLive()]).catch(()=>{});
  await restoreServerIfLost();
  await loadMarket().catch(e=>showErr("시장 데이터를 불러오지 못했어요. ("+e+")"));
  setInterval(()=>{ if(curTab==="market"||curTab==="asset") refresh(true); }, 60000);
}
init();
</script>
</body>
</html>"""


# --------------------------- 서버 ---------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _authed(self):
        if not LOCKED:
            return True
        cookie = self.headers.get("Cookie", "") or ""
        return ("awm_auth=" + _auth_token()) in cookie

    def _login_page(self, code=200):
        self._send(code, LOGIN_PAGE, "text/html")

    def _do_login(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        pw = urllib.parse.parse_qs(raw).get("pw", [""])[0]
        if pw == APP_PASSWORD:
            self.send_response(302)
            self.send_header("Set-Cookie",
                             "awm_auth=" + _auth_token() + "; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header("Location", "/login?err=1")
            self.end_headers()

    # ---- 여러 명 로그인(배포용) ----
    def _auth_page(self, code=200):
        self._send(code, AUTH_PAGE, "text/html")

    def _session_cookie(self, userid):
        return ("awm_sess=" + userid + "." + _sig(userid)
                + "; Path=/; Max-Age=31536000; SameSite=Lax")

    def _redir(self, loc, cookie=None):
        self.send_response(302)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Location", loc)
        self.end_headers()

    def _form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        q = urllib.parse.parse_qs(raw)
        return q.get("userid", [""])[0].strip(), q.get("pw", [""])[0]

    def _do_signup(self):
        userid, pw = self._form()
        if not _valid_userid(userid) or len(pw) < 4:
            return self._redir("/login?signup=1&err=bad")
        if _user_get(userid) is not None:
            return self._redir("/login?signup=1&err=taken")
        try:
            _user_set(userid, {"pw": _pw_hash(userid, pw), "created": datetime.now(KST).isoformat()})
        except Exception:
            return self._redir("/login?signup=1&err=bad")
        return self._redir("/", self._session_cookie(userid))

    def _do_user_login(self):
        userid, pw = self._form()
        u = _user_get(userid)
        if u and u.get("pw") == _pw_hash(userid, pw):
            return self._redir("/", self._session_cookie(userid))
        return self._redir("/login?err=login")

    def _logout(self):
        self.send_response(302)
        self.send_header("Set-Cookie", "awm_sess=; Path=/; Max-Age=0")
        self.send_header("Location", "/login")
        self.end_headers()

    def do_GET(self):
        p = self.path.split("?")[0]
        if MULTI_USER:
            if p == "/logout":
                return self._logout()
            user = _session_user(self.headers.get("Cookie", ""))
            if not user:
                return self._auth_page()
            _CTX.user = user
        elif LOCKED and p == "/login":
            return self._login_page()
        elif LOCKED and not self._authed():
            return self._login_page()
        try:
            if p == "/":
                self._send(200, PAGE.replace("__MULTIUSER__", "1" if MULTI_USER else "0"), "text/html")
            elif p == "/api/market":
                self._json(build_market())
            elif p == "/api/portfolio_live":
                self._json(compute_portfolio())
            elif p == "/api/portfolio_raw":
                self._json(load_json(F_STOCK, []))
            elif p == "/api/ledger":
                self._json(load_json(F_LEDGER, []))
            elif p == "/api/networth":
                self._json(migrate_networth(load_json(F_NETWORTH, {})))
            elif p == "/api/monthly":
                self._json(load_json(F_MANUAL, {}))
            elif p == "/api/members":
                cfg = load_json(F_MEMBERS, {})
                mem = cfg.get("members") if isinstance(cfg, dict) else None
                grp = cfg.get("groups") if isinstance(cfg, dict) else None
                cats = cfg.get("assetCats") if isinstance(cfg, dict) else None
                lcats = cfg.get("ledgerCats") if isinstance(cfg, dict) else None
                self._json({"members": mem if isinstance(mem, list) and mem else DEFAULT_MEMBERS,
                            "groups": grp if isinstance(grp, list) else [],
                            "assetCats": cats if isinstance(cats, list) else [],
                            "ledgerCats": lcats if isinstance(lcats, dict) else {}})
            elif p == "/api/summary":
                self._json(compute_summary())
            else:
                self._send(404, "not found", "text/plain")
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def do_POST(self):
        p = self.path.split("?")[0]
        if MULTI_USER:
            if p == "/login":
                return self._do_user_login()
            if p == "/signup":
                return self._do_signup()
            user = _session_user(self.headers.get("Cookie", ""))
            if not user:
                return self._json({"error": "unauthorized"}, 401)
            _CTX.user = user
        elif LOCKED and p == "/login":
            return self._do_login()
        elif LOCKED and not self._authed():
            return self._json({"error": "unauthorized"}, 401)
        data = self._body()
        try:
            if p == "/api/portfolio_raw":
                save_json(F_STOCK, data if isinstance(data, list) else [])
                self._json({"ok": True})
            elif p == "/api/ledger":
                save_json(F_LEDGER, data if isinstance(data, list) else [])
                self._json({"ok": True})
            elif p == "/api/networth":
                save_json(F_NETWORTH, data if isinstance(data, dict) else {})
                self._json({"ok": True})
            elif p == "/api/monthly":
                save_json(F_MANUAL, data if isinstance(data, dict) else {})
                self._json({"ok": True})
            elif p == "/api/members":
                mem = data.get("members") if isinstance(data, dict) else None
                grp = data.get("groups") if isinstance(data, dict) else None
                cats = data.get("assetCats") if isinstance(data, dict) else None
                lcats = data.get("ledgerCats") if isinstance(data, dict) else None
                save_json(F_MEMBERS, {"members": mem if isinstance(mem, list) else DEFAULT_MEMBERS,
                                      "groups": grp if isinstance(grp, list) else [],
                                      "assetCats": cats if isinstance(cats, list) else [],
                                      "ledgerCats": lcats if isinstance(lcats, dict) else {}})
                self._json({"ok": True})
            else:
                self._send(404, "not found", "text/plain")
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def log_message(self, *args):
        pass


def find_free_port(start=8765):
    for pp in range(start, start + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", pp)) != 0:
                return pp
    return start


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    if CLOUD:
        # 클라우드(렌더 등): 외부 접속 허용(0.0.0.0). 비밀번호는 APP_PASSWORD 있을 때만.
        host = "0.0.0.0"
        port = int(os.environ.get("PORT", "7860"))
        print(f"[클라우드 모드] 포트 {port} · 비밀번호 잠금 {'켜짐' if LOCKED else '꺼짐(APP_PASSWORD 미설정)'}")
        with Server((host, port), Handler) as httpd:
            httpd.serve_forever()
    else:
        # 내 PC(로컬): 예전과 동일 — 브라우저 자동 열림, 비밀번호 없음
        port = find_free_port()
        url = f"http://127.0.0.1:{port}/"
        print("=" * 54)
        print("  내 자산관리 대시보드가 열립니다.")
        print(f"  브라우저 주소: {url}")
        print("  창을 닫으려면 이 검은 창을 닫으세요.")
        print("=" * 54)
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        with Server(("127.0.0.1", port), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
