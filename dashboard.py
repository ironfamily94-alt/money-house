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


def _redis_get(name):
    key = "awm:" + _RKEY.get(name, name)
    req = urllib.request.Request(UPSTASH_URL + "/get/" + key,
                                 headers={"Authorization": "Bearer " + UPSTASH_TOKEN})
    with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx) as r:
        return json.loads(r.read().decode("utf-8")).get("result")


def _redis_set(name, value):
    key = "awm:" + _RKEY.get(name, name)
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
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1><span class="dot">●</span> 내 자산관리 대시보드</h1>
    <div class="updated">업데이트 <b id="updated">불러오는 중…</b> · 60초마다 자동</div>
  </header>
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
      <div class="fld"><label>수량</label><input id="s-qty" type="number" step="any" placeholder="10" size="6"></div>
      <div class="fld"><label>평균매입가</label><input id="s-avg" type="number" step="any" placeholder="70000" size="8"></div>
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
      <div class="fld"><label>총자산(원)</label><input id="ma-total" type="number" step="any" placeholder="0"></div>
      <div class="fld"><label>부채(원)</label><input id="ma-debt" type="number" step="any" placeholder="0"></div>
      <div class="fld"><label>순자산 (총자산−부채, 자동)</label>
        <input id="ma-net" readonly style="background:#12303a;color:#5fd0e0;font-weight:700;"></div>
      <span class="autosave" id="ma-saved"></span>
    </div>
    <div class="hint">자산현황의 <b>투자는 실시간</b>이라 매월 값이 바뀌어요. 여기에 그 달의 총자산·부채를
      직접 적어두면 <b>그 달 숫자로 고정</b>돼서 나중에 비교하기 좋아요. 입력하면 자동 저장돼요.</div>
    <div class="grid stat-grid" id="ledger-stats"></div>
    <div class="two" style="margin:14px 0">
      <div class="chart-card"><h3>월별 수입 vs 지출</h3><div class="chart-scroll" id="l-barchart"></div></div>
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
      <div class="fld"><label>금액(원)</label><input id="l-amt" type="number" step="any" placeholder="15000" size="8"></div>
      <div class="fld"><label>메모</label><input id="l-memo" placeholder="예: 점심 식사" size="11"></div>
      <button class="btn" id="l-add">＋ 추가</button>
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
      html+=`<tr><td class="l"><b>${r.name||"-"}</b> <span style="color:#6b7484;font-size:12px">${r.market} ${r.code}</span></td>
        <td>${fmt(r.qty,0)}</td><td>${unit}${fmt(r.avg,dp)}</td>
        <td>${r.price===null?"-":unit+fmt(r.price,dp)}</td><td>${won(r.val_krw)}</td>
        <td class="${c}">${r.pl===null?"-":(r.pl>=0?"+":"-")+unit+fmt(Math.abs(r.pl),dp)}</td>
        <td class="${c}">${r.plpct===null?"-":(r.plpct>=0?"+":"")+fmt(r.plpct,2)+"%"}</td>
        <td><button class="mini-btn" onclick="delHolding(${i})">삭제</button></td></tr>`;
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
$("#s-add").onclick=async()=>{
  const market=$("#s-market").value, isGold=(market==="금현물");
  const code=$("#s-code").value.trim(), name=$("#s-name").value.trim();
  const qty=parseFloat($("#s-qty").value), avg=parseFloat($("#s-avg").value);
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
          <input class="am" type="number" step="any" placeholder="0" value="${it.amount?it.amount:''}">
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
    const nm=row.querySelector(".nm"), am=row.querySelector(".am");
    nm.oninput=()=>{ nwEnsure(curMember,nwMonth)[cat][idx].name=nm.value; scheduleNwSave(); };
    am.oninput=()=>{ nwEnsure(curMember,nwMonth)[cat][idx].amount=parseFloat(am.value)||0; updateNwTotals(); scheduleNwSave(); };
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
  $("#ma-total").value = s.total?s.total:"";
  $("#ma-debt").value = s.debt?s.debt:"";
  $("#ma-net").value = won(total-debt);
}
function maUpdate(){
  const total=parseFloat($("#ma-total").value)||0, debt=parseFloat($("#ma-debt").value)||0;
  manualAssets[curMonth]={total, debt};
  $("#ma-net").value=won(total-debt);
  scheduleManualSave();
}
$("#ma-total").oninput=maUpdate; $("#ma-debt").oninput=maUpdate;
function shiftMonth(delta){ let[y,m]=curMonth.split("-").map(Number); m+=delta;
  if(m<1){m=12;y--;} if(m>12){m=1;y++;} curMonth=`${y}-${String(m).padStart(2,"0")}`; renderLedger(); }
$("#prev-m").onclick=()=>shiftMonth(-1); $("#next-m").onclick=()=>shiftMonth(1);
$("#l-add").onclick=async()=>{
  const date=$("#l-date").value, amt=parseFloat($("#l-amt").value);
  if(!date||isNaN(amt)){ alert("날짜와 금액을 입력해 주세요."); return; }
  ledger.push({date, member:$("#l-member").value, type:$("#l-type").value,
    category:$("#l-cat").value, amount:amt, memo:$("#l-memo").value.trim()});
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
  // 표
  let html=`<table><thead><tr><th class="l">날짜</th><th class="l">가족</th><th class="l">구분</th><th class="l">분류</th>
    <th class="l">메모</th><th>금액</th><th></th></tr></thead><tbody>`;
  if(items.length===0){ html+=`<tr><td colspan="7" class="empty">이 달 내역이 없어요. 위에서 추가해 보세요.</td></tr>`; }
  items.forEach(x=>{ const e=x.e; const c=e.type==="수입"?"up":"down";
    html+=`<tr><td class="l">${e.date}</td><td class="l">${e.member||"공용"}</td>
      <td class="l"><span class="pill ${e.type}">${e.type}</span></td>
      <td class="l">${e.category||"-"}</td><td class="l">${e.memo||""}</td>
      <td class="${c}">${e.type==="수입"?"+":"-"}${won(e.amount)}</td>
      <td><button class="mini-btn" onclick="delLedger(${x.i})">삭제</button></td></tr>`; });
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
async function init(){
  $("#l-date").value=new Date().toISOString().slice(0,10);
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

    def do_GET(self):
        p = self.path.split("?")[0]
        if LOCKED and p == "/login":
            return self._login_page()
        if LOCKED and not self._authed():
            return self._login_page()
        try:
            if p == "/":
                self._send(200, PAGE, "text/html")
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
        if LOCKED and p == "/login":
            return self._do_login()
        if LOCKED and not self._authed():
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
