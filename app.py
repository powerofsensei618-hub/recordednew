import base64
import ipaddress
import json
import os
import re
import socket
import time
from urllib.parse import quote, urljoin, urlsplit, urlunsplit, parse_qs

import requests
from http.cookiejar import DefaultCookiePolicy
from flask import Flask, Response, abort, render_template_string, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
# Render HTTPS proxy ke peeche hai -> sahi scheme (mixed-content se bachne ke liye)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE", "0") == "1"  # sirf local testing ke liye
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36")
URI_ATTR = re.compile(r'URI="([^"]+)"')


# ---------------------------------------------------------------- helpers
def is_safe_url(u: str) -> bool:
    """Sirf http/https, aur private/localhost IPs block (SSRF guard)."""
    try:
        p = urlsplit(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        if ALLOW_PRIVATE:
            return True
        for info in socket.getaddrinfo(p.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                return False
        return True
    except Exception:
        return False


def cf_expiry(url: str):
    """CloudFront signed URL ka expiry epoch (Policy ya Expires se). Na mile to None."""
    try:
        q = parse_qs(urlsplit(url).query)
        if "Expires" in q:
            return int(q["Expires"][0])
        if "Policy" in q:
            s = q["Policy"][0]
            s = s.replace("-", "+").replace("_", "=").replace("~", "/")
            s += "=" * (-len(s) % 4)
            data = json.loads(base64.b64decode(s))
            return int(data["Statement"][0]["Condition"]["DateLessThan"]["AWS:EpochTime"])
    except Exception:
        return None
    return None


def proxied(abs_url: str) -> str:
    return "/proxy?u=" + quote(abs_url, safe="")


def abs_with_auth(ref: str, base_url: str) -> str:
    """ref ko absolute banao; agar ref me query nahi hai aur host same hai to
    parent ki CloudFront auth query (Signature/Policy/Key-Pair-Id) chipka do."""
    bp = urlsplit(base_url)
    clean_base = urlunsplit((bp.scheme, bp.netloc, bp.path, "", ""))
    absu = urljoin(clean_base, ref.strip())
    ap = urlsplit(absu)
    if not ap.query and bp.query and ap.netloc == bp.netloc:
        absu = urlunsplit((ap.scheme, ap.netloc, ap.path, bp.query, ""))
    return absu


def rewrite_playlist(text: str, base_url: str) -> str:
    """Har URI ko absolute banao, auth query aage bhi lagao, aur /proxy se route karo."""
    def fix(ref: str) -> str:
        return proxied(abs_with_auth(ref, base_url))

    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            out.append(line)
        elif s.startswith("#"):
            out.append(URI_ATTR.sub(lambda m: 'URI="%s"' % fix(m.group(1)), line))
        else:
            out.append(fix(s))
    return "\n".join(out) + "\n"


# 403 aaye to in header-sets ko baari baari try karte hain (jo chal jaye wo yaad rakhte hain)
HEADER_SETS = [
    {},  # sirf browser UA
    {"Referer": "https://www.pw.live/", "Origin": "https://www.pw.live"},
]
_pref = [0]

SESSION = requests.Session()
SESSION.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))  # cookies store mat karo


def _send(u: str, hdrs: dict, stream: bool, timeout):
    prep = SESSION.prepare_request(requests.Request("GET", u, headers=hdrs))
    prep.url = u  # URL byte-for-byte jaisa PW ne diya (%7E ko ~ me mat badlo)
    return SESSION.send(prep, stream=stream, timeout=timeout, allow_redirects=True)


def upstream_get(u: str, stream=False, rng=None, timeout=(10, 30), ua=None):
    # identity: gzip nahi, warna decoded body aur Content-Length mismatch ho jata hai
    base = {"User-Agent": ua or UA, "Accept": "*/*", "Accept-Encoding": "identity"}
    if rng:
        base["Range"] = rng
    order = [_pref[0]] + [i for i in range(len(HEADER_SETS)) if i != _pref[0]]
    r = None
    for i in order:
        if r is not None:
            r.close()
        r = _send(u, {**base, **HEADER_SETS[i]}, stream, timeout)
        if r.status_code != 403:
            if r.status_code < 400:
                _pref[0] = i
            return r
    return r


def probe(u: str, timeout=(10, 30), ua=None):
    """Ek URL ka status + (playlist ho to) shuru ki lines."""
    try:
        r = upstream_get(u, timeout=timeout, ua=ua)
        info = {"url": u.split("?")[0], "status": r.status_code,
                "type": r.headers.get("Content-Type", ""), "bytes": len(r.content)}
        for h in ("Server", "X-Cache", "X-Amz-Cf-Pop", "Via"):
            if h in r.headers:
                info[h.lower()] = r.headers[h][:80]
        if r.status_code >= 400 or r.content[:7] == b"#EXTM3U":
            info["head"] = r.text[:400]
        return info, r
    except requests.RequestException as e:
        return {"url": u.split("?")[0], "status": "ERR", "error": str(e)[:200]}, None


# ---------------------------------------------------------------- pages
PLAYER_HTML = """<!doctype html>
<html lang="hi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Player</title>
<style>
  html,body{margin:0;height:100%;background:#000;color:#fff;font-family:system-ui,sans-serif}
  video{width:100%;height:100%;background:#000}
  #dbg{position:fixed;left:0;right:0;top:0;padding:4px 8px;font:11px monospace;
       background:rgba(0,0,0,.6);color:#ff9;display:none;z-index:5;word-break:break-all;white-space:pre-wrap}
  #msg{position:fixed;inset:0;display:none;align-items:center;justify-content:center;
       text-align:center;padding:20px;font-size:18px;background:rgba(0,0,0,.85)}
</style>
</head>
<body>
<video id="v" controls autoplay playsinline></video>
<div id="dbg"></div>
<div id="msg"></div>
<script>
  const DIRECT = {{ direct|tojson }};   // original CloudFront/media URL
  const PROXY = {{ proxy|tojson }};     // apne server ka /proxy URL
  const IS_HLS = {{ is_hls|tojson }};
  const PRE = {{ pre|tojson }};         // server-side check ka status (info)
  const video = document.getElementById("v");
  const msg = document.getElementById("msg");
  const dbg = document.getElementById("dbg");
  function fail(t){ msg.textContent = t; msg.style.display = "flex"; }
  const LOG = [];
  function note(t){ LOG.push(t); if (LOG.length > 5) LOG.shift(); dbg.textContent = LOG.join("\\n"); dbg.style.display = "block"; }
  video.addEventListener("error", () => note("video error: " + (video.error ? video.error.code + " " + (video.error.message||"") : "")));

  function loadScript(src, ok, bad){
    const s = document.createElement("script");
    s.src = src; s.onload = ok; s.onerror = bad;
    document.head.appendChild(s);
  }

  // ?mode=direct | proxy se force kar sakte ho (default: pehle direct, fail ho to proxy)
  const FORCE = new URLSearchParams(location.search).get("mode");

  function startHls(mode) {
    const useProxy = mode === "proxy";
    const src = useProxy ? PROXY : DIRECT;
    const hlsCfg = { enableWorker: true, lowLatencyMode: false };

    if (!useProxy) {
      // direct mode: master URL ki auth query (Signature/Policy/Key-Pair-Id) har
      // sub-playlist / segment request par bhi lagao (CloudFront policy "/*" ke liye zaroori)
      const M = new URL(DIRECT);
      const AUTH = M.search.slice(1);
      const Base = Hls.DefaultConfig.loader;
      class AuthLoader extends Base {
        load(ctx, cfg, cb) {
          try {
            const u = new URL(ctx.url);
            if (u.host === M.host && !/[?&](Signature|Policy|Expires)=/.test(u.search)) {
              ctx.url = ctx.url + (ctx.url.indexOf("?") > -1 ? "&" : "?") + AUTH;
            }
          } catch (e) {}
          super.load(ctx, cfg, cb);
        }
      }
      hlsCfg.loader = AuthLoader;
    }

    const hls = new Hls(hlsCfg);
    hls.loadSource(src);
    hls.attachMedia(video);
    let netRetry = 0;
    hls.on(Hls.Events.ERROR, (e, d) => {
      const code = d.response ? d.response.code : "";
      note("[" + mode + "] " + (d.fatal ? "FATAL " : "") + d.type + " / " + d.details + (code !== "" ? " / HTTP " + code : "") + (d.response && d.response.text ? " / " + String(d.response.text).replace(/\\s+/g, " ").slice(0, 80) : "") + (PRE && mode === "proxy" ? " | server-check: " + PRE : ""));
      if (!d.fatal) return;
      if (d.type === Hls.ErrorTypes.NETWORK_ERROR) {
        if (!useProxy && FORCE !== "direct") { hls.destroy(); startHls("proxy"); return; }
        if (netRetry < 3) { netRetry++; hls.startLoad(); return; }
      } else if (d.type === Hls.ErrorTypes.MEDIA_ERROR) {
        hls.recoverMediaError(); return;
      }
      hls.destroy();
      fail("Video load nahi ho paya (" + d.details + (code !== "" ? ", HTTP " + code : "") + "). Link expire/invalid ho sakta hai - naya link generate karo.");
    });
  }

  function start() {
    if (!IS_HLS) {
      video.src = DIRECT;
    } else if (window.Hls && Hls.isSupported()) {
      startHls(FORCE === "proxy" ? "proxy" : "direct");
    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
      video.src = PROXY;
    } else {
      fail("Is browser me HLS support nahi hai.");
    }
  }

  if (!IS_HLS) {
    start();
  } else {
    // pehle apne server ki copy (/static/hls.min.js), na mile to CDN fallback
    loadScript("/static/hls.min.js", start, function () {
      loadScript("https://cdn.jsdelivr.net/npm/hls.js@1.5.17/dist/hls.min.js", start, start);
    });
  }
</script>
</body>
</html>"""

ERROR_HTML = """<!doctype html><meta name="viewport" content="width=device-width, initial-scale=1">
<body style="margin:0;background:#000;color:#fff;font-family:system-ui;display:flex;
align-items:center;justify-content:center;height:100vh;text-align:center;padding:20px">
<div><h2>{{ title }}</h2><p>{{ text }}</p></div></body>"""


def error_page(title, text, code):
    return render_template_string(ERROR_HTML, title=title, text=text), code


@app.after_request
def add_cors(resp):
    if request.path in ("/proxy", "/debug"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Range"
        resp.headers["Access-Control-Expose-Headers"] = "Content-Length, Content-Range"
    return resp


@app.route("/")
def home():
    return "Recorded/Live player is running. Use /play?v=<encoded video url>"


@app.route("/health")
def health():
    return "ok"


@app.route("/play")
def play():
    v = request.args.get("v", "").strip()
    if not v:
        return error_page("URL missing", "Link me ?v=<video url> hona zaroori hai.", 400)
    if not is_safe_url(v):
        return error_page("Invalid URL", "Ye video URL allowed nahi hai.", 400)

    exp = cf_expiry(v)
    if exp is not None and exp < time.time():
        return error_page("Link expire ho gaya",
                          "Is video link ka signature expire ho chuka hai. Naya link generate karo.", 410)

    path = urlsplit(v).path.lower()
    is_hls = path.endswith(".m3u8") or ".m3u8" in path

    pre = ""
    if is_hls:
        # sirf info: server se master check. Fail ho to bhi player try karega (direct browser se)
        info, _ = probe(v, timeout=(4, 6), ua=request.headers.get("User-Agent"))
        st = info.get("status")
        if st != 200:
            snip = re.sub(r"<[^>]+>|\s+", " ", info.get("head", "")).strip()[:90]
            pre = ("HTTP %s %s" % (st, snip)).strip()
    return render_template_string(PLAYER_HTML, direct=v, proxy=proxied(v), is_hls=is_hls, pre=pre)



@app.route("/debug")
def debug():
    """/debug?v=<encoded master url> -> poori chain ka status JSON (master, sub-playlist, key, segment)."""
    v = request.args.get("v", "").strip()
    if not v or not is_safe_url(v):
        abort(400)
    steps = []
    info, r = probe(v, ua=request.headers.get("User-Agent"))
    info["step"] = "master"
    info["expires_utc"] = cf_expiry(v)
    tests = []
    for i, hs in enumerate(HEADER_SETS):
        try:
            rr = _send(v, {"User-Agent": request.headers.get("User-Agent") or UA, "Accept": "*/*",
                           "Accept-Encoding": "identity", **hs}, False, (5, 8))
            tests.append({"set": i, "extra_headers": list(hs) or ["(none)"], "status": rr.status_code})
        except requests.RequestException as e:
            tests.append({"set": i, "error": str(e)[:100]})
    info["header_tests"] = tests
    steps.append(info)
    try:
        if r is not None and r.status_code < 400 and r.text.lstrip().startswith("#EXTM3U"):
            lines = [l.strip() for l in r.text.splitlines() if l.strip()]
            subs = [l for l in lines if not l.startswith("#")]
            if subs:
                sub_url = abs_with_auth(subs[0], r.url)
                info2, r2 = probe(sub_url)
                info2["step"] = "sub-playlist"
                steps.append(info2)
                if r2 is not None and r2.status_code < 400:
                    l2 = [l.strip() for l in r2.text.splitlines() if l.strip()]
                    for l in l2:
                        m = URI_ATTR.search(l)
                        if l.startswith("#EXT-X-KEY") and m:
                            i3, _ = probe(abs_with_auth(m.group(1), r2.url))
                            i3["step"] = "key"
                            i3.pop("head", None) if i3.get("status") == 200 else None
                            steps.append(i3)
                            break
                    segs = [l for l in l2 if not l.startswith("#")]
                    if segs:
                        i4, _ = probe(abs_with_auth(segs[0], r2.url))
                        i4["step"] = "first-segment"
                        steps.append(i4)
    except Exception as e:
        steps.append({"step": "debug-error", "error": str(e)[:200]})
    return Response(json.dumps(steps, indent=2), mimetype="application/json")


@app.route("/proxy")
def proxy():
    u = request.args.get("u", "")
    if not u or not is_safe_url(u):
        abort(400)

    try:
        r = upstream_get(u, stream=True, rng=request.headers.get("Range"),
                         ua=request.headers.get("User-Agent"))
    except requests.RequestException:
        return Response("Upstream fetch failed", status=502, mimetype="text/plain")

    ctype = r.headers.get("Content-Type", "")
    path = urlsplit(u).path.lower()
    looks_playlist = path.endswith(".m3u8") or "mpegurl" in ctype.lower()

    if r.status_code >= 400:
        body = r.content[:300]
        r.close()
        return Response(body, status=r.status_code, mimetype="text/plain")

    if looks_playlist:
        text = r.text
        r.close()
        if text.lstrip().startswith("#EXTM3U"):
            text = rewrite_playlist(text, r.url if r.url else u)
        return Response(text, mimetype="application/vnd.apple.mpegurl",
                        headers={"Cache-Control": "no-store"})

    # segment / key / mp4 -> seedha stream
    out_headers = {}
    for h in ("Content-Type", "Content-Length", "Content-Range", "Accept-Ranges"):
        if h in r.headers:
            out_headers[h] = r.headers[h]
    out_headers["Cache-Control"] = "public, max-age=300"

    def gen():
        try:
            for chunk in r.iter_content(64 * 1024):
                if chunk:
                    yield chunk
        finally:
            r.close()

    return Response(gen(), status=r.status_code, headers=out_headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
