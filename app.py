import base64
import ipaddress
import json
import os
import re
import socket
import time
from urllib.parse import quote, urljoin, urlsplit, urlunsplit, parse_qs

import requests
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


def rewrite_playlist(text: str, base_url: str) -> str:
    """Har URI ko absolute banao, CloudFront auth query (Signature/Policy/Key-Pair-Id)
    aage ki sub-playlists/segments par bhi lagao, aur /proxy se route karo."""
    bp = urlsplit(base_url)
    auth_query = bp.query
    clean_base = urlunsplit((bp.scheme, bp.netloc, bp.path, "", ""))

    def fix(ref: str) -> str:
        absu = urljoin(clean_base, ref.strip())
        ap = urlsplit(absu)
        # query nahi hai aur host same hai -> parent ki auth query chipka do
        if not ap.query and auth_query and ap.netloc == bp.netloc:
            absu = urlunsplit((ap.scheme, ap.netloc, ap.path, auth_query, ""))
        return proxied(absu)

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
  #msg{position:fixed;inset:0;display:none;align-items:center;justify-content:center;
       text-align:center;padding:20px;font-size:18px;background:rgba(0,0,0,.85)}
</style>
</head>
<body>
<video id="v" controls autoplay playsinline></video>
<div id="msg"></div>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.17/dist/hls.min.js"></script>
<script>
  const SRC = {{ src|tojson }};
  const IS_HLS = {{ is_hls|tojson }};
  const video = document.getElementById("v");
  const msg = document.getElementById("msg");
  function fail(t){ msg.textContent = t; msg.style.display = "flex"; }

  if (!IS_HLS) {
    video.src = SRC;
  } else if (window.Hls && Hls.isSupported()) {
    const hls = new Hls({ enableWorker: true, lowLatencyMode: false });
    hls.loadSource(SRC);
    hls.attachMedia(video);
    let netRetry = 0;
    hls.on(Hls.Events.ERROR, (e, d) => {
      if (!d.fatal) return;
      if (d.type === Hls.ErrorTypes.NETWORK_ERROR && netRetry < 3) { netRetry++; hls.startLoad(); }
      else if (d.type === Hls.ErrorTypes.MEDIA_ERROR) { hls.recoverMediaError(); }
      else { hls.destroy(); fail("Video load nahi ho paya. Link expire ho gaya ho sakta hai - naya link generate karo."); }
    });
  } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
    video.src = SRC;
  } else {
    fail("Is browser me HLS support nahi hai.");
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
    src = proxied(v) if is_hls else v
    return render_template_string(PLAYER_HTML, src=src, is_hls=is_hls)


@app.route("/proxy")
def proxy():
    u = request.args.get("u", "")
    if not u or not is_safe_url(u):
        abort(400)

    headers = {"User-Agent": UA, "Accept": "*/*"}
    if "Range" in request.headers:
        headers["Range"] = request.headers["Range"]

    try:
        r = requests.get(u, headers=headers, stream=True, timeout=(10, 30), allow_redirects=True)
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
