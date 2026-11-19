#!/usr/bin/env python3
"""vpn-hub: subscription bridge — upstream xray-JSON → mihomo proxy-provider.

Each source from /etc/vpn-hub/config.yaml is served at /<name>.yaml,
live-pulled on every request; disk cache is failover-only. Put it behind a
TLS reverse-proxy with basic_auth (e.g. Caddy: sub.example.com:8443 →
127.0.0.1:8080). See README.md.

Usage: render.py [--config /etc/vpn-hub/config.yaml]
"""

from __future__ import annotations

import http.server
import json
import logging
import os
import re
import socketserver
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

CONFIG_PATH = Path("/etc/vpn-hub/config.yaml")
MAX_UPSTREAM_BYTES = 8 * 1024 * 1024
_SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
log = logging.getLogger("vpn-hub")

GOVPN_MODE_TAGS = {
    "Основной режим": "main",
    "Запасной": "backup",
    "Антизаглушка": "antiblock",
}


def detect_mode_govpn(remarks: str) -> str:
    for needle, tag in GOVPN_MODE_TAGS.items():
        if needle in remarks:
            return tag
    return "unknown"


def detect_mode_buzzvpn(remarks: str) -> str:
    # «Автовыбор*» — balancer-агрегаты тех же нод, что и одиночные профили; skip.
    if "Автовыбор" in remarks:
        return "unknown"
    if "Обход белых списков" in remarks:
        return "antiblock"
    return "main"


def detect_mode_generic(remarks: str) -> str:
    # Default dialect: every node → main. Adapt per your subscription's remarks.
    return "main"


# fingerprint: "random" hardcodes utls fp; "upstream" mirrors the fp the
# subscription ships (falls back to random when absent).
DIALECTS = {
    "govpn": {"detect": detect_mode_govpn, "fingerprint": "random"},
    "buzzvpn": {"detect": detect_mode_buzzvpn, "fingerprint": "upstream"},
    "generic": {"detect": detect_mode_generic, "fingerprint": "upstream"},
}


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _json_int(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _server_name(settings: dict) -> str:
    name = settings.get("serverName") or settings.get("Show") or ""
    if isinstance(name, str) and name:
        return name
    names = settings.get("serverNames")
    if isinstance(names, list):
        for item in names:
            if isinstance(item, str) and item:
                return item
    return ""


def _header_map(raw) -> dict | None:
    if not isinstance(raw, dict) or not raw:
        return None
    out: dict[str, str] = {}
    for key, val in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(val, str):
            out[key] = val
        elif isinstance(val, list):
            out[key] = ", ".join(str(item) for item in val if item is not None)
    return out or None


def _xmux_to_reuse(xmux: dict) -> dict:
    """xray xmux object → mihomo reuse-settings (same shape mihomo's converter emits)."""
    reuse: dict = {}

    def put(src: str, dst: str, *, as_int: bool = False) -> None:
        if src not in xmux:
            return
        val = xmux[src]
        if isinstance(val, str):
            if val:
                reuse[dst] = val
            return
        number = _json_int(val)
        if number is None:
            return
        reuse[dst] = number if as_int else str(number)

    put("maxConnections", "max-connections")
    put("maxConcurrency", "max-concurrency")
    put("cMaxReuseTimes", "c-max-reuse-times")
    put("hMaxRequestTimes", "h-max-request-times")
    put("hMaxReusableSecs", "h-max-reusable-secs")
    put("hKeepAlivePeriod", "h-keep-alive-period", as_int=True)
    return reuse


def _legacy_reuse(reuse: dict) -> dict:
    # Flat reuseSettings shipped by some panels. Keep every key so the YAML
    # stays stable for subscriptions that don't nest this under extra.xmux.
    return {
        "max-concurrency": str(reuse.get("maxConcurrency", "")),
        "max-connections": reuse.get("maxConnections", 0),
        "c-max-reuse-times": reuse.get("cMaxReuseTimes", 0),
        "h-max-request-times": str(reuse.get("hMaxRequestTimes", "")),
        "h-max-reusable-secs": str(reuse.get("hMaxReusableSecs", "")),
        "h-keep-alive-period": reuse.get("hKeepAlivePeriod", 0),
    }


def _put_str(opts: dict, extra: dict, src: str, dst: str) -> None:
    val = extra.get(src)
    if isinstance(val, str) and val:
        opts[dst] = val


def _download_settings(raw: dict) -> dict:
    """xray extra.downloadSettings → mihomo xhttp-opts.download-settings."""
    out: dict = {}
    address = raw.get("address")
    if isinstance(address, str) and address:
        out["server"] = address
    port = _json_int(raw.get("port"))
    if port is not None:
        out["port"] = port

    sec = raw.get("security")
    sec = sec.lower() if isinstance(sec, str) else ""
    if sec in ("tls", "reality"):
        out["tls"] = True
        tls = _as_dict(raw.get("tlsSettings"))
        reality = _as_dict(raw.get("realitySettings"))
        sni = _server_name(tls) or _server_name(reality)
        if sni:
            out["servername"] = sni
        fingerprint = tls.get("fingerprint") or reality.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            out["client-fingerprint"] = fingerprint
        alpn = tls.get("alpn") if isinstance(tls.get("alpn"), list) else reality.get("alpn")
        if isinstance(alpn, list):
            alpn_list = [item for item in alpn if isinstance(item, str) and item]
            if alpn_list:
                out["alpn"] = alpn_list
        if tls.get("allowInsecure") is True:
            out["skip-cert-verify"] = True
        if sec == "reality":
            public_key = reality.get("publicKey")
            if isinstance(public_key, str) and public_key:
                reality_opts = {"public-key": public_key}
                short_id = reality.get("shortId")
                if short_id not in (None, ""):
                    reality_opts["short-id"] = str(short_id)
                out["reality-opts"] = reality_opts

    xhttp = _as_dict(raw.get("xhttpSettings"))
    path = xhttp.get("path")
    if isinstance(path, str) and path:
        out["path"] = path
    host = xhttp.get("host")
    if isinstance(host, str) and host:
        out["host"] = host
    headers = _header_map(xhttp.get("headers"))
    if headers:
        out["headers"] = headers
    extra = _as_dict(xhttp.get("extra"))
    reuse = _xmux_to_reuse(_as_dict(extra.get("xmux")))
    if reuse:
        out["reuse-settings"] = reuse
    return out


def _apply_xhttp_extra(extra: dict, opts: dict) -> None:
    """Map xray xhttpSettings.extra onto mihomo xhttp-opts.

    Field names follow MetaCubeX/mihomo common/convert parseXHTTPExtra.
    """
    if not extra:
        return
    headers = _header_map(extra.get("headers"))
    if headers:
        opts["headers"] = headers
    if extra.get("noGRPCHeader") is True:
        opts["no-grpc-header"] = True
    _put_str(opts, extra, "xPaddingBytes", "x-padding-bytes")
    if isinstance(extra.get("xPaddingObfsMode"), bool):
        opts["x-padding-obfs-mode"] = extra["xPaddingObfsMode"]
    for src, dst in (
        ("xPaddingKey", "x-padding-key"),
        ("xPaddingHeader", "x-padding-header"),
        ("xPaddingPlacement", "x-padding-placement"),
        ("xPaddingMethod", "x-padding-method"),
        ("uplinkHTTPMethod", "uplink-http-method"),
        ("seqPlacement", "seq-placement"),
        ("seqKey", "seq-key"),
        ("uplinkDataPlacement", "uplink-data-placement"),
        ("uplinkDataKey", "uplink-data-key"),
    ):
        _put_str(opts, extra, src, dst)
    _put_str(opts, extra, "sessionIDPlacement", "session-placement")
    if "session-placement" not in opts:
        _put_str(opts, extra, "sessionPlacement", "session-placement")
    _put_str(opts, extra, "sessionIDKey", "session-key")
    if "session-key" not in opts:
        _put_str(opts, extra, "sessionKey", "session-key")
    _put_str(opts, extra, "sessionIDTable", "session-table")
    length = extra.get("sessionIDLength")
    if isinstance(length, str) and length:
        opts["session-length"] = length
    else:
        number = _json_int(length)
        if number is not None:
            opts["session-length"] = str(number)
    for src, dst in (
        ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
        ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
        ("uplinkChunkSize", "uplink-chunk-size"),
    ):
        number = _json_int(extra.get(src))
        if number is not None:
            opts[dst] = number
    reuse = _xmux_to_reuse(_as_dict(extra.get("xmux")))
    if reuse:
        opts["reuse-settings"] = reuse
    download = _download_settings(_as_dict(extra.get("downloadSettings")))
    if download:
        opts["download-settings"] = download


def xhttp_options(settings: dict) -> dict:
    extra = _as_dict(settings.get("extra"))
    opts: dict = {
        "path": settings.get("path") or "/",
        "mode": settings.get("mode") or "auto",
    }
    host = settings.get("host")
    if isinstance(host, str) and host:
        opts["host"] = host
    _apply_xhttp_extra(extra, opts)
    # Top-level keys win. Older panels put them next to path/mode, not in extra.
    if "xPaddingBytes" in settings:
        opts["x-padding-bytes"] = str(settings["xPaddingBytes"])
    if "scMaxEachPostBytes" in settings:
        opts["sc-max-each-post-bytes"] = settings["scMaxEachPostBytes"]
    headers = _header_map(settings.get("headers"))
    if headers:
        opts["headers"] = headers
    reuse = settings.get("reuseSettings")
    if isinstance(reuse, dict):
        opts["reuse-settings"] = _legacy_reuse(reuse)
    if not isinstance(opts.get("path"), str) or not opts["path"]:
        opts["path"] = "/"
    if not isinstance(opts.get("mode"), str) or not opts["mode"]:
        opts["mode"] = "auto"
    return opts


def _port(value) -> int | None:
    number = _json_int(value)
    if number is None and isinstance(value, str) and value.isdigit():
        number = int(value)
    if number is None or not 1 <= number <= 65535:
        return None
    return number


def convert_outbound(ob: dict, name: str, fingerprint_mode: str) -> dict | None:
    """xray outbound → mihomo proxy dict. None for unsupported protocols."""
    if ob.get("protocol") != "vless":
        return None
    settings = _as_dict(ob.get("settings"))
    vnext = settings.get("vnext") or []
    if not isinstance(vnext, list) or not vnext or not isinstance(vnext[0], dict):
        return None
    server_block = vnext[0]
    users = server_block.get("users") or []
    if not isinstance(users, list) or not users or not isinstance(users[0], dict):
        return None
    user = users[0]
    address = server_block.get("address")
    uuid = user.get("id")
    port = _port(server_block.get("port"))
    if not isinstance(address, str) or not address or not isinstance(uuid, str) or not uuid or port is None:
        return None

    stream = _as_dict(ob.get("streamSettings"))
    network = stream.get("network") or "tcp"
    if not isinstance(network, str):
        return None
    network = network.lower()
    if network == "raw":  # xray ≥24.x renamed tcp→raw; mihomo знает только tcp
        network = "tcp"
    elif network == "splithttp":  # old name of xhttp
        network = "xhttp"
    if network not in ("tcp", "xhttp"):
        return None

    sec = stream.get("security")
    sec = sec.lower() if isinstance(sec, str) else ""
    if sec not in ("reality", "tls"):
        return None

    proxy: dict = {
        "name": name,
        "type": "vless",
        "server": address,
        "port": port,
        "uuid": uuid,
        "packet-encoding": "xudp",
        "udp": True,
        "tls": True,
        "network": network,
        "client-fingerprint": "random",
        "encryption": user.get("encryption") if isinstance(user.get("encryption"), str) and user.get("encryption") else "none",
    }

    flow = user.get("flow")
    if isinstance(flow, str) and flow and network == "tcp":
        proxy["flow"] = flow

    reality: dict = {}
    tls: dict = {}
    if sec == "reality":
        reality = _as_dict(stream.get("realitySettings"))
        public_key = reality.get("publicKey")
        if not isinstance(public_key, str) or not public_key.strip():
            log.warning("skip %s: reality publicKey missing", name)
            return None
        sni = _server_name(reality)
        if sni:
            proxy["servername"] = sni
        short_id = reality.get("shortId", "")
        proxy["reality-opts"] = {
            "public-key": public_key.strip(),
            "short-id": "" if short_id is None else str(short_id),
        }
        if fingerprint_mode == "upstream" and isinstance(reality.get("fingerprint"), str) and reality["fingerprint"]:
            proxy["client-fingerprint"] = reality["fingerprint"]
    else:
        tls = _as_dict(stream.get("tlsSettings"))
        sni = _server_name(tls)
        if sni:
            proxy["servername"] = sni
        if fingerprint_mode == "upstream" and isinstance(tls.get("fingerprint"), str) and tls["fingerprint"]:
            proxy["client-fingerprint"] = tls["fingerprint"]
        if tls.get("allowInsecure") is True:
            proxy["skip-cert-verify"] = True

    if network == "xhttp":
        alpn_source = reality.get("alpn") if sec == "reality" else tls.get("alpn")
        if isinstance(alpn_source, list):
            alpn = [item for item in alpn_source if isinstance(item, str) and item]
        else:
            alpn = []
        proxy["alpn"] = alpn or ["h2"]
        xhttp = stream.get("xhttpSettings")
        if not isinstance(xhttp, dict):
            xhttp = stream.get("splithttpSettings")
        proxy["xhttp-opts"] = xhttp_options(_as_dict(xhttp))

    return proxy


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlparse(newurl).scheme
        if scheme not in ("http", "https"):
            raise urllib.error.URLError(f"refusing redirect to {scheme or 'unknown'} URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def sanitize_header_value(value: str | None) -> str | None:
    """Single-line visible ASCII, so an upstream header cannot inject another one."""
    if value is None:
        return None
    cleaned = "".join(ch for ch in str(value) if 32 <= ord(ch) < 127)
    cleaned = cleaned[:512]
    return cleaned or None


def fetch_source(src: dict, timeout: int = 15, max_bytes: int = MAX_UPSTREAM_BYTES) -> tuple[list | dict, str | None]:
    """Pull upstream subscription. Returns (xray JSON, subscription-userinfo)."""
    parsed = urllib.parse.urlparse(src["url"])
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("source URL must be http(s)")
    headers = {"User-Agent": src.get("user_agent") or "vpn-hub"}
    extra = src.get("headers") or {}
    if isinstance(extra, dict):
        headers.update({str(k): str(v) for k, v in extra.items()})
    req = urllib.request.Request(src["url"], headers=headers)
    # Ignore HTTP(S)_PROXY from the environment: the hub dials the subscription itself.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SafeRedirect)
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(max_bytes + 1)
        userinfo = sanitize_header_value(resp.headers.get("subscription-userinfo"))
    if len(body) > max_bytes:
        raise ValueError(f"upstream body exceeds {max_bytes} bytes")
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]
    return json.loads(body), userinfo


def extract_proxies(xray_profiles, dialect: str = "generic", prefix: str | None = None) -> dict:
    """xray profiles → {'main': [...], 'antiblock': [...], 'backup': [...]}."""
    if isinstance(xray_profiles, dict):
        profiles = [xray_profiles]
    elif isinstance(xray_profiles, list):
        profiles = xray_profiles
    else:
        raise ValueError("upstream JSON must be a list of xray profiles")
    if dialect not in DIALECTS:
        dialect = "generic"
    spec = DIALECTS[dialect]
    prefix = prefix or dialect
    out: dict = {"main": [], "antiblock": [], "backup": []}
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        remarks = profile.get("remarks")
        tag = spec["detect"](remarks if isinstance(remarks, str) else "")
        if tag not in out:
            continue
        for ob in profile.get("outbounds") or []:
            if not isinstance(ob, dict):
                continue
            if str(ob.get("tag") or "").lower() in ("direct", "block"):
                continue
            proxy = convert_outbound(ob, f"{prefix}-{tag}-{len(out[tag]) + 1:02d}", spec["fingerprint"])
            if proxy is None:
                continue
            out[tag].append(proxy)
    # Happ-style feeds repeat the same vless endpoints inside several full
    # client configs ("Автоматический", "Обход LTE", ...). The difference is
    # routing, which a proxy-provider cannot express, so keep the first copy.
    for tag, proxies in out.items():
        seen: set[str] = set()
        unique: list[dict] = []
        for proxy in proxies:
            identity = json.dumps(
                {key: value for key, value in proxy.items() if key != "name"},
                sort_keys=True,
                ensure_ascii=False,
            )
            if identity in seen:
                continue
            seen.add(identity)
            unique.append(proxy)
        for index, proxy in enumerate(unique, start=1):
            proxy["name"] = f"{prefix}-{tag}-{index:02d}"
        out[tag] = unique
    return out


def render_provider_from(by_mode: dict) -> str:
    """mihomo proxy-provider body. Names stay <source>-{main,antiblock,backup}-NN."""
    proxies = list(by_mode.get("main") or []) + list(by_mode.get("antiblock") or []) + list(by_mode.get("backup") or [])
    dumped = yaml.safe_dump(
        proxies,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=200,
    )
    return "proxies:\n" + dumped


def render_provider(state: "State", source: str) -> str:
    by_mode = state.proxies.get(source) or {"main": [], "antiblock": [], "backup": []}
    return render_provider_from(by_mode)


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proxies: dict[str, dict] = {}
        self.userinfo: dict[str, str | None] = {}
        self.last_pull_ok: dict[str, float] = {}


def check_source_name(name: str) -> None:
    if not isinstance(name, str) or _SOURCE_NAME.fullmatch(name) is None:
        raise ValueError(f"invalid source name: {name!r} (use letters, digits, '_' or '-')")


def _cache_path(state_dir: Path, source: str, suffix: str) -> Path:
    check_source_name(source)
    root = state_dir.resolve()
    path = (root / f"{source}.{suffix}").resolve()
    if path.parent != root:
        raise ValueError(f"cache path for {source!r} escapes {state_dir}")
    return path


def _tighten(path: Path, mode: int) -> None:
    if os.name != "posix":
        return
    try:
        path.chmod(mode)
    except OSError:
        pass


def load_cache(state_dir: Path, state: State, sources: dict) -> None:
    for name in sources:
        check_source_name(name)
        pj = _cache_path(state_dir, name, "proxies.json")
        uj = _cache_path(state_dir, name, "userinfo")
        if pj.exists():
            try:
                state.proxies[name] = json.loads(pj.read_text(encoding="utf-8"))
                log.info("%s: loaded cached proxies: %s", name,
                         {k: len(v) for k, v in state.proxies[name].items()})
            except Exception as e:  # noqa: BLE001
                log.warning("%s: cache parse failed: %s", name, e)
        if uj.exists():
            state.userinfo[name] = sanitize_header_value(uj.read_text(encoding="utf-8").strip())


def save_cache(state_dir: Path, source: str, by_mode: dict, userinfo: str | None) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    _tighten(state_dir, 0o750)
    pj = _cache_path(state_dir, source, "proxies.json")
    with tempfile.NamedTemporaryFile(
        "w", dir=state_dir, delete=False, encoding="utf-8", newline="\n"
    ) as handle:
        json.dump(by_mode, handle, ensure_ascii=False)
        tmp = Path(handle.name)
    tmp.replace(pj)
    _tighten(pj, 0o640)
    if userinfo:
        uj = _cache_path(state_dir, source, "userinfo")
        uj.write_text(userinfo + "\n", encoding="utf-8")
        _tighten(uj, 0o640)


def refresh_once(cfg: dict, state: State, source: str) -> bool:
    check_source_name(source)
    src = cfg["sources"][source]
    # A source named like a dialect ("govpn") picks that dialect when the
    # config omits one. Anything else falls back to generic.
    dialect = src.get("dialect", source)
    if dialect not in DIALECTS:
        dialect = "generic"
    timeout = src.get("timeout") or 15
    if isinstance(timeout, bool) or not isinstance(timeout, int):
        timeout = 15
    try:
        xray_profiles, userinfo = fetch_source(src, timeout=timeout)
        by_mode = extract_proxies(xray_profiles, dialect=dialect, prefix=source)
        counts = {k: len(v) for k, v in by_mode.items()}
        log.info("%s pulled: %s userinfo=%s", source, counts, userinfo)
    except Exception as e:  # noqa: BLE001
        log.warning("%s pull failed: %s", source, e)
        return False
    with state.lock:
        state.proxies[source] = by_mode
        state.userinfo[source] = userinfo
        state.last_pull_ok[source] = time.time()
    try:
        save_cache(Path(cfg["state_dir"]), source, by_mode, userinfo)
    except Exception as e:  # noqa: BLE001
        log.warning("%s: cache write failed: %s", source, e)
    return True


def warm_sources(cfg: dict, state: State) -> None:
    for name in cfg["sources"]:
        refresh_once(cfg, state, name)


def _request_path(raw: str) -> str:
    path = raw.split("?", 1)[0]
    if "://" in path:
        path = urllib.parse.urlparse(raw).path
    return path


def make_handler(cfg: dict, state: State):
    class Handler(http.server.BaseHTTPRequestHandler):
        timeout = 20

        def log_message(self, fmt, *args):  # quieter
            log.info("%s - %s", self.address_string(), fmt % args)

        def do_GET(self):
            path = _request_path(self.path)
            if path == "/healthz":
                with state.lock:
                    lines = [f"ok={all(name in state.proxies for name in cfg['sources'])}"]
                    lines += [f"{name}={name in state.proxies}" for name in cfg["sources"]]
                body = ("\n".join(lines) + "\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            source = path.removeprefix("/").removesuffix(".yaml")
            if not path.endswith(".yaml") or source not in cfg["sources"]:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            fresh = refresh_once(cfg, state, source)
            with state.lock:
                current = state.proxies.get(source)
                userinfo = state.userinfo.get(source)
                if current is not None:
                    current = {key: list(value) for key, value in current.items()}
            if current is None:
                log.error("%s: no data — live-pull failed and no cache", source)
                self.send_response(503)
                self.send_header("Retry-After", "30")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if not fresh:
                log.info("%s: serving from stale cache (upstream unreachable)", source)

            try:
                body = render_provider_from(current)
            except Exception as e:  # noqa: BLE001
                log.exception("%s: render failed: %s", source, e)
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            body_bytes = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            safe_userinfo = sanitize_header_value(userinfo)
            if safe_userinfo:
                self.send_header("subscription-userinfo", safe_userinfo)
            self.send_header("profile-update-interval", "1")
            self.end_headers()
            self.wfile.write(body_bytes)

    return Handler


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def serve_forever(self, poll_interval=0.5):
        try:
            super().serve_forever(poll_interval)
        except OSError as exc:
            # Windows raises WinError 10038 if the listening socket is closed
            # while select() is blocked. Treat that as a shutdown.
            if getattr(exc, "winerror", None) != 10038:
                raise


def _require_header_token(value, what: str) -> str:
    if not isinstance(value, str) or not value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{what} must be a single-line string")
    return value


def load_config(path: Path) -> dict:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"invalid YAML in {path}: {e}") from e
    if not isinstance(loaded, dict):
        raise ValueError("config must be a mapping")
    for key in ("listen", "state_dir", "sources"):
        if key not in loaded:
            raise ValueError(f"config needs {key}")
    listen = loaded["listen"]
    if not isinstance(listen, str) or listen.count(":") < 1:
        raise ValueError("listen must be host:port")
    host, _, port_s = listen.rpartition(":")
    if not host or not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
        raise ValueError("listen must be host:port")
    if not isinstance(loaded["state_dir"], str) or not loaded["state_dir"]:
        raise ValueError("state_dir must be a path")
    sources = loaded["sources"]
    if not isinstance(sources, dict) or not sources:
        raise ValueError("sources must be a non-empty mapping")
    for name, src in sources.items():
        check_source_name(name)
        if not isinstance(src, dict):
            raise ValueError(f"{name}: source must be a mapping")
        url = src.get("url")
        if not isinstance(url, str):
            raise ValueError(f"{name}: url is required")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"{name}: url must be http(s)")
        if "user_agent" in src and src["user_agent"] is not None:
            _require_header_token(src["user_agent"], f"{name}: user_agent")
        headers = src.get("headers") or {}
        if not isinstance(headers, dict):
            raise ValueError(f"{name}: headers must be a mapping")
        for hk, hv in headers.items():
            _require_header_token(hk, f"{name}: header name")
            _require_header_token(hv, f"{name}: header {hk}")
        dialect = src.get("dialect")
        if dialect is not None and not isinstance(dialect, str):
            raise ValueError(f"{name}: dialect must be a string")
        if "timeout" in src and src["timeout"] is not None:
            timeout = src["timeout"]
            if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 120:
                raise ValueError(f"{name}: timeout must be a whole number of seconds from 1 to 120")
    return loaded


def serve(cfg: dict, state: State, ready=None) -> None:
    host, _, port_s = str(cfg["listen"]).rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host not in {"127.0.0.1", "localhost", "::1"}:
        log.warning(
            "listen address %s is not loopback; terminate TLS and basic_auth in front of it",
            cfg["listen"],
        )
    # Bind before the startup pull so the port is not refused, but do not answer
    # until that pull finishes: the first /healthz then matches the cache-or-live state.
    httpd = ThreadingHTTPServer((host, int(port_s)), make_handler(cfg, state))
    warm_sources(cfg, state)
    log.info(
        "vpn-hub listening on %s (sources: %s; live-pull per request, cache as failover)",
        cfg["listen"],
        ", ".join(cfg["sources"]),
    )
    worker = threading.Thread(target=httpd.serve_forever, name="vpn-hub", daemon=True)
    worker.start()
    try:
        if ready is None:
            worker.join()
        else:
            ready(httpd)
    finally:
        httpd.shutdown()
        httpd.server_close()
        worker.join(timeout=5)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = list(sys.argv[1:] if argv is None else argv)
    path = CONFIG_PATH
    if args:
        if len(args) != 2 or args[0] != "--config" or not args[1]:
            raise SystemExit("usage: render.py [--config PATH]")
        path = Path(args[1])
    try:
        cfg = load_config(path)
    except (OSError, ValueError) as e:
        log.error("config: %s", e)
        sys.exit(1)
    state = State()
    load_cache(Path(cfg["state_dir"]), state, cfg["sources"])
    serve(cfg, state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
