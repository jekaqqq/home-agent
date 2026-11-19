#!/usr/bin/env python3
"""vpn-hub: subscription bridge — upstream xray-JSON → mihomo proxy-provider.

Each source from /etc/vpn-hub/config.yaml is served at /<name>.yaml,
live-pulled on every request; disk cache is failover-only. Put it behind a
TLS reverse-proxy with basic_auth (e.g. Caddy: sub.example.com:8443 →
127.0.0.1:8080). See README.md.

Config path: /etc/vpn-hub/config.yaml, or $VPN_HUB_CONFIG, or argv[1].
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
import urllib.request
from pathlib import Path

import yaml

CONFIG_PATH = Path("/etc/vpn-hub/config.yaml")
MAX_BODY = 8 * 1024 * 1024
SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
BUCKETS = ("main", "antiblock", "backup")

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


def detect_mode_clo(remarks: str) -> str:
    # «Автоматический» — xray-балансировщик тех же нод, что и профили «Обход LTE».
    # В mihomo url-test делает то же самое, поэтому агрегат пропускаем.
    if "Автоматический" in remarks:
        return "unknown"
    if "Обход LTE" in remarks:
        return "antiblock"
    return "main"


# fingerprint: "random" hardcodes utls fp; "upstream" mirrors the fp the
# subscription ships (falls back to random when absent).
DIALECTS = {
    "govpn": {"detect": detect_mode_govpn, "fingerprint": "random"},
    "buzzvpn": {"detect": detect_mode_buzzvpn, "fingerprint": "upstream"},
    "clo": {"detect": detect_mode_clo, "fingerprint": "upstream"},
    "generic": {"detect": detect_mode_generic, "fingerprint": "upstream"},
}


def sanitize_header_value(value: object) -> str | None:
    """One-line header value: CR/LF would let an upstream inject response headers."""
    if value is None:
        return None
    chars: list[str] = []
    for ch in str(value):
        if ch in "\r\n\t":
            chars.append(" ")
        elif ch >= " " and ch != "\x7f":
            chars.append(ch)
    text = " ".join("".join(chars).split())
    return text or None


def _redact(message: str, secret: str) -> str:
    if secret:
        message = message.replace(secret, "<url>")
    return message.replace("\r", " ").replace("\n", " ")[:500]


def _server_name(settings: dict) -> str:
    name = settings.get("serverName")
    if not isinstance(name, str) or not name:
        name = settings.get("server_name")
    if isinstance(name, str) and name:
        return name
    names = settings.get("serverNames") or settings.get("server_names") or []
    if isinstance(names, list):
        for item in names:
            if isinstance(item, str) and item:
                return item
    return ""


def _normalize_alpn(alpn: object) -> list[str] | None:
    if isinstance(alpn, str) and alpn:
        return [alpn]
    if isinstance(alpn, list) and alpn and all(isinstance(item, str) and item for item in alpn):
        return list(alpn)
    return None


def _apply_fingerprint(proxy: dict, settings: dict, mode: str) -> None:
    if mode != "upstream":
        return
    fingerprint = settings.get("fingerprint")
    if isinstance(fingerprint, str) and fingerprint:
        proxy["client-fingerprint"] = fingerprint


def _header_map(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    out: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, str):
            out[key] = value
        elif isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            out[key] = value[0] if len(value) == 1 else ", ".join(value)
    return out or None


def _reuse_opts(raw: object) -> dict | None:
    if not isinstance(raw, dict):
        return None
    # mihomo string-range fields stay strings; h-keep-alive-period is seconds.
    fields = (
        ("maxConcurrency", "max-concurrency", True),
        ("maxConnections", "max-connections", True),
        ("cMaxReuseTimes", "c-max-reuse-times", True),
        ("hMaxRequestTimes", "h-max-request-times", True),
        ("hMaxReusableSecs", "h-max-reusable-secs", True),
        ("hKeepAlivePeriod", "h-keep-alive-period", False),
    )
    opts: dict = {}
    for src_key, dst_key, as_str in fields:
        if src_key not in raw or raw[src_key] in (None, ""):
            continue
        value = raw[src_key]
        opts[dst_key] = str(value) if as_str else value
    return opts or None


def _pick(primary: dict, extra: dict, key: str, default=None):
    if key in primary:
        return primary[key]
    if key in extra:
        return extra[key]
    return default


def _xhttp_opts(stream: dict) -> dict:
    raw = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
    if not isinstance(raw, dict):
        raw = {}
    extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}

    path = _pick(raw, extra, "path", "/")
    mode = _pick(raw, extra, "mode", "auto")
    opts: dict = {
        "path": path if isinstance(path, str) and path else "/",
        "mode": mode if isinstance(mode, str) and mode else "auto",
    }
    host = _pick(raw, extra, "host")
    if isinstance(host, str) and host:
        opts["host"] = host

    padding = _pick(raw, extra, "xPaddingBytes")
    if padding not in (None, ""):
        opts["x-padding-bytes"] = str(padding)
    for src_key, dst_key in (
        ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
        ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
    ):
        value = _pick(raw, extra, src_key)
        if value not in (None, ""):
            opts[dst_key] = value
    no_grpc = _pick(raw, extra, "noGRPCHeader")
    if isinstance(no_grpc, bool):
        opts["no-grpc-header"] = no_grpc

    headers = _header_map(raw.get("headers"))
    if headers:
        opts["headers"] = headers

    reuse = _reuse_opts(
        raw.get("reuseSettings")
        or raw.get("xmux")
        or extra.get("xmux")
        or extra.get("reuseSettings")
    )
    if reuse:
        opts["reuse-settings"] = reuse
    return opts


def convert_outbound(ob: dict, name: str, fingerprint_mode: str) -> dict | None:
    """xray outbound → mihomo proxy dict. None for unsupported or incomplete nodes."""
    if not isinstance(ob, dict) or ob.get("protocol") != "vless":
        return None
    settings = ob.get("settings") or {}
    if not isinstance(settings, dict):
        return None
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
    try:
        port = int(server_block.get("port"))
    except (TypeError, ValueError):
        return None
    if not isinstance(address, str) or not address or not isinstance(uuid, str) or not uuid:
        return None
    if not 1 <= port <= 65535:
        return None

    stream = ob.get("streamSettings") or {}
    if not isinstance(stream, dict):
        return None
    network = stream.get("network") or "tcp"
    if network == "raw":  # xray ≥24 renamed tcp→raw; mihomo knows tcp
        network = "tcp"
    elif network == "splithttp":  # previous name of xhttp
        network = "xhttp"
    if network not in ("tcp", "xhttp"):
        return None

    security = stream.get("security")
    if security == "reality":
        sec_settings = stream.get("realitySettings") or {}
    elif security == "tls":
        sec_settings = stream.get("tlsSettings") or {}
    else:
        return None
    if not isinstance(sec_settings, dict):
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
    }

    flow = user.get("flow")
    if isinstance(flow, str) and flow and network == "tcp":
        proxy["flow"] = flow

    proxy["servername"] = _server_name(sec_settings)
    if security == "reality":
        public_key = sec_settings.get("publicKey") or sec_settings.get("public_key") or ""
        if not isinstance(public_key, str) or not public_key.strip():
            return None
        short_id = sec_settings.get("shortId", sec_settings.get("short_id"))
        if short_id is None:
            short_ids = sec_settings.get("shortIds") or sec_settings.get("short_ids") or []
            short_id = short_ids[0] if isinstance(short_ids, list) and short_ids else ""
        proxy["reality-opts"] = {
            "public-key": public_key.strip(),
            "short-id": "" if short_id is None else str(short_id),
        }

    _apply_fingerprint(proxy, sec_settings, fingerprint_mode)

    alpn = _normalize_alpn(sec_settings.get("alpn"))
    if alpn:
        proxy["alpn"] = alpn
    elif network == "xhttp":
        proxy["alpn"] = ["h2"]

    if network == "xhttp":
        proxy["xhttp-opts"] = _xhttp_opts(stream)
    return proxy


def normalize_profiles(payload: object) -> list[dict]:
    """V2Box/Happ/Hiddify body: a list of profiles, or one profile object."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("outbounds"), list):
        return [payload]
    raise ValueError(f"unsupported subscription shape: {type(payload).__name__}")


def extract_proxies(payload: object, dialect: str = "generic", prefix: str | None = None) -> dict:
    """xray profiles → {'main': [...], 'antiblock': [...], 'backup': [...]}."""
    if dialect not in DIALECTS:
        raise KeyError(dialect)
    spec = DIALECTS[dialect]
    prefix = prefix or dialect
    out: dict[str, list] = {bucket: [] for bucket in BUCKETS}
    seen: dict[str, set[str]] = {bucket: set() for bucket in BUCKETS}
    skipped = 0
    duplicates = 0
    for profile in normalize_profiles(payload):
        remarks = profile.get("remarks") or ""
        if not isinstance(remarks, str):
            remarks = str(remarks)
        try:
            tag = spec["detect"](remarks)
        except Exception:  # noqa: BLE001 — a custom dialect must not abort the pull
            log.warning("%s: dialect %s failed on remarks %r", prefix, dialect, remarks[:80])
            continue
        if tag not in out:
            log.debug("%s: skip remarks %r (mode %s)", prefix, remarks[:80], tag)
            continue
        outbounds = profile.get("outbounds")
        if not isinstance(outbounds, list):
            continue
        for ob in outbounds:
            if isinstance(ob, dict) and str(ob.get("tag", "")).lower() in ("direct", "block"):
                continue
            name = f"{prefix}-{tag}-{len(out[tag]) + 1:02d}"
            try:
                proxy = convert_outbound(ob, name, spec["fingerprint"]) if isinstance(ob, dict) else None
            except Exception:  # noqa: BLE001
                log.debug("%s: convert failed for %s", prefix, name, exc_info=True)
                proxy = None
            if proxy is None:
                skipped += 1
                continue
            # Happ/xray balancers repeat the same outbound in several profiles.
            # Keep the first copy in each bucket; a later bucket may still
            # carry the same endpoint under its own name.
            identity = json.dumps(
                {key: value for key, value in proxy.items() if key != "name"},
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            if identity in seen[tag]:
                duplicates += 1
                continue
            seen[tag].add(identity)
            out[tag].append(proxy)
    if skipped:
        log.info("%s: skipped %d outbound(s)", prefix, skipped)
    if duplicates:
        log.info("%s: skipped %d duplicate outbound(s)", prefix, duplicates)
    return out


def render_provider(state: "State", source: str) -> tuple[str, str | None]:
    """Source nodes as a mihomo proxy-provider payload, plus userinfo.

    Names stay <source>-{main,antiblock,backup}-NN so a local profile can
    filter via `use:` + `filter:` regex on prefix.
    """
    with state.lock:
        by_mode = state.proxies.get(source)
        userinfo = state.userinfo.get(source)
        if not by_mode:
            raise KeyError(source)
        proxies = [item for bucket in BUCKETS for item in by_mode.get(bucket) or []]
    body = yaml.safe_dump(
        {"proxies": proxies},
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=200,
    )
    return body, userinfo


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proxies: dict[str, dict] = {}
        self.userinfo: dict[str, str | None] = {}
        self.last_pull_ok: dict[str, float] = {}
        self.serving_stale: dict[str, bool] = {}


def _valid_buckets(data: object) -> dict | None:
    if not isinstance(data, dict):
        return None
    out: dict[str, list] = {}
    for key in BUCKETS:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            return None
        out[key] = list(value)
    return out


def load_cache(state_dir: Path, state: State, sources: dict) -> None:
    for name in sources:
        if not SOURCE_NAME.fullmatch(name):
            log.warning("ignoring cache for invalid source name %r", name)
            continue
        pj = state_dir / f"{name}.proxies.json"
        uj = state_dir / f"{name}.userinfo"
        if pj.exists():
            try:
                parsed = _valid_buckets(json.loads(pj.read_text()))
            except Exception as e:  # noqa: BLE001
                log.warning("%s: cache parse failed: %s", name, e)
                parsed = None
            if parsed and sum(len(bucket) for bucket in parsed.values()):
                state.proxies[name] = parsed
                log.info(
                    "%s: loaded cached proxies: %s",
                    name,
                    {key: len(value) for key, value in parsed.items()},
                )
                if uj.exists():
                    state.userinfo[name] = sanitize_header_value(uj.read_text())
            elif parsed is not None:
                log.warning("%s: ignoring empty cache", name)


def _atomic_write(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, dest)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def save_cache(state_dir: Path, source: str, by_mode: dict, userinfo: str | None) -> None:
    if not SOURCE_NAME.fullmatch(source):
        raise ValueError(f"invalid source name: {source!r}")
    payload = json.dumps(by_mode, ensure_ascii=False) + "\n"
    _atomic_write(state_dir / f"{source}.proxies.json", payload)
    if userinfo:
        _atomic_write(state_dir / f"{source}.userinfo", userinfo + "\n")


def _mark_stale(state: State, source: str) -> None:
    with state.lock:
        if source in state.proxies:
            state.serving_stale[source] = True


def fetch_source(src: dict, timeout: int = 15) -> tuple[object, str | None]:
    """Pull upstream subscription. Returns (xray-json, subscription-userinfo)."""
    headers = {"User-Agent": str(src.get("user_agent") or "vpn-hub")}
    extra = src.get("headers") or {}
    if isinstance(extra, dict):
        for key, value in extra.items():
            if isinstance(key, str) and value is not None:
                headers[key] = str(value)
    req = urllib.request.Request(src["url"], headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("upstream body exceeds 8 MiB")
        userinfo = sanitize_header_value(resp.headers.get("subscription-userinfo"))
    return json.loads(body), userinfo


def refresh_once(cfg: dict, state: State, source: str) -> bool:
    src = cfg["sources"][source]
    dialect = src.get("dialect", source)
    if dialect not in DIALECTS:
        log.warning("%s: unknown dialect %r, using generic", source, dialect)
        dialect = "generic"
    try:
        timeout = int(src.get("timeout") or 15)
    except (TypeError, ValueError):
        timeout = 15
    url = src.get("url") or ""
    try:
        payload, userinfo = fetch_source(src, timeout=timeout)
        userinfo = sanitize_header_value(userinfo)
        by_mode = extract_proxies(payload, dialect=dialect, prefix=source)
    except Exception as e:  # noqa: BLE001
        log.warning("%s pull failed: %s", source, _redact(str(e), url))
        _mark_stale(state, source)
        return False

    total = sum(len(bucket) for bucket in by_mode.values())
    if total == 0:
        log.warning("%s: no convertible vless nodes; keeping previous cache", source)
        _mark_stale(state, source)
        return False

    if userinfo is None:
        userinfo = state.userinfo.get(source)
    counts = {key: len(value) for key, value in by_mode.items()}
    log.info("%s pulled: %s userinfo=%s", source, counts, userinfo)
    with state.lock:
        state.proxies[source] = by_mode
        state.userinfo[source] = userinfo
        state.last_pull_ok[source] = time.time()
        state.serving_stale[source] = False
    try:
        save_cache(Path(cfg["state_dir"]), source, by_mode, userinfo)
    except Exception as e:  # noqa: BLE001
        log.warning("%s: cache write failed: %s", source, e)
    return True


def _health_body(cfg: dict, state: State) -> bytes:
    with state.lock:
        lines = [f"ok={all(name in state.proxies for name in cfg['sources'])}"]
        now = time.time()
        for name in cfg["sources"]:
            present = name in state.proxies
            if not present:
                lines.append(f"{name}=False")
                continue
            nodes = sum(len(state.proxies[name].get(bucket) or []) for bucket in BUCKETS)
            bits = [f"nodes={nodes}"]
            if name in state.last_pull_ok:
                bits.append(f"age={int(now - state.last_pull_ok[name])}s")
            else:
                bits.append("cached=1")
            if state.serving_stale.get(name):
                bits.append("stale=1")
            lines.append(f"{name}=True " + " ".join(bits))
    return ("\n".join(lines) + "\n").encode()


def make_handler(cfg: dict, state: State):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "vpn-hub"
        sys_version = ""

        def version_string(self) -> str:
            return "vpn-hub"

        def log_message(self, fmt, *args):  # quieter, and via our logger
            log.info("%s - %s", self.address_string(), fmt % args)

        def _reply(self, code: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):  # noqa: N802 — stdlib handler API
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._reply(200, _health_body(cfg, state), "text/plain; charset=utf-8")
                return

            source = path.removeprefix("/").removesuffix(".yaml")
            if not path.endswith(".yaml") or source not in cfg["sources"]:
                self._reply(404, b"", "text/plain; charset=utf-8")
                return

            fresh = refresh_once(cfg, state, source)
            with state.lock:
                has_data = source in state.proxies
            if not has_data:
                log.error("%s: no data — live-pull failed and no cache", source)
                self._reply(503, b"", "text/plain; charset=utf-8", {"Retry-After": "30"})
                return
            if not fresh:
                log.info("%s: serving from stale cache (upstream unreachable)", source)

            try:
                body, userinfo = render_provider(state, source)
            except Exception as e:  # noqa: BLE001
                log.exception("%s: render failed: %s", source, e)
                self._reply(500, b"", "text/plain; charset=utf-8")
                return

            extra = {"profile-update-interval": "1"}
            if userinfo:
                extra["subscription-userinfo"] = userinfo
            self._reply(200, body.encode("utf-8"), "text/yaml; charset=utf-8", extra)

    return Handler


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def parse_listen(listen: object) -> tuple[str, int]:
    if not isinstance(listen, str) or ":" not in listen:
        raise ValueError(f"invalid listen address: {listen!r}")
    host, port_s = listen.rsplit(":", 1)
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ValueError(f"invalid listen address: {listen!r}")
    try:
        port = int(port_s)
    except ValueError as e:
        raise ValueError(f"invalid listen port: {port_s!r}") from e
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid listen port: {port}")
    return host, port


def validate_config(cfg: object) -> None:
    if not isinstance(cfg, dict):
        raise SystemExit("config: expected a mapping")
    sources = cfg.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise SystemExit("config: sources must be a non-empty map")
    for name, src in sources.items():
        if not isinstance(name, str) or not SOURCE_NAME.fullmatch(name):
            raise SystemExit(
                f"config: invalid source name {name!r} (use [A-Za-z0-9._-], max 64, start alphanumeric)"
            )
        if not isinstance(src, dict) or not isinstance(src.get("url"), str) or not src["url"]:
            raise SystemExit(f"config: source {name} needs a url")
    state_dir = cfg.get("state_dir")
    if not isinstance(state_dir, str) or not state_dir:
        raise SystemExit("config: state_dir is required")
    try:
        parse_listen(cfg.get("listen"))
    except ValueError as e:
        raise SystemExit(f"config: {e}") from e


def config_path() -> Path:
    if len(sys.argv) > 2:
        raise SystemExit("usage: render.py [config.yaml]")
    if len(sys.argv) == 2:
        return Path(sys.argv[1])
    env = os.environ.get("VPN_HUB_CONFIG")
    if env:
        return Path(env)
    return CONFIG_PATH


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    path = config_path()
    if not path.is_file():
        log.error("config not found: %s", path)
        sys.exit(1)
    try:
        cfg = yaml.safe_load(path.read_text())
    except Exception as e:  # noqa: BLE001
        log.error("config parse failed: %s", e)
        sys.exit(1)
    try:
        validate_config(cfg)
    except SystemExit as e:
        log.error("%s", e)
        sys.exit(1)

    state = State()
    load_cache(Path(cfg["state_dir"]), state, cfg["sources"])
    host, port = parse_listen(cfg["listen"])
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg, state))
    log.info(
        "vpn-hub listening on %s (sources: %s; live-pull per request, cache as failover)",
        cfg["listen"],
        ", ".join(cfg["sources"]),
    )
    httpd.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
