"""Converter, cache, and HTTP behaviour of vpn-hub."""

from __future__ import annotations

import http.server
import json
import logging
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import render  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
UUID = "11111111-1111-1111-1111-111111111111"


def setUpModule():
    logging.disable(logging.CRITICAL)


def tearDownModule():
    logging.disable(logging.NOTSET)


def _user(flow: str | None = "xtls-rprx-vision", encryption: str | None = None) -> dict:
    user = {"id": UUID}
    if flow is not None:
        user["flow"] = flow
    if encryption is not None:
        user["encryption"] = encryption
    return user


def _vless(address: str = "203.0.113.10", *, stream: dict, flow: str | None = "xtls-rprx-vision",
           encryption: str | None = None, port=443, tag: str | None = "proxy") -> dict:
    ob = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": port, "users": [_user(flow, encryption)]}]},
        "streamSettings": stream,
    }
    if tag is not None:
        ob["tag"] = tag
    return ob


def _reality_stream(**extra) -> dict:
    reality = {
        "serverName": "www.microsoft.com",
        "fingerprint": "chrome",
        "publicKey": "PUBLIC",
        "shortId": "abcd",
    }
    reality.update(extra)
    return {"network": "tcp", "security": "reality", "realitySettings": reality}


def _profile(remarks: str, *outbounds: dict) -> dict:
    return {"remarks": remarks, "outbounds": list(outbounds)}


def _names(by_mode: dict) -> dict[str, list[str]]:
    return {mode: [proxy["name"] for proxy in proxies] for mode, proxies in by_mode.items()}


class ConvertTests(unittest.TestCase):
    def test_reality_tcp_vision_random_fingerprint(self):
        profiles = [_profile("nl", _vless(stream=_reality_stream()))]
        by_mode = render.extract_proxies(profiles, dialect="govpn", prefix="govpn")
        self.assertEqual(_names(by_mode), {"main": [], "antiblock": [], "backup": []})
        # "nl" matches no govpn tag, so the node is dropped.
        profiles = [_profile("Основной режим NL", _vless(stream=_reality_stream()))]
        proxy = render.extract_proxies(profiles, dialect="govpn", prefix="govpn")["main"][0]
        self.assertEqual(proxy, {
            "name": "govpn-main-01",
            "type": "vless",
            "server": "203.0.113.10",
            "port": 443,
            "uuid": UUID,
            "packet-encoding": "xudp",
            "udp": True,
            "tls": True,
            "network": "tcp",
            "client-fingerprint": "random",
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "servername": "www.microsoft.com",
            "reality-opts": {"public-key": "PUBLIC", "short-id": "abcd"},
        })

    def test_upstream_fingerprint_and_custom_encryption(self):
        ob = _vless(stream=_reality_stream(), encryption="mlkem768x25519plus")
        proxy = render.convert_outbound(ob, "n", "upstream")
        self.assertEqual(proxy["client-fingerprint"], "chrome")
        self.assertEqual(proxy["encryption"], "mlkem768x25519plus")

    def test_raw_network_becomes_tcp_and_keeps_flow(self):
        stream = _reality_stream()
        stream["network"] = "raw"
        proxy = render.convert_outbound(_vless(stream=stream), "n", "random")
        self.assertEqual(proxy["network"], "tcp")
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")

    def test_tls_without_reality_opts(self):
        stream = {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": "ex.com", "fingerprint": "firefox", "allowInsecure": True},
        }
        proxy = render.convert_outbound(_vless(stream=stream, flow=None), "n", "upstream")
        self.assertEqual(proxy["servername"], "ex.com")
        self.assertEqual(proxy["client-fingerprint"], "firefox")
        self.assertTrue(proxy["skip-cert-verify"])
        self.assertNotIn("reality-opts", proxy)
        self.assertNotIn("flow", proxy)

    def test_xhttp_does_not_copy_vision_flow_and_reads_extra(self):
        stream = {
            "network": "xhttp",
            "security": "tls",
            "tlsSettings": {"serverName": "ex.com", "alpn": ["h3"]},
            "xhttpSettings": {
                "path": "/xh",
                "host": "ex.com",
                "mode": "stream-up",
                "extra": {
                    "xPaddingBytes": "100-1000",
                    "noGRPCHeader": True,
                    "scMaxEachPostBytes": 1000000,
                    "scMinPostsIntervalMs": 30,
                    "xmux": {"maxConcurrency": "16-32", "hKeepAlivePeriod": 15},
                    "downloadSettings": {
                        "address": "dl.example.com",
                        "port": 8443,
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "www.cloudflare.com",
                            "fingerprint": "chrome",
                            "publicKey": "DLPUB",
                            "shortId": "aa",
                        },
                        "xhttpSettings": {
                            "path": "/dl",
                            "host": "dl.example.com",
                            "extra": {"xmux": {"maxConnections": 4}},
                        },
                    },
                },
            },
        }
        proxy = render.convert_outbound(_vless(stream=stream), "n", "upstream")
        self.assertEqual(proxy["network"], "xhttp")
        self.assertEqual(proxy["alpn"], ["h3"])
        self.assertNotIn("flow", proxy)
        self.assertEqual(proxy["xhttp-opts"], {
            "path": "/xh",
            "mode": "stream-up",
            "host": "ex.com",
            "x-padding-bytes": "100-1000",
            "no-grpc-header": True,
            "sc-max-each-post-bytes": 1000000,
            "sc-min-posts-interval-ms": 30,
            "reuse-settings": {"max-concurrency": "16-32", "h-keep-alive-period": 15},
            "download-settings": {
                "server": "dl.example.com",
                "port": 8443,
                "tls": True,
                "servername": "www.cloudflare.com",
                "client-fingerprint": "chrome",
                "reality-opts": {"public-key": "DLPUB", "short-id": "aa"},
                "path": "/dl",
                "host": "dl.example.com",
                "reuse-settings": {"max-connections": "4"},
            },
        })

    def test_flat_xhttp_fields_keep_legacy_shape(self):
        stream = {
            "network": "splithttp",
            "security": "reality",
            "realitySettings": _reality_stream()["realitySettings"],
            "splithttpSettings": {
                "path": "/",
                "mode": "auto",
                "xPaddingBytes": "100-1000",
                "scMaxEachPostBytes": 1000000,
                "reuseSettings": {
                    "maxConcurrency": "16-32",
                    "maxConnections": 0,
                    "cMaxReuseTimes": 0,
                    "hMaxRequestTimes": "600-900",
                    "hMaxReusableSecs": "1800-3000",
                    "hKeepAlivePeriod": 0,
                },
                "extra": {"xPaddingBytes": "should-lose", "xmux": {"maxConcurrency": "1"}},
            },
        }
        proxy = render.convert_outbound(_vless(stream=stream, flow="xtls-rprx-vision"), "n", "random")
        self.assertEqual(proxy["network"], "xhttp")
        self.assertEqual(proxy["alpn"], ["h2"])
        self.assertNotIn("flow", proxy)
        self.assertEqual(proxy["client-fingerprint"], "random")
        self.assertEqual(proxy["xhttp-opts"], {
            "path": "/",
            "mode": "auto",
            "x-padding-bytes": "100-1000",
            "sc-max-each-post-bytes": 1000000,
            "reuse-settings": {
                "max-concurrency": "16-32",
                "max-connections": 0,
                "c-max-reuse-times": 0,
                "h-max-request-times": "600-900",
                "h-max-reusable-secs": "1800-3000",
                "h-keep-alive-period": 0,
            },
        })

    def test_skips_unsupported_and_keeps_the_rest(self):
        good = _vless(address="203.0.113.2", stream=_reality_stream())
        broken = _vless(address="203.0.113.3", stream=_reality_stream(publicKey=""))
        ws = _vless(address="203.0.113.4", stream={"network": "ws", "security": "tls", "tlsSettings": {}})
        vmess = {"protocol": "vmess", "settings": {}, "tag": "vm"}
        direct = {"protocol": "freedom", "tag": "DIRECT"}
        profiles = [
            _profile("a", direct, good),
            {"remarks": None, "outbounds": [vmess]},
            "not-a-profile",
            _profile("b", broken, ws),
            _profile("c", _vless(address="203.0.113.5", stream=_reality_stream(), port="443")),
        ]
        by_mode = render.extract_proxies(profiles, dialect="generic", prefix="myvpn")
        self.assertEqual(_names(by_mode)["main"], ["myvpn-main-01", "myvpn-main-02"])
        self.assertEqual([p["server"] for p in by_mode["main"]], ["203.0.113.2", "203.0.113.5"])

    def test_happ_install_url_points_at_the_json_feed(self):
        rewritten = render.normalize_subscription_url("https://clolinks.example/happ?token=abc")
        self.assertEqual(rewritten, "https://clolinks.example/api/sub?token=abc")
        self.assertEqual(
            render.normalize_subscription_url("https://clolinks.example/api/sub?token=abc"),
            "https://clolinks.example/api/sub?token=abc",
        )

    def test_router_config_keeps_subscription_direct_rules(self):
        stream = _reality_stream()
        profiles = [
            {
                "remarks": "Автоматический",
                "outbounds": [_vless(address="203.0.113.2", stream=stream)],
                "routing": {
                    "rules": [
                        {"type": "field", "outboundTag": "direct", "ip": ["10.0.0.0/8", "not-a-cidr"]},
                        {
                            "type": "field",
                            "outboundTag": "direct",
                            "domain": ["domain:vk.ru", "full:kion.ru", "geosite:private", "regexp:a,b"],
                        },
                        {"type": "field", "outboundTag": "direct", "port": "22", "protocol": ["bittorrent"]},
                        {"type": "field", "outboundTag": "proxy", "network": "tcp"},
                    ]
                },
            },
            _profile("ещё раз", _vless(address="203.0.113.2", stream=stream)),
        ]
        policy = render.extract_policy(profiles)
        self.assertIn("DOMAIN-SUFFIX,vk.ru,DIRECT", policy["domain_rules"])
        self.assertIn("DOMAIN,kion.ru,DIRECT", policy["domain_rules"])
        self.assertIn("GEOSITE,private,DIRECT", policy["domain_rules"])
        self.assertNotIn("DOMAIN-REGEX,a,b,DIRECT", policy["domain_rules"])
        self.assertEqual(policy["cidr_rules"], ["IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"])
        self.assertEqual(policy["port_rules"], ["DST-PORT,22,DIRECT", "DST-PORT,6881-6999,DIRECT"])

        by_mode = render.extract_proxies(profiles, prefix="myvpn")
        body = render.render_router(by_mode, policy)
        loaded = render.yaml.safe_load(body)
        self.assertEqual(loaded["mode"], "rule")
        self.assertTrue(loaded["allow-lan"])
        self.assertEqual(loaded["proxies"][0]["name"], "myvpn-main-01")
        self.assertEqual(loaded["proxy-groups"][0]["name"], "VPN")
        self.assertEqual(loaded["proxy-groups"][0]["proxies"], ["AUTO", "DIRECT"])
        self.assertIn("DOMAIN-SUFFIX,vk.ru,DIRECT", loaded["rules"])
        self.assertEqual(loaded["rules"][-1], "MATCH,VPN")

        overridden = render.yaml.safe_load(render.render_router(by_mode, policy, {"rules": ["MATCH,DIRECT"]}))
        self.assertEqual(overridden["rules"], ["MATCH,DIRECT"])

    def test_duplicate_endpoints_across_profiles_collapse(self):
        same = _vless(address="203.0.113.2", stream=_reality_stream())
        other = _vless(address="203.0.113.9", stream=_reality_stream(shortId="ffff"))
        profiles = [
            _profile("Автоматический", same, _vless(address="203.0.113.2", stream=_reality_stream())),
            _profile("Обход LTE", same),
            _profile("Для WiFi", same, other),
        ]
        proxies = render.extract_proxies(profiles, dialect="generic", prefix="happ")["main"]
        self.assertEqual([p["name"] for p in proxies], ["happ-main-01", "happ-main-02"])
        self.assertEqual([p["server"] for p in proxies], ["203.0.113.2", "203.0.113.9"])

    def test_two_outbounds_in_one_profile_are_numbered_without_gaps(self):
        first = _vless(address="203.0.113.1", stream=_reality_stream())
        second = _vless(address="203.0.113.2", stream=_reality_stream())
        profiles = [_profile("n", first, {"tag": "block", "protocol": "blackhole"}, second)]
        names = _names(render.extract_proxies(profiles, prefix="myvpn"))["main"]
        self.assertEqual(names, ["myvpn-main-01", "myvpn-main-02"])

    def test_dialects_bucket_by_remarks(self):
        profiles = [
            _profile("Основной режим 1", _vless(address="203.0.113.1", stream=_reality_stream())),
            _profile("Запасной 2", _vless(address="203.0.113.2", stream=_reality_stream())),
            _profile("Антизаглушка 3", _vless(address="203.0.113.3", stream=_reality_stream())),
            _profile("что-то ещё", _vless(address="203.0.113.4", stream=_reality_stream())),
        ]
        names = _names(render.extract_proxies(profiles, dialect="govpn", prefix="govpn"))
        self.assertEqual(names, {
            "main": ["govpn-main-01"],
            "antiblock": ["govpn-antiblock-01"],
            "backup": ["govpn-backup-01"],
        })

        buzz = [
            _profile("NL Автовыбор", _vless(stream=_reality_stream())),
            _profile("Обход белых списков FI", _vless(address="203.0.113.8", stream=_reality_stream())),
            _profile("Finland", _vless(address="203.0.113.9", stream=_reality_stream())),
        ]
        names = _names(render.extract_proxies(buzz, dialect="buzzvpn", prefix="buzz"))
        self.assertEqual(names["main"], ["buzz-main-01"])
        self.assertEqual(names["antiblock"], ["buzz-antiblock-01"])
        self.assertEqual(names["backup"], [])

    def test_single_object_and_reject_garbage(self):
        one = _profile("n", _vless(stream=_reality_stream()))
        self.assertEqual(len(render.extract_proxies(one, prefix="myvpn")["main"]), 1)
        with self.assertRaises(ValueError):
            render.extract_proxies("vless://not-json", prefix="myvpn")

    def test_yaml_provider_roundtrip_orders_buckets(self):
        profiles = [
            _profile("Основной режим", _vless(address="203.0.113.1", stream=_reality_stream())),
            _profile("Антизаглушка", _vless(address="203.0.113.2", stream=_reality_stream())),
            _profile("Запасной", _vless(address="203.0.113.3", stream=_reality_stream())),
        ]
        body = render.render_provider_from(render.extract_proxies(profiles, dialect="govpn", prefix="govpn"))
        self.assertTrue(body.startswith("proxies:\n"))
        loaded = render.yaml.safe_load(body)["proxies"]
        self.assertEqual([item["name"] for item in loaded], [
            "govpn-main-01", "govpn-antiblock-01", "govpn-backup-01",
        ])
        self.assertNotIn("Основной", body)

    def test_ten_nodes_are_not_zero_padded_past_two_digits(self):
        profiles = [
            _profile(str(i), _vless(address=f"203.0.113.{i}", stream=_reality_stream()))
            for i in range(1, 11)
        ]
        names = _names(render.extract_proxies(profiles, prefix="myvpn"))["main"]
        self.assertEqual(names[0], "myvpn-main-01")
        self.assertEqual(names[-1], "myvpn-main-10")


class ConfigTests(unittest.TestCase):
    def test_example_config_loads(self):
        cfg = render.load_config(ROOT / "config.example.yaml")
        self.assertEqual(cfg["listen"], "127.0.0.1:8080")
        self.assertIn("myvpn", cfg["sources"])
        self.assertEqual(cfg["sources"]["myvpn"]["dialect"], "generic")

    def test_rejects_bad_names_ports_and_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"

            def dump(sources, listen="127.0.0.1:8080"):
                path.write_text(render.yaml.safe_dump({
                    "listen": listen,
                    "state_dir": tmp,
                    "sources": sources,
                }), encoding="utf-8")

            dump({"../x": {"url": "https://example.com/sub"}})
            with self.assertRaises(ValueError):
                render.load_config(path)
            dump({"ok": {"url": "file:///etc/passwd"}})
            with self.assertRaises(ValueError):
                render.load_config(path)
            dump({"ok": {"url": "https://example.com/sub"}}, listen="8080")
            with self.assertRaises(ValueError):
                render.load_config(path)
            dump({"ok": {"url": "https://example.com/sub", "headers": {"x-hwid": "bad\nid"}}})
            with self.assertRaises(ValueError):
                render.load_config(path)

    def test_templates_mention_the_deploy_contract(self):
        caddy = (ROOT / "Caddyfile.example").read_text(encoding="utf-8")
        self.assertIn("basic_auth", caddy)
        self.assertIn("/myvpn.router.yaml", caddy)
        self.assertIn("127.0.0.1:8080", caddy)
        self.assertIn("__PASSWORD_HASH__", caddy)
        unit = (ROOT / "systemd" / "vpn-hub.service").read_text(encoding="utf-8")
        self.assertIn("User=vpn-hub", unit)
        self.assertIn("/opt/vpn-hub/render.py", unit)
        self.assertNotIn("\r", unit)


class CacheTests(unittest.TestCase):
    def test_roundtrip_and_reject_escaping_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp)
            by_mode = {"main": [{"name": "myvpn-main-01"}], "antiblock": [], "backup": []}
            render.save_cache(state_dir, "myvpn", by_mode, "upload=1; download=2")
            state = render.State()
            render.load_cache(state_dir, state, {"myvpn": {}})
            self.assertEqual(state.proxies["myvpn"]["main"][0]["name"], "myvpn-main-01")
            self.assertEqual(state.userinfo["myvpn"], "upload=1; download=2")
            with self.assertRaises(ValueError):
                render.save_cache(state_dir, "../x", by_mode, None)


class HeaderTests(unittest.TestCase):
    def test_sanitize_strips_crlf_and_non_ascii(self):
        self.assertEqual(render.sanitize_header_value("upload=1\r\nX-Evil: 1"), "upload=1X-Evil: 1")
        self.assertIsNone(render.sanitize_header_value("\r\n"))
        self.assertEqual(render.sanitize_header_value("ok"), "ok")


class HttpTests(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def _serve_upstream(self, handler):
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return httpd

    def test_live_pull_failover_and_userinfo(self):
        payload = json.dumps([
            _profile("n", _vless(stream=_reality_stream())),
        ]).encode()

        class Upstream(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.seen.append((self.headers.get("User-Agent"), self.headers.get("x-hwid")))
                if self.server.fail:
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("subscription-userinfo", "upload=1\r\nX-Injected: yes")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt, *args):
                return

        upstream = self._serve_upstream(Upstream)
        upstream.seen = []
        upstream.fail = False
        host, port = upstream.server_address
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "listen": "127.0.0.1:9",
                "state_dir": tmp,
                "sources": {
                    "myvpn": {
                        "url": f"http://{host}:{port}/sub",
                        "user_agent": "V2Box",
                        "headers": {"x-hwid": "fixed"},
                        "dialect": "generic",
                    }
                },
            }
            state = render.State()
            httpd = render.ThreadingHTTPServer(("127.0.0.1", 0), render.make_handler(cfg, state))
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(httpd.server_close)
            self.addCleanup(httpd.shutdown)
            base = f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"

            health = urllib.request.urlopen(base + "/healthz", timeout=5)
            self.assertIn("ok=False", health.read().decode())

            resp = urllib.request.urlopen(base + "/myvpn.yaml?clash=1", timeout=5)
            body = resp.read().decode()
            # urllib already splits a smuggled CRLF, so only the first line arrives.
            # Poison the cached value and force a failover to prove the hub still
            # refuses to write a second header.
            self.assertEqual(resp.headers.get("subscription-userinfo"), "upload=1")
            self.assertIsNone(resp.headers.get("X-Injected"))
            self.assertEqual(resp.headers.get("profile-update-interval"), "1")
            self.assertEqual(render.yaml.safe_load(body)["proxies"][0]["name"], "myvpn-main-01")
            router = render.yaml.safe_load(
                urllib.request.urlopen(base + "/myvpn.router.yaml", timeout=5).read().decode()
            )
            self.assertEqual(router["mode"], "rule")
            self.assertEqual(router["rules"][-1], "MATCH,VPN")
            self.assertEqual(router["proxies"][0]["server"], "203.0.113.10")
            self.assertEqual(upstream.seen[-1], ("V2Box", "fixed"))
            state.userinfo["myvpn"] = "upload=9\r\nX-Injected: yes"

            health = urllib.request.urlopen(base + "/healthz", timeout=5)
            self.assertIn("ok=True", health.read().decode())

            upstream.fail = True
            stale = urllib.request.urlopen(base + "/myvpn.yaml", timeout=5)
            self.assertEqual(render.yaml.safe_load(stale.read().decode())["proxies"][0]["server"], "203.0.113.10")
            self.assertEqual(stale.headers.get("subscription-userinfo"), "upload=9X-Injected: yes")
            self.assertIsNone(stale.headers.get("X-Injected"))

            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(base + "/nope.yaml", timeout=5)
            self.assertEqual(missing.exception.code, 404)

    def test_503_without_cache_and_body_limit(self):
        import socket

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "listen": "127.0.0.1:9",
                "state_dir": tmp,
                "sources": {
                    "myvpn": {
                        "url": f"http://127.0.0.1:{closed_port}/sub",
                        "dialect": "generic",
                        "timeout": 2,
                    }
                },
            }
            sock_httpd = render.ThreadingHTTPServer(("127.0.0.1", 0), render.make_handler(cfg, render.State()))
            thread = threading.Thread(target=sock_httpd.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(sock_httpd.server_close)
            self.addCleanup(sock_httpd.shutdown)
            base = f"http://{sock_httpd.server_address[0]}:{sock_httpd.server_address[1]}"
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(base + "/myvpn.yaml", timeout=5)
            self.assertEqual(caught.exception.code, 503)
            self.assertEqual(caught.exception.headers.get("Retry-After"), "30")

        class Big(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"0123456789"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        big = self._serve_upstream(Big)
        host, port = big.server_address
        with self.assertRaises(ValueError):
            render.fetch_source({"url": f"http://{host}:{port}/x"}, max_bytes=4)

    def test_refuses_non_http_redirect_and_follows_http(self):
        class Redirects(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/file":
                    self.send_response(302)
                    self.send_header("Location", "file:///etc/passwd")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/hop":
                    self.send_response(302)
                    host, port = self.server.server_address
                    self.send_header("Location", f"http://{host}:{port}/ok")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b"[]"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        httpd = self._serve_upstream(Redirects)
        host, port = httpd.server_address
        with self.assertRaises(urllib.error.URLError):
            render.fetch_source({"url": f"http://{host}:{port}/file"})
        data, _userinfo = render.fetch_source({"url": f"http://{host}:{port}/hop"})
        self.assertEqual(data, [])

    def test_dialect_defaults_to_source_name(self):
        payload = json.dumps([
            _profile("Антизаглушка", _vless(stream=_reality_stream())),
        ]).encode()

        class Upstream(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt, *args):
                return

        upstream = self._serve_upstream(Upstream)
        host, port = upstream.server_address
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "state_dir": tmp,
                "sources": {"govpn": {"url": f"http://{host}:{port}/sub"}},
            }
            state = render.State()
            self.assertTrue(render.refresh_once(cfg, state, "govpn"))
            self.assertEqual(state.proxies["govpn"]["antiblock"][0]["name"], "govpn-antiblock-01")
            self.assertEqual(state.proxies["govpn"]["main"], [])

    def test_serve_warms_before_accepting(self):
        payload = json.dumps([_profile("n", _vless(stream=_reality_stream()))]).encode()

        class Upstream(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("subscription-userinfo", "total=1")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt, *args):
                return

        upstream = self._serve_upstream(Upstream)
        host, port = upstream.server_address
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "listen": "127.0.0.1:0",
                "state_dir": tmp,
                "sources": {"myvpn": {"url": f"http://{host}:{port}/sub", "dialect": "generic"}},
            }

            def ready(httpd):
                base = f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"
                health = urllib.request.urlopen(base + "/healthz", timeout=5).read().decode()
                self.assertEqual(health, "ok=True\nmyvpn=True\n")

            render.serve(cfg, render.State(), ready=ready)


if __name__ == "__main__":
    unittest.main()
