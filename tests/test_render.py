"""Converter, cache, and HTTP behaviour of vpn-hub."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import render  # noqa: E402


UUID = "11111111-1111-1111-1111-111111111111"
SECRET_URL = "https://example.invalid/sub?token=SECRET"


def profile(
    remarks,
    *,
    network="tcp",
    security="reality",
    flow="xtls-rprx-vision",
    fingerprint="chrome",
    public_key="pub-key",
    short_id="ab",
    servername="www.microsoft.com",
    port=443,
    address="203.0.113.10",
    uuid=UUID,
    xhttp=None,
    alpn=None,
    protocol="vless",
    server_names=None,
):
    stream = {"network": network, "security": security}

    def _sec() -> dict:
        settings: dict = {}
        if servername is not None:
            settings["serverName"] = servername
        if server_names is not None:
            settings["serverNames"] = server_names
        if fingerprint is not None:
            settings["fingerprint"] = fingerprint
        if alpn is not None:
            settings["alpn"] = alpn
        return settings

    if security == "reality":
        reality = _sec()
        reality["publicKey"] = public_key
        if short_id is not None:
            reality["shortId"] = short_id
        stream["realitySettings"] = reality
    elif security == "tls":
        stream["tlsSettings"] = _sec()
    if xhttp is not None:
        stream["xhttpSettings"] = xhttp
    user = {"id": uuid, "encryption": "none"}
    if flow:
        user["flow"] = flow
    return {
        "remarks": remarks,
        "outbounds": [
            {
                "protocol": protocol,
                "tag": "proxy",
                "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
                "streamSettings": stream,
            },
            {"protocol": "freedom", "tag": "direct", "settings": {}},
            {"protocol": "blackhole", "tag": "block", "settings": {}},
        ],
    }


def cfg_for(tmp, **source):
    base = {"url": SECRET_URL, "dialect": "generic", "user_agent": "V2Box"}
    base.update(source)
    return {
        "listen": "127.0.0.1:8080",
        "state_dir": str(tmp),
        "sources": {"myvpn": base},
    }


class ConvertTests(unittest.TestCase):
    def test_reality_tcp_uses_upstream_fingerprint_for_generic(self):
        proxies = render.extract_proxies([profile("NL")], dialect="generic", prefix="myvpn")
        self.assertEqual([p["name"] for p in proxies["main"]], ["myvpn-main-01"])
        self.assertEqual(proxies["antiblock"], [])
        self.assertEqual(proxies["backup"], [])
        node = proxies["main"][0]
        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["server"], "203.0.113.10")
        self.assertEqual(node["port"], 443)
        self.assertEqual(node["uuid"], UUID)
        self.assertEqual(node["network"], "tcp")
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["servername"], "www.microsoft.com")
        self.assertEqual(node["client-fingerprint"], "chrome")
        self.assertEqual(node["reality-opts"], {"public-key": "pub-key", "short-id": "ab"})
        self.assertTrue(node["udp"])
        self.assertTrue(node["tls"])
        self.assertNotIn("alpn", node)
        self.assertNotIn("NL", node["name"])

    def test_govpn_forces_random_fingerprint_and_buckets(self):
        payload = [
            profile("Основной режим 1"),
            profile("Антизаглушка Франкфурт", address="203.0.113.11"),
            profile("Запасной 3", address="203.0.113.12"),
            profile("Балансировщик"),
        ]
        proxies = render.extract_proxies(payload, dialect="govpn", prefix="govpn")
        self.assertEqual([p["name"] for p in proxies["main"]], ["govpn-main-01"])
        self.assertEqual([p["name"] for p in proxies["antiblock"]], ["govpn-antiblock-01"])
        self.assertEqual([p["name"] for p in proxies["backup"]], ["govpn-backup-01"])
        self.assertEqual(proxies["main"][0]["client-fingerprint"], "random")
        self.assertEqual(proxies["antiblock"][0]["server"], "203.0.113.11")

    def test_buzzvpn_skips_autoselect_and_marks_antiblock(self):
        payload = [
            profile("Нидерланды"),
            profile("Обход белых списков 1", address="203.0.113.20"),
            profile("Автовыбор лучших"),
            profile("Автовыбор Обход белых списков"),
        ]
        proxies = render.extract_proxies(payload, dialect="buzzvpn", prefix="buzz")
        self.assertEqual([p["name"] for p in proxies["main"]], ["buzz-main-01"])
        self.assertEqual([p["name"] for p in proxies["antiblock"]], ["buzz-antiblock-01"])
        self.assertEqual(proxies["backup"], [])
        self.assertEqual(proxies["antiblock"][0]["client-fingerprint"], "chrome")

    def test_numbering_follows_kept_nodes_only(self):
        bad = profile("skip-me", protocol="vmess")
        second = profile("second", address="203.0.113.30")
        proxies = render.extract_proxies([bad, profile("first"), second], prefix="myvpn")
        self.assertEqual(
            [p["name"] for p in proxies["main"]],
            ["myvpn-main-01", "myvpn-main-02"],
        )
        self.assertEqual(proxies["main"][1]["server"], "203.0.113.30")

    def test_two_vless_outbounds_in_one_profile_get_sequential_names(self):
        item = profile("dual")
        extra = profile("ignored", address="203.0.113.40")["outbounds"][0]
        item["outbounds"].insert(0, extra)
        proxies = render.extract_proxies([item], prefix="myvpn")
        self.assertEqual(
            [(p["name"], p["server"]) for p in proxies["main"]],
            [("myvpn-main-01", "203.0.113.40"), ("myvpn-main-02", "203.0.113.10")],
        )

    def test_raw_becomes_tcp_and_string_port(self):
        item = profile("raw", network="raw", port="8443")
        node = render.extract_proxies([item], prefix="myvpn")["main"][0]
        self.assertEqual(node["network"], "tcp")
        self.assertEqual(node["port"], 8443)
        self.assertEqual(node["flow"], "xtls-rprx-vision")

    def test_xhttp_maps_extra_and_xmux(self):
        item = profile(
            "xh",
            network="xhttp",
            flow="xtls-rprx-vision",
            xhttp={
                "path": "/xh",
                "host": "cdn.example",
                "mode": "packet-up",
                "headers": {"Host": ["cdn.example"]},
                "extra": {
                    "xPaddingBytes": "100-1000",
                    "scMaxEachPostBytes": 1000000,
                    "noGRPCHeader": False,
                    "xmux": {"maxConcurrency": "16-32", "hKeepAlivePeriod": 5},
                },
            },
        )
        node = render.extract_proxies([item], prefix="myvpn")["main"][0]
        self.assertEqual(node["network"], "xhttp")
        self.assertNotIn("flow", node)
        self.assertEqual(node["alpn"], ["h2"])
        self.assertEqual(
            node["xhttp-opts"],
            {
                "path": "/xh",
                "mode": "packet-up",
                "host": "cdn.example",
                "x-padding-bytes": "100-1000",
                "sc-max-each-post-bytes": 1000000,
                "no-grpc-header": False,
                "headers": {"Host": "cdn.example"},
                "reuse-settings": {"max-concurrency": "16-32", "h-keep-alive-period": 5},
            },
        )

    def test_splithttp_and_server_names_and_tls(self):
        item = profile(
            "old",
            network="splithttp",
            security="tls",
            fingerprint=None,
            alpn=["h2", "http/1.1"],
            servername=None,
            server_names=["a.example", "b.example"],
        )
        item["outbounds"][0]["streamSettings"]["splithttpSettings"] = {"path": "/s", "mode": "stream-up"}
        node = render.convert_outbound(item["outbounds"][0], "n", "upstream")
        self.assertEqual(node["network"], "xhttp")
        self.assertEqual(node["servername"], "a.example")
        self.assertEqual(node["alpn"], ["h2", "http/1.1"])
        self.assertNotIn("reality-opts", node)
        self.assertEqual(node["client-fingerprint"], "random")
        self.assertEqual(node["xhttp-opts"]["path"], "/s")
        self.assertEqual(node["xhttp-opts"]["mode"], "stream-up")

    def test_skips_incomplete_without_raising(self):
        broken = profile("broken", public_key="")
        ws = profile("ws", network="ws")
        none_sec = profile("open", security="none")
        proxies = render.extract_proxies(
            [broken, ws, none_sec, profile("ok")],
            prefix="myvpn",
        )
        self.assertEqual([p["name"] for p in proxies["main"]], ["myvpn-main-01"])

    def test_single_profile_object_and_short_ids_list(self):
        item = profile("one", short_id=None)
        item["outbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] = ["abcd", ""]
        proxies = render.extract_proxies(item, prefix="myvpn")
        self.assertEqual(proxies["main"][0]["reality-opts"]["short-id"], "abcd")

    def test_render_order_and_round_trip(self):
        payload = [
            profile("Основной режим"),
            profile("Антизаглушка", address="203.0.113.11"),
            profile("Запасной", address="203.0.113.12"),
        ]
        state = render.State()
        state.proxies["govpn"] = render.extract_proxies(payload, dialect="govpn", prefix="govpn")
        state.userinfo["govpn"] = "upload=1; download=2; total=3; expire=9"
        text, userinfo = render.render_provider(state, "govpn")
        loaded = render.yaml.safe_load(text)
        names = [item["name"] for item in loaded["proxies"]]
        self.assertEqual(names, ["govpn-main-01", "govpn-antiblock-01", "govpn-backup-01"])
        self.assertNotIn("Антизаглушка", text)
        self.assertEqual(userinfo, state.userinfo["govpn"])
        self.assertIn("udp: true", text)

    def test_clo_splits_lte_and_drops_duplicate_profiles(self):
        auto = profile("🇳🇱 Автоматический 👻", address="203.0.113.1", port=4443, fingerprint="qq", flow=None)
        second = profile("ignored", address="203.0.113.2", port=5269, fingerprint="qq", flow=None)["outbounds"][0]
        auto["outbounds"].insert(1, second)
        lte_a = profile("🇳🇱Обход LTE 🎻", address="203.0.113.1", port=4443, fingerprint="qq", flow=None)
        lte_a["outbounds"].insert(1, second)
        lte_b = profile("🇳🇱Обход LTE 🥁", address="203.0.113.1", port=4443, fingerprint="qq", flow=None)
        lte_b["outbounds"].insert(1, json.loads(json.dumps(second)))
        wifi = profile("🇳🇱Для WiFi, ПК и ТВ 💻", address="203.0.113.1", port=4443, fingerprint="qq", flow=None)
        proxies = render.extract_proxies([auto, lte_a, lte_b, wifi], dialect="clo", prefix="clo")
        self.assertEqual(proxies["backup"], [])
        self.assertEqual(
            [(p["name"], p["server"], p["port"]) for p in proxies["antiblock"]],
            [("clo-antiblock-01", "203.0.113.1", 4443), ("clo-antiblock-02", "203.0.113.2", 5269)],
        )
        self.assertEqual([p["name"] for p in proxies["main"]], ["clo-main-01"])
        self.assertEqual(proxies["antiblock"][0]["client-fingerprint"], "qq")
        self.assertNotIn("flow", proxies["main"][0])

    def test_duplicate_outbound_inside_one_profile_is_collapsed(self):
        item = profile("dup", address="203.0.113.5")
        item["outbounds"].insert(0, json.loads(json.dumps(item["outbounds"][0])))
        proxies = render.extract_proxies([item], prefix="myvpn")
        self.assertEqual([p["name"] for p in proxies["main"]], ["myvpn-main-01"])

    def test_unsupported_shape(self):
        with self.assertRaises(ValueError):
            render.normalize_profiles({"status": "ok"})


class CacheAndRefreshTests(unittest.TestCase):
    def test_empty_or_bad_pull_keeps_cache_and_redacts_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = cfg_for(tmp)
            state = render.State()
            kept = {"main": [{"name": "keep"}], "antiblock": [], "backup": []}
            state.proxies["myvpn"] = kept
            render.save_cache(Path(tmp), "myvpn", kept, "upload=1")
            before = (Path(tmp) / "myvpn.proxies.json").read_text()

            with patch.object(render, "fetch_source", return_value=([], None)):
                with self.assertLogs("vpn-hub", level="WARNING") as logs:
                    self.assertFalse(render.refresh_once(config, state, "myvpn"))
            self.assertEqual(state.proxies["myvpn"], kept)
            self.assertTrue(state.serving_stale["myvpn"])
            self.assertEqual((Path(tmp) / "myvpn.proxies.json").read_text(), before)
            self.assertTrue(any("no convertible" in line for line in logs.output))

            with patch.object(
                render,
                "fetch_source",
                side_effect=RuntimeError(f"failed {SECRET_URL}"),
            ):
                with self.assertLogs("vpn-hub", level="WARNING") as logs:
                    self.assertFalse(render.refresh_once(config, state, "myvpn"))
            self.assertFalse(any("SECRET" in line for line in logs.output))
            self.assertTrue(any("<url>" in line for line in logs.output))
            self.assertEqual((Path(tmp) / "myvpn.proxies.json").read_text(), before)

    def test_success_writes_private_cache_and_unknown_dialect_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = cfg_for(tmp, dialect="no-such")
            state = render.State()
            with patch.object(render, "fetch_source", return_value=([profile("NL")], "upload=1\r\nX-Evil: 1")):
                with self.assertLogs("vpn-hub", level="WARNING") as logs:
                    self.assertTrue(render.refresh_once(config, state, "myvpn"))
            self.assertIn("unknown dialect", "\n".join(logs.output))
            self.assertEqual(state.proxies["myvpn"]["main"][0]["name"], "myvpn-main-01")
            self.assertEqual(state.userinfo["myvpn"], "upload=1 X-Evil: 1")
            self.assertFalse(state.serving_stale["myvpn"])
            cache = Path(tmp) / "myvpn.proxies.json"
            info = Path(tmp) / "myvpn.userinfo"
            self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(info.stat().st_mode), 0o600)
            loaded = json.loads(cache.read_text())
            self.assertEqual(loaded["main"][0]["server"], "203.0.113.10")

            fresh = render.State()
            render.load_cache(Path(tmp), fresh, config["sources"])
            self.assertEqual(fresh.proxies["myvpn"]["main"][0]["name"], "myvpn-main-01")
            self.assertEqual(fresh.userinfo["myvpn"], "upload=1 X-Evil: 1")

    def test_fetch_sanitizes_userinfo_and_rejects_huge_body(self):
        class FakeResp:
            def __init__(self, body, headers):
                self._body = body
                self.headers = headers

            def read(self, n=-1):
                return self._body if n is None or n < 0 else self._body[:n]

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        headers = {"subscription-userinfo": "upload=1\r\nX-Injected: yes"}
        body = json.dumps([profile("NL")]).encode()
        with patch("urllib.request.urlopen", return_value=FakeResp(body, headers)):
            payload, userinfo = render.fetch_source({"url": SECRET_URL, "user_agent": "V2Box"})
        self.assertIsInstance(payload, list)
        self.assertNotIn("\n", userinfo)
        self.assertNotIn("\r", userinfo)
        self.assertEqual(userinfo, "upload=1 X-Injected: yes")

        huge = b"{" + b"a" * (render.MAX_BODY + 5)
        with patch("urllib.request.urlopen", return_value=FakeResp(huge, {})):
            with self.assertRaises(ValueError):
                render.fetch_source({"url": SECRET_URL})

    def test_validate_config_and_listen_and_config_path(self):
        render.validate_config(
            {
                "listen": "[::1]:8080",
                "state_dir": "/var/lib/vpn-hub",
                "sources": {"myvpn": {"url": SECRET_URL}},
            }
        )
        self.assertEqual(render.parse_listen("[::1]:8080"), ("::1", 8080))
        self.assertEqual(render.parse_listen("127.0.0.1:8080"), ("127.0.0.1", 8080))
        with self.assertRaises(SystemExit):
            render.validate_config(
                {
                    "listen": "127.0.0.1:8080",
                    "state_dir": "/var/lib/vpn-hub",
                    "sources": {"../x": {"url": SECRET_URL}},
                }
            )
        with self.assertRaises(SystemExit):
            render.validate_config({"listen": "127.0.0.1:8080", "state_dir": "/tmp", "sources": {}})
        with patch.object(sys, "argv", ["render.py", "/tmp/x.yaml"]):
            self.assertEqual(render.config_path(), Path("/tmp/x.yaml"))
        with patch.object(sys, "argv", ["render.py"]), patch.dict(os.environ, {"VPN_HUB_CONFIG": "/tmp/env.yaml"}):
            self.assertEqual(render.config_path(), Path("/tmp/env.yaml"))
        with patch.object(sys, "argv", ["render.py"]), patch.dict(os.environ, {}, clear=True):
            self.assertEqual(render.config_path(), render.CONFIG_PATH)


class HttpTests(unittest.TestCase):
    def test_live_pull_failover_and_health(self):
        calls = {"mode": "fail"}

        def fake_fetch(src, timeout=15):
            if calls["mode"] == "fail":
                raise TimeoutError("upstream timeout")
            if calls["mode"] == "empty":
                return [], "upload=9"
            if calls["mode"] == "bad-shape":
                return {"status": "ok"}, None
            return [profile("NL")], "upload=1; download=2; total=3; expire=999"

        with tempfile.TemporaryDirectory() as tmp:
            config = cfg_for(tmp)
            state = render.State()
            httpd = render.ThreadingHTTPServer(("127.0.0.1", 0), render.make_handler(config, state))
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(httpd.server_close)
            try:
                with patch.object(render, "fetch_source", side_effect=fake_fetch):
                    status, headers, body = self.request(port, "/myvpn.yaml")
                    self.assertEqual(status, 503)
                    self.assertEqual(headers["Retry-After"], "30")
                    health_status, _, health = self.request(port, "/healthz")
                    self.assertEqual(health_status, 200)
                    self.assertIn("ok=False", health)
                    self.assertIn("myvpn=False", health)

                    calls["mode"] = "ok"
                    status, headers, body = self.request(port, "/myvpn.yaml")
                    self.assertEqual(status, 200)
                    self.assertIn("text/yaml", headers["Content-Type"])
                    self.assertEqual(headers["subscription-userinfo"], "upload=1; download=2; total=3; expire=999")
                    self.assertEqual(headers["profile-update-interval"], "1")
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertNotIn("Python", headers.get("Server", ""))
                    self.assertNotIn("SECRET", body)
                    loaded = render.yaml.safe_load(body)
                    self.assertEqual(loaded["proxies"][0]["name"], "myvpn-main-01")

                    _, _, health = self.request(port, "/healthz")
                    self.assertRegex(health, r"ok=True\nmyvpn=True nodes=1 age=\d+s\n")

                    calls["mode"] = "fail"
                    status, headers, body = self.request(port, "/myvpn.yaml")
                    self.assertEqual(status, 200)
                    self.assertEqual(render.yaml.safe_load(body)["proxies"][0]["name"], "myvpn-main-01")
                    self.assertEqual(headers["subscription-userinfo"], "upload=1; download=2; total=3; expire=999")
                    _, _, health = self.request(port, "/healthz")
                    self.assertIn("stale=1", health)

                    calls["mode"] = "empty"
                    status, _, body = self.request(port, "/myvpn.yaml")
                    self.assertEqual(status, 200)
                    self.assertEqual(render.yaml.safe_load(body)["proxies"][0]["uuid"], UUID)

                    calls["mode"] = "bad-shape"
                    status, _, body = self.request(port, "/myvpn.yaml")
                    self.assertEqual(status, 200)
                    self.assertEqual(render.yaml.safe_load(body)["proxies"][0]["name"], "myvpn-main-01")

                    status, _, body = self.request(port, "/nope.yaml")
                    self.assertEqual(status, 404)
                    self.assertEqual(body, "")
                    status, _, _ = self.request(port, "/../x.yaml")
                    self.assertEqual(status, 404)
            finally:
                httpd.shutdown()

    def request(self, port, path):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read().decode()


if __name__ == "__main__":
    unittest.main()
