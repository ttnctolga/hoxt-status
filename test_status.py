import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe  # noqa: E402
import render  # noqa: E402

T0 = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
CFG = {
    "components": [{"id": "api", "name": "API"}, {"id": "dns", "name": "DNS"}],
    "authoritative": ["ns1.test", "ns2.test"], "public_resolvers": ["8.8.8.8"],
    "checks": [
        {"id": "a1", "component": "api", "type": "http", "url": "https://x.test/up", "status": 200},
        {"id": "d1", "component": "dns", "type": "dns"},
    ],
}
RECORDS = [("my.test", "A", ["1.2.3.4"]), ("k.test", "TXT", ["sha256:" + hashlib.sha256(b"longvalue").hexdigest()])]


class FakeNet:
    def __init__(self, http=(200, "ok", 0.1), dns=None, cert=60.0):
        self._http, self._dns, self._cert = http, dns or {}, cert
        self.http_calls = []

    def http(self, url, timeout=15):
        self.http_calls.append(url)
        return self._http

    def cert_days(self, host, port=443, timeout=10):
        return self._cert

    def dig(self, server, name, rtype, timeout=5):
        return self._dns.get((server, name, rtype), self._dns.get((None, name, rtype), "UNSET")) if (server, name, rtype) in self._dns or (None, name, rtype) in self._dns else ["1.2.3.4"] if name == "my.test" else ["longvalue"]


class Matching(unittest.TestCase):
    def test_norm_handles_quotes_dots_case_and_split_txt(self):
        self.assertEqual(probe.norm('"v=DMARC1; p=none;"'), "v=dmarc1; p=none;")
        self.assertEqual(probe.norm("Send.Forge.RMTA.net."), "send.forge.rmta.net")
        self.assertEqual(probe.norm('"abc" "def"'), "abcdef")

    def test_matches_is_an_exact_unordered_set_comparison(self):
        self.assertTrue(probe.matches(["1.1.1.1", "2.2.2.2"], ["2.2.2.2", "1.1.1.1"]))
        self.assertFalse(probe.matches(["1.1.1.1"], ["1.1.1.1", "2.2.2.2"]))
        self.assertFalse(probe.matches(["1.1.1.1", "2.2.2.2"], ["1.1.1.1"]))
        self.assertFalse(probe.matches(["1.1.1.1"], ["9.9.9.9"]))
        self.assertFalse(probe.matches(["1.1.1.1"], None))

    def test_sha256_expectations_check_the_digest_of_the_normalised_value(self):
        good = "sha256:" + hashlib.sha256(b"longvalue").hexdigest()
        self.assertTrue(probe.matches([good], ["longvalue"]))
        self.assertFalse(probe.matches([good], ["longvalue2"]))
        self.assertFalse(probe.matches(["sha256:" + "0" * 64], ["longvalue"]))


class Checks(unittest.TestCase):
    def test_http_statuses(self):
        c = {"url": "u", "status": 200}
        self.assertEqual(probe.check_http(FakeNet(http=(200, "ok", 0.1)), c), (probe.OK, "ok"))
        self.assertEqual(probe.check_http(FakeNet(http=(502, "", 0.1)), c), (probe.OUTAGE, "http_502"))
        self.assertEqual(probe.check_http(FakeNet(http=(None, "", 15)), c), (probe.OUTAGE, "unreachable"))
        self.assertEqual(probe.check_http(FakeNet(http=(404, "", 0.1)), {"url": "u", "status": 404}), (probe.OK, "ok"))
        self.assertEqual(probe.check_http(FakeNet(http=(200, "nothing", 0.1)), {**c, "contains": "ok"}), (probe.DEGRADED, "unexpected_body"))
        self.assertEqual(probe.check_http(FakeNet(http=(200, "ok", 12)), c), (probe.DEGRADED, "slow"))

    def test_tls_thresholds(self):
        c = {"host": "h"}
        self.assertEqual(probe.check_tls(FakeNet(cert=60), c)[0], probe.OK)
        self.assertEqual(probe.check_tls(FakeNet(cert=10), c), (probe.DEGRADED, "cert_expires_10d"))
        self.assertEqual(probe.check_tls(FakeNet(cert=2), c)[0], probe.OUTAGE)
        self.assertEqual(probe.check_tls(FakeNet(cert=-1), c)[0], probe.OUTAGE)
        self.assertEqual(probe.check_tls(FakeNet(cert=None), c), (probe.OUTAGE, "tls_unreachable"))

    def test_dns_ok_partial_and_total_failure(self):
        net = FakeNet()
        self.assertEqual(probe.check_dns(net, {}, RECORDS, ["8.8.8.8"], ["ns1.test", "ns2.test"]), (probe.OK, "ok"))

        wrong = FakeNet(dns={("ns2.test", "my.test", "A"): ["6.6.6.6"], ("ns1.test", "my.test", "A"): ["1.2.3.4"], ("8.8.8.8", "my.test", "A"): ["1.2.3.4"]})
        st, detail = probe.check_dns(wrong, {}, RECORDS, ["8.8.8.8"], ["ns1.test", "ns2.test"])
        self.assertEqual(st, probe.DEGRADED)
        self.assertIn("my.test A@auth:ns2.test", detail)

        class Silent(FakeNet):
            def dig(self, *a, **k):
                return None

        self.assertEqual(probe.check_dns(Silent(), {}, RECORDS, ["8.8.8.8"], ["ns1.test"]), (probe.OUTAGE, "dns_no_answer"))

        class AllWrong(FakeNet):
            def dig(self, *a, **k):
                return ["9.9.9.9"]

        self.assertEqual(probe.check_dns(AllWrong(), {}, RECORDS, ["8.8.8.8"], ["ns1.test"])[0], probe.OUTAGE)


class Merge(unittest.TestCase):
    def tick(self, prev, status, detail="ok", t=T0):
        return probe.merge(prev, [{"component": "api", "check": "a1", "status": status, "detail": detail}], CFG, t)

    def test_first_run_has_no_transition(self):
        s, tr = self.tick(None, probe.OK)
        self.assertEqual((s["overall"], tr), (probe.OK, []))

    def test_a_component_that_starts_bad_is_announced_exactly_once(self):
        s, tr = self.tick(None, probe.OUTAGE, "http_502")
        self.assertEqual([(x["kind"], x["from"]) for x in tr], [("outage", "unknown")])
        s, tr = self.tick(s, probe.OUTAGE, "http_502", T0 + timedelta(minutes=5))
        self.assertEqual(tr, [], "ikinci turda yinelenmez (hatırlatma 6 saat sonra)")

    def test_one_bad_tick_changes_nothing_two_consecutive_bad_ticks_raise_an_outage(self):
        s, _ = self.tick(None, probe.OK)
        s, tr = self.tick(s, probe.OUTAGE, "http_502", T0 + timedelta(minutes=5))
        self.assertEqual((s["components"][0]["status"], tr), (probe.OK, []), "tek takılma alarm vermez")
        s, tr = self.tick(s, probe.OUTAGE, "http_502", T0 + timedelta(minutes=10))
        self.assertEqual(s["components"][0]["status"], probe.OUTAGE)
        self.assertEqual([(x["kind"], x["detail"]) for x in tr], [("outage", "http_502")])

    def test_a_blip_between_good_ticks_never_counts(self):
        s, _ = self.tick(None, probe.OK)
        s, _ = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(minutes=5))
        s, tr = self.tick(s, probe.OK, "ok", T0 + timedelta(minutes=10))
        s, tr2 = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(minutes=15))
        self.assertEqual((s["components"][0]["status"], tr, tr2), (probe.OK, [], []))

    def test_recovery_is_immediate_and_resets_the_streak(self):
        s, _ = self.tick(None, probe.OK)
        for m in (5, 10):
            s, _ = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(minutes=m))
        s, tr = self.tick(s, probe.OK, "ok", T0 + timedelta(minutes=15))
        self.assertEqual((s["components"][0]["status"], s["components"][0]["consecutive_bad"], [x["kind"] for x in tr]), (probe.OK, 0, ["recovered"]))

    def test_degraded_then_outage_are_separate_transitions(self):
        s, _ = self.tick(None, probe.OK)
        for m in (5, 10):
            s, tr = self.tick(s, probe.DEGRADED, "slow", T0 + timedelta(minutes=m))
        self.assertEqual([x["kind"] for x in tr], ["degraded"])
        s, tr = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(minutes=15))
        self.assertEqual([x["kind"] for x in tr], ["outage"])

    def test_reminders_only_every_six_hours_during_an_outage(self):
        s, _ = self.tick(None, probe.OK)
        for m in (5, 10):
            s, _ = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(minutes=m))
        s, tr = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(hours=3))
        self.assertEqual(tr, [])
        s, tr = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(hours=7))
        self.assertEqual([x["kind"] for x in tr], ["reminder"])
        s, tr = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(hours=8))
        self.assertEqual(tr, [])

    def test_since_moves_only_when_the_status_changes(self):
        s, _ = self.tick(None, probe.OK)
        first = s["components"][0]["since"]
        s, _ = self.tick(s, probe.OK, "ok", T0 + timedelta(minutes=5))
        self.assertEqual(s["components"][0]["since"], first)
        for m in (10, 15):
            s, _ = self.tick(s, probe.OUTAGE, "x", T0 + timedelta(minutes=m))
        self.assertEqual(s["components"][0]["since"], (T0 + timedelta(minutes=15)).isoformat())

    def test_overall_is_the_worst_component(self):
        res = [{"component": "api", "check": "a", "status": probe.OK, "detail": "ok"}, {"component": "dns", "check": "d", "status": probe.DEGRADED, "detail": "m"}]
        s, _ = probe.merge(None, res, CFG, T0)
        self.assertEqual(s["overall"], probe.DEGRADED)

    def test_the_worst_check_of_a_component_decides(self):
        res = [{"component": "api", "check": "a", "status": probe.OK, "detail": "ok"}, {"component": "api", "check": "b", "status": probe.OUTAGE, "detail": "bad"}]
        s, _ = probe.merge(None, res, CFG, T0)
        self.assertEqual((s["components"][0]["status"], s["components"][0]["detail"]), (probe.OUTAGE, "bad"))


class History(unittest.TestCase):
    def test_counts_prunes_and_computes_uptime(self):
        s, _ = probe.merge(None, [{"component": "api", "check": "a", "status": probe.OK, "detail": "ok"}], CFG, T0)
        h = probe.update_history({"api": {"2025-01-01": [10, 10]}}, s, T0)
        self.assertNotIn("2025-01-01", h["api"], "90 günden eski atılır")
        h = probe.update_history(h, s, T0)
        self.assertEqual(h["api"]["2026-10-15"], [2, 2])
        bad = {"components": [{"id": "api", "status": probe.OUTAGE}]}
        h = probe.update_history(h, bad, T0)
        self.assertEqual(probe.uptime(h, "api"), round(100 * 2 / 3, 3))
        self.assertIsNone(probe.uptime({}, "api"))


class Notify(unittest.TestCase):
    TR = [{"component": "api", "name": "API", "kind": "outage", "from": "operational", "to": "outage", "detail": "http_502"}]

    def test_without_a_topic_nothing_is_sent_and_nothing_is_printed_about_it(self):
        calls = []
        self.assertEqual(probe.notify(self.TR, "", lambda *a: calls.append(a)), 0)
        self.assertEqual(calls, [])

    def test_messages_carry_titles_priorities_and_never_the_topic_in_the_body(self):
        calls = []
        probe.notify(self.TR + [{**self.TR[0], "kind": "recovered", "to": "operational", "detail": "ok"}], "fake-topic-1", lambda url, msg, h: calls.append((url, msg, h)))
        self.assertEqual(calls[0][0], "https://ntfy.sh/fake-topic-1")
        self.assertEqual((calls[0][2]["Priority"], calls[1][2]["Priority"]), ("5", "3"))
        self.assertIn("API: outage (http_502)", calls[0][1])
        for _, msg, h in calls:
            self.assertNotIn("fake-topic-1", msg + json.dumps(h))

    def test_a_failing_endpoint_never_raises_and_never_leaks_the_topic(self):
        def boom(*a):
            raise OSError("https://ntfy.sh/fake-topic-1 unreachable")

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            n = probe.notify(self.TR, "fake-topic-1", boom)
        self.assertEqual(n, 0)
        self.assertNotIn("fake-topic-1", buf.getvalue())


class EndToEnd(unittest.TestCase):
    def test_main_writes_status_history_without_secrets_and_notifies_on_a_confirmed_outage(self):
        with tempfile.TemporaryDirectory() as d:
            cfg, rec, data = os.path.join(d, "c.json"), os.path.join(d, "r.tsv"), os.path.join(d, "data")
            json.dump(CFG, open(cfg, "w"))
            open(rec, "w").write("# yorum\nmy.test\tA\t1.2.3.4\nk.test\tTXT\tsha256:%s\n" % hashlib.sha256(b"longvalue").hexdigest())
            os.environ["NTFY_TOPIC"] = "fake-topic-1"
            sent = []
            orig = probe._post
            probe._post = lambda url, msg, h: sent.append((url, msg))
            try:
                self.assertEqual(probe.main(["--config", cfg, "--records", rec, "--data", data], net=FakeNet(), t=T0), 0)
                bad = FakeNet(http=(503, "", 0.1))
                probe.main(["--config", cfg, "--records", rec, "--data", data], net=bad, t=T0 + timedelta(minutes=5))
                self.assertEqual(sent, [], "ilk bozuk tur bildirim üretmez")
                probe.main(["--config", cfg, "--records", rec, "--data", data], net=bad, t=T0 + timedelta(minutes=10))
            finally:
                probe._post = orig
                del os.environ["NTFY_TOPIC"]
            self.assertEqual(len(sent), 1)
            self.assertIn("API: outage", sent[0][1])
            status = json.load(open(os.path.join(data, "status.json")))
            self.assertEqual(status["overall"], probe.OUTAGE)
            self.assertTrue(all("detail" not in c for c in status["components"]), "hata ayrıntısı herkese açık status.json'a yazılmaz")
            self.assertNotIn("fake-topic-1", open(os.path.join(data, "status.json")).read() + open(os.path.join(data, "history.json")).read())
            self.assertEqual(status["components"][0]["uptime_90d"], round(100 * 2 / 3, 3), "geçmiş DOĞRULANMIŞ durumu sayar (tek takılma erişilebilirliği düşürmez)")

    def test_load_records_groups_multiple_values_per_name_and_type(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.tsv")
            open(p, "w").write("# c\nhoxt.net\tNS\tns1\nhoxt.net\tNS\tns2\n\nmy.test\tA\t1.2.3.4\n")
            got = {(n, t): v for n, t, v in probe.load_records(p)}
            self.assertEqual(got[("hoxt.net", "NS")], ["ns1", "ns2"])
            self.assertEqual(got[("my.test", "A")], ["1.2.3.4"])


class Render(unittest.TestCase):
    def build(self, incidents):
        with tempfile.TemporaryDirectory() as d:
            data, out = os.path.join(d, "data"), os.path.join(d, "site")
            os.makedirs(data)
            s, _ = probe.merge(None, [{"component": "api", "check": "a", "status": probe.OUTAGE, "detail": "x"}, {"component": "dns", "check": "d", "status": probe.OK, "detail": "ok"}], CFG, T0)
            s["components"][0]["uptime_90d"] = 99.5
            json.dump(s, open(os.path.join(data, "status.json"), "w"))
            json.dump(incidents, open(os.path.join(data, "incidents.json"), "w"))
            render.main(["--data", data, "--out", out])
            return {p: open(os.path.join(out, p), encoding="utf-8").read() for p in ("index.html", "tr/index.html", "status.json")}

    def test_both_languages_banner_and_public_json(self):
        files = self.build([])
        self.assertIn("Service disruption", files["index.html"])
        self.assertIn("Hizmet kesintisi", files["tr/index.html"])
        self.assertIn('lang="tr"', files["tr/index.html"])
        self.assertIn("No incidents reported.", files["index.html"])
        self.assertIn("99.5%", files["index.html"])
        pub = json.loads(files["status.json"])
        self.assertEqual(set(pub["components"][0]), {"id", "name", "status", "since", "uptime_90d"})

    def test_the_operational_banner_is_translated(self):
        status = {"generated_at": T0.isoformat(), "overall": probe.OK, "components": []}
        self.assertIn("All systems operational", render.page("en", status, []))
        self.assertIn("Tüm sistemler çalışıyor", render.page("tr", status, []))
        self.assertIn("Bazı sistemlerde bozulma var", render.page("tr", {**status, "overall": probe.DEGRADED}, []))

    def test_incident_text_is_escaped_and_the_page_has_no_scripts_or_external_resources(self):
        files = self.build([{"started": T0.isoformat(), "resolved": False, "title": {"en": "<script>alert(1)</script>", "tr": "Başlık"}, "body": {"en": "<img src=x onerror=alert(1)> & more"}}])
        page = files["index.html"]
        self.assertNotIn("<script", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;", page)
        for bad in ("http://", "https://", 'src="', "@import", "<link", "<iframe", "<script"):
            self.assertNotIn(bad, page, "dış kaynak yok: " + bad)
        self.assertIn("Ongoing", page)
        self.assertIn("Başlık", files["tr/index.html"])
        self.assertIn("&lt;img", files["tr/index.html"], "TR'de çeviri yoksa İngilizce gövdeye düşer, yine kaçışlı")


if __name__ == "__main__":
    unittest.main()
