from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.detectors import detect, new_source_ip, rate_spikes
from app.main import app

T0 = datetime(2024, 6, 1, 8, 0, tzinfo=timezone.utc)
_n = 0


def ev(minutes, type_="login_failed", user="lab.alice", ip="203.0.113.5"):
    global _n
    _n += 1
    return {"id": f"e{_n}", "timestamp": (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "type": type_, "user": user, "ip": ip}


def test_quiet_user_with_burst_is_flagged():
    events = [ev(m * 60) for m in range(0, 6)]                    # one failure per hour for 5 hours
    events += [ev(330 + i * 0.2) for i in range(6)]               # then 6 in a minute
    out = rate_spikes(events)
    assert len(out) == 1 and out[0]["subject"] == "user:lab.alice" and len(out[0]["eventIds"]) == 6


def test_steady_noisy_user_is_not_flagged():
    events = [ev(m * 5 + k * 0.1) for m in range(0, 40) for k in range(4)]   # 4 failures every bucket, always
    assert rate_spikes(events) == []


def test_small_blips_are_ignored():
    events = [ev(m * 60) for m in range(6)] + [ev(330), ev(330.1)]
    assert rate_spikes(events) == []


def test_new_ip_after_baseline():
    events = [ev(i, "login_success", ip="203.0.113.5") for i in range(6)] + [ev(100, "login_success", ip="198.51.100.9")]
    out = new_source_ip(events)
    assert len(out) == 1 and "198.51.100.9" in out[0]["explanation"]


def test_new_ip_needs_baseline_and_ignores_known_ips():
    assert new_source_ip([ev(1, "login_success"), ev(2, "login_success", ip="198.51.100.9")]) == []
    base = [ev(i, "login_success") for i in range(6)]
    assert new_source_ip(base + [ev(50, "login_success")]) == []


def test_deterministic_and_order_independent():
    events = [ev(m * 60) for m in range(6)] + [ev(330 + i * 0.2) for i in range(6)]
    assert detect(events) == detect(list(reversed(events)))


def test_http_contract_and_validation():
    c = TestClient(app)
    assert c.get("/health").json() == {"status": "ok"}
    events = [ev(m * 60) for m in range(6)] + [ev(330 + i * 0.2) for i in range(6)]
    r = c.post("/v1/anomalies", json={"events": events})
    assert r.status_code == 200 and r.json()["analyzed"] == 12 and r.json()["anomalies"][0]["kind"] == "rate_spike"
    assert c.post("/v1/anomalies", json={"events": [{"id": "x"}]}).status_code == 422
