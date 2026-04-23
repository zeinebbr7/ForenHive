from services.alert_engine import AlertEngine


def test_dedup_suppresses_second_hit_within_window():
    eng = AlertEngine()
    ip = "198.51.100.7"
    assert eng._should_dedup(ip, window_min=15) is False
    assert eng._should_dedup(ip, window_min=15) is True


def test_dedup_isolates_by_ip():
    eng = AlertEngine()
    assert eng._should_dedup("10.0.0.1", window_min=15) is False
    assert eng._should_dedup("10.0.0.2", window_min=15) is False
