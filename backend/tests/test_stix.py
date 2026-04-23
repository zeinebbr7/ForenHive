from services.report_service import ReportService


def test_stix_bundle_shape():
    events = [
        {"source": {"ip": "1.2.3.4"}, "file": {"hash": {"sha256": "a" * 64}}},
        {"source": {"ip": "1.2.3.4"}},
        {"source": {"ip": "5.6.7.8"}},
    ]
    bundle = ReportService.build_stix_bundle(events, "Test Report")
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types
    assert "report" in types
    assert types.count("ipv4-addr") == 2
    assert types.count("indicator") == 2
    assert types.count("file") == 1


def test_infer_helpers():
    assert ReportService._extract_ip_from_title("Forensic Report — IP 203.0.113.5") == "203.0.113.5"
    assert ReportService._extract_session_from_title("Forensic Report — Session abc-123") == "abc-123"
