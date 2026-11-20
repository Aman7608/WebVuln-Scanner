"""Tests for the Flask dashboard, the API and the HTML/PDF reports."""

import re
import time

import pytest

from app import create_app
from reports.report_generator import generate_html_report, generate_pdf_report


@pytest.fixture
def client(tmp_path):
    app = create_app(database_path=str(tmp_path / "dashboard.db"))
    app.config["TESTING"] = True
    return app.test_client()


def start_scan(client, target, **extra):
    body = {"target_url": target, "authorized": True, "max_depth": 2, "max_pages": 40,
            "delay": 0, **extra}
    return client.post("/api/scans", json=body)


def wait_for_scan(client, scan_id, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        status = client.get(f"/api/scans/{scan_id}").get_json()
        if status["status"] in ("completed", "failed", "cancelled"):
            return status
        time.sleep(0.3)
    raise AssertionError("scan did not finish in time")


@pytest.mark.parametrize("path", ["/", "/scan", "/history"])
def test_pages_load(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert b"WebVuln" in response.data


def test_dashboard_sends_its_own_security_headers(client):
    headers = client.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_unknown_scan_is_404(client):
    assert client.get("/scans/999").status_code == 404
    assert client.get("/api/scans/999").status_code == 404
    assert client.get("/scans/999/report.pdf").status_code == 404


def test_api_requires_json(client):
    response = client.post("/api/scans", data={"target_url": "http://127.0.0.1/", "authorized": "1"})
    assert response.status_code == 403


def test_api_blocks_other_origins(client):
    response = client.post("/api/scans", json={"target_url": "http://127.0.0.1/", "authorized": True},
                           headers={"Origin": "http://evil.test"})
    assert response.status_code == 403


def test_api_requires_authorization_checkbox(client, lab_url):
    response = client.post("/api/scans", json={"target_url": lab_url})
    assert response.status_code == 400
    assert "authorized" in response.get_json()["error"]


def test_api_rejects_target_not_on_allowlist(client):
    response = start_scan(client, "https://example.com/")
    assert response.status_code == 400
    assert "allowlist" in response.get_json()["error"]


def test_api_rejects_empty_module_list(client, lab_url):
    assert start_scan(client, lab_url, modules=[]).status_code == 400
    assert start_scan(client, lab_url, modules=["nonsense"]).status_code == 400


def test_full_scan_through_dashboard(client, lab_url):
    response = start_scan(client, lab_url + "/")
    assert response.status_code == 201
    scan_id = response.get_json()["scan_id"]

    status = wait_for_scan(client, scan_id)
    assert status["status"] == "completed"
    assert status["finding_count"] > 5

    page = client.get(f"/scans/{scan_id}").data.decode()
    assert "SQL Injection" in page and "Reflected Cross-Site Scripting" in page
    assert "Recommended fix" in page
    # Payloads in the evidence must be escaped, never rendered as real tags
    assert not re.search(r"<wvs[a-z0-9]{6}x>", page)
    assert "&lt;wvs" in page

    # The scan now shows on the dashboard and in the history
    assert lab_url.encode() in client.get("/history").data
    dashboard = client.get("/").data.decode()
    assert "Recent scan activity" in dashboard and lab_url in dashboard

    # HTML report: viewable and downloadable
    html = client.get(f"/scans/{scan_id}/report.html")
    assert html.status_code == 200 and b"Detailed findings" in html.data
    assert not re.search(rb"<wvs[a-z0-9]{6}x>", html.data)
    download = client.get(f"/scans/{scan_id}/report.html?download=1")
    assert "attachment" in download.headers["Content-Disposition"]

    # PDF report
    pdf = client.get(f"/scans/{scan_id}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.data.startswith(b"%PDF")
    assert len(pdf.data) > 3000


SAMPLE_SCAN = {"id": 1, "target_url": "http://127.0.0.1/", "status": "completed", "error_message": "",
               "current_step": "Finished", "started_at": "2026-11-20 10:00:00",
               "finished_at": "2026-11-20 10:01:00", "pages_found": 3, "requests_sent": 40,
               "config": {"max_depth": 2, "max_pages": 30, "modules": ["xss"]}}
SAMPLE_FINDING = {"name": "Reflected <XSS> & stuff", "url": "http://127.0.0.1/s?a=1&b=<2>",
                  "parameter": "q", "severity": "High", "risk_score": 16, "confidence": "High",
                  "description": "desc", "evidence": "<script>alert(1)</script>\nline 2",
                  "remediation": "fix it"}
SAMPLE_COUNTS = {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Informational": 0}


def test_html_report_escapes_evidence():
    html = generate_html_report(SAMPLE_SCAN, [SAMPLE_FINDING], SAMPLE_COUNTS, [])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_pdf_report_handles_special_characters():
    pdf = generate_pdf_report(SAMPLE_SCAN, [SAMPLE_FINDING], SAMPLE_COUNTS,
                              [{"source": "crawler", "url": "http://127.0.0.1/?a=<b>", "status_code": 200}])
    assert pdf.startswith(b"%PDF")


def test_pdf_report_with_no_findings():
    assert generate_pdf_report(SAMPLE_SCAN, [], SAMPLE_COUNTS, []).startswith(b"%PDF")


def test_new_scan_page_shows_login_and_exclusions(client):
    page = client.get("/scan").data.decode()
    assert 'name="login_url"' in page and 'name="cookies"' in page
    assert "logout" in page
    # Stored XSS writes data, so it is not ticked by default
    assert re.search(r'value="stored_xss"\s*>', page)
    assert re.search(r'value="xss"\s*checked', page)


def test_api_scan_with_login_never_stores_password(client, lab_url):
    from test_lab.vulnerable_app import LAB_PASSWORD, LAB_USERNAME
    response = start_scan(client, lab_url + "/", modules=["xss"], login_url=lab_url + "/account/login",
                          login_username=LAB_USERNAME, login_password=LAB_PASSWORD)
    scan_id = response.get_json()["scan_id"]
    assert wait_for_scan(client, scan_id)["status"] == "completed"
    page = client.get(f"/scans/{scan_id}").data.decode()
    assert "form login as tester" in page
    assert "/account/notes" in page
    assert LAB_PASSWORD not in page
    assert LAB_PASSWORD.encode() not in client.get(f"/scans/{scan_id}/report.html").data


def test_cancel_running_scan(client, lab_url):
    # A slow scan (delay between requests) so there is time to cancel it
    scan_id = start_scan(client, lab_url + "/", delay=0.3, max_pages=40).get_json()["scan_id"]
    time.sleep(1)
    response = client.post(f"/api/scans/{scan_id}/cancel", json={})
    assert response.status_code == 200
    status = wait_for_scan(client, scan_id)
    assert status["status"] == "cancelled"
    page = client.get(f"/scans/{scan_id}").data.decode()
    assert "was cancelled" in page
    # Reports still work for a cancelled scan
    assert client.get(f"/scans/{scan_id}/report.pdf").status_code == 200
    # Cancelling again is refused because it is no longer running
    assert client.post(f"/api/scans/{scan_id}/cancel", json={}).status_code == 409


def test_cancel_requires_json(client):
    assert client.post("/api/scans/1/cancel", data={}).status_code == 403


def test_json_and_csv_export():
    import csv
    import io
    import json
    from reports.report_generator import csv_safe, generate_csv_report, generate_json_report

    finding = dict(SAMPLE_FINDING, evidence="=HYPERLINK(\"http://evil.test\")")
    data = json.loads(generate_json_report(SAMPLE_SCAN, [finding], SAMPLE_COUNTS, []))
    assert data["scan"]["target_url"] == "http://127.0.0.1/"
    assert data["findings"][0]["severity"] == "High"

    rows = list(csv.reader(io.StringIO(generate_csv_report(SAMPLE_SCAN, [finding], SAMPLE_COUNTS, []))))
    assert rows[0][0] == "severity" and rows[1][0] == "High"
    # Formula-looking text is made harmless for Excel
    assert rows[1][rows[0].index("evidence")].startswith("'=")
    assert csv_safe("+1") == "'+1" and csv_safe("normal") == "normal"


def test_export_routes(client, lab_url):
    scan_id = start_scan(client, lab_url + "/", modules=["headers"]).get_json()["scan_id"]
    wait_for_scan(client, scan_id)
    json_response = client.get(f"/scans/{scan_id}/findings.json")
    assert json_response.status_code == 200 and json_response.get_json()["findings"]
    csv_response = client.get(f"/scans/{scan_id}/findings.csv")
    assert csv_response.mimetype == "text/csv" and b"Content-Security-Policy" in csv_response.data
    assert "JSON</a>" in client.get(f"/scans/{scan_id}").data.decode()
