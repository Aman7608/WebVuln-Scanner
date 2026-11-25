"""Tests for the Flask dashboard, the API and the HTML/PDF/JSON/CSV reports."""

import re
import time

import pytest

from reports.report_generator import generate_html_report, generate_pdf_report
from tests.conftest import csrf_from, post_json


def start_scan(client, target, **extra):
    body = {"target_url": target, "authorized": True, "max_depth": 2, "max_pages": 40,
            "delay": 0, **extra}
    return post_json(client, "/api/scans", body)


def wait_for_scan(client, scan_id, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        status = client.get(f"/api/scans/{scan_id}").get_json()
        if status["status"] in ("completed", "failed", "cancelled"):
            return status
        time.sleep(0.3)
    raise AssertionError("scan did not finish in time")


@pytest.mark.parametrize("path", ["/", "/scan", "/history", "/websites", "/account"])
def test_pages_load(user_client, path):
    response = user_client.get(path)
    assert response.status_code == 200
    assert b"WebVuln" in response.data


@pytest.mark.parametrize("path", ["/", "/scan", "/history", "/scans/1", "/scans/1/report.pdf"])
def test_pages_need_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_api_needs_login(client):
    assert client.get("/api/scans/1").status_code == 401


def test_dashboard_sends_its_own_security_headers(client):
    headers = client.get("/login").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_unknown_scan_is_404(user_client):
    assert user_client.get("/scans/999").status_code == 404
    assert user_client.get("/api/scans/999").status_code == 404
    assert user_client.get("/scans/999/report.pdf").status_code == 404


def test_api_requires_json(user_client):
    response = user_client.post("/api/scans", data={"target_url": "http://127.0.0.1/", "authorized": "1",
                                                    "csrf_token": csrf_from(user_client)})
    assert response.status_code == 403


def test_api_requires_csrf_token(user_client):
    response = user_client.post("/api/scans", json={"target_url": "http://127.0.0.1/", "authorized": True})
    assert response.status_code == 400


def test_api_blocks_other_origins(user_client):
    # A correct token, but the browser says the request came from another site
    response = user_client.post("/api/scans", json={"target_url": "http://127.0.0.1/", "authorized": True},
                                headers={"Origin": "http://evil.test", "X-CSRF-Token": csrf_from(user_client)})
    assert response.status_code == 403


def test_api_requires_authorization_checkbox(user_client, lab_url):
    response = post_json(user_client, "/api/scans", {"target_url": lab_url})
    assert response.status_code == 400
    assert "authorized" in response.get_json()["error"]


def test_api_rejects_target_not_on_allowlist(user_client):
    response = start_scan(user_client, "https://example.com/")
    assert response.status_code == 400
    assert "allowlist" in response.get_json()["error"]


def test_api_rejects_empty_module_list(user_client, lab_url):
    assert start_scan(user_client, lab_url, modules=[]).status_code == 400
    assert start_scan(user_client, lab_url, modules=["nonsense"]).status_code == 400


def test_full_scan_through_dashboard(user_client, lab_url):
    client = user_client
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

    # Delete the scan
    response = client.post(f"/scans/{scan_id}/delete", data={"csrf_token": csrf_from(client)})
    assert response.status_code == 302
    assert client.get(f"/scans/{scan_id}").status_code == 404


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


def test_new_scan_page_shows_login_and_exclusions(user_client):
    page = user_client.get("/scan").data.decode()
    assert 'name="login_url"' in page and 'name="cookies"' in page
    assert "logout" in page
    # Stored XSS writes data, so it is not ticked by default
    assert re.search(r'value="stored_xss"\s*>', page)
    assert re.search(r'value="xss"\s*checked', page)


def test_api_scan_with_login_never_stores_password(user_client, lab_url, app):
    from database import db
    from test_lab.vulnerable_app import LAB_PASSWORD, LAB_USERNAME
    client = user_client
    response = start_scan(client, lab_url + "/", modules=["xss"], login_url=lab_url + "/account/login",
                          login_username=LAB_USERNAME, login_password=LAB_PASSWORD)
    scan_id = response.get_json()["scan_id"]
    assert wait_for_scan(client, scan_id)["status"] == "completed"
    page = client.get(f"/scans/{scan_id}").data.decode()
    assert "form login as tester" in page
    assert "/account/notes" in page
    assert LAB_PASSWORD not in page
    assert LAB_PASSWORD.encode() not in client.get(f"/scans/{scan_id}/report.html").data
    # The encrypted copy in the queue was wiped when the scan started
    with db.connect(app.config["DATABASE_PATH"]) as conn:
        row = conn.execute("SELECT secrets_enc FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert row["secrets_enc"] == ""


def test_cancel_running_scan(user_client, lab_url):
    client = user_client
    # A slow scan (delay between requests) so there is time to cancel it
    scan_id = start_scan(client, lab_url + "/", delay=0.3, max_pages=40).get_json()["scan_id"]
    time.sleep(1.5)
    response = post_json(client, f"/api/scans/{scan_id}/cancel")
    assert response.status_code == 200
    status = wait_for_scan(client, scan_id)
    assert status["status"] == "cancelled"
    page = client.get(f"/scans/{scan_id}").data.decode()
    assert "was cancelled" in page
    # Reports still work for a cancelled scan
    assert client.get(f"/scans/{scan_id}/report.pdf").status_code == 200
    # Cancelling again is refused because it is no longer running
    assert post_json(client, f"/api/scans/{scan_id}/cancel").status_code == 409


def test_cancel_requires_json(user_client):
    response = user_client.post("/api/scans/1/cancel", data={"csrf_token": csrf_from(user_client)})
    assert response.status_code == 403


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


def test_export_routes(user_client, lab_url):
    client = user_client
    scan_id = start_scan(client, lab_url + "/", modules=["headers"]).get_json()["scan_id"]
    wait_for_scan(client, scan_id)
    json_response = client.get(f"/scans/{scan_id}/findings.json")
    assert json_response.status_code == 200 and json_response.get_json()["findings"]
    csv_response = client.get(f"/scans/{scan_id}/findings.csv")
    assert csv_response.mimetype == "text/csv" and b"Content-Security-Policy" in csv_response.data
    assert "JSON</a>" in client.get(f"/scans/{scan_id}").data.decode()
