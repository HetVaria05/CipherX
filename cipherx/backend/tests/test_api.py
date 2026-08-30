from fastapi.testclient import TestClient
import sys
import os
import pytest

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def disable_live_network(monkeypatch):
    monkeypatch.setattr("engine.threat_intel.query_urlhaus_api", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "engine.network_intel.collect_dns_intel",
        lambda *args, **kwargs: {
            "status": "ok",
            "hostname": "example.com",
            "addresses": ["93.184.216.34"],
            "a_records": ["93.184.216.34"],
            "aaaa_records": [],
            "ns_records": [],
            "mx_records": [],
            "minimum_ttl": 3600,
            "summary": "DNS resolved successfully.",
        },
    )
    monkeypatch.setattr(
        "engine.network_intel.collect_tls_certificate",
        lambda *args, **kwargs: {"status": "blocked", "summary": "TLS probe disabled in tests."},
    )
    monkeypatch.setattr(
        "engine.network_intel.collect_rdap_domain",
        lambda *args, **kwargs: {"status": "blocked", "summary": "RDAP lookup disabled in tests."},
    )
    monkeypatch.setattr("engine.network_intel.collect_redirect_chain", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "engine.network_intel._fetch_page_sample",
        lambda *args, **kwargs: {
            "status": "ok",
            "url": "https://example.com/",
            "content_type": "text/html",
            "body": "<html><head><title>Example</title></head><body><h1>Welcome</h1></body></html>",
            "truncated": False,
        },
    )


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "CipherX API"
    assert "database" in data

def test_analyze_url():
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert data["url"] == "https://example.com"
    assert data["normalized_url"] == "https://example.com/"
    assert data["features"]["registrable_domain"] == "example.com"


def test_legitimate_amazon_low_risk():
    response = client.post("/api/analyze", json={"url": "https://amazon.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "LOW"
    assert data["brand_analysis"]["best_match"]["official_domain_matches"] is True
    assert data["adversarial_findings"] == []


def test_typosquatting_brand_similarity():
    response = client.post("/api/analyze", json={"url": "https://amaz0n-login.xyz"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["HIGH", "CRITICAL"]
    assert data["brand_analysis"]["impersonated_brand"] == "Amazon"
    assert data["features"]["suspicious_tld"] is True
    assert any(signal["signal"] == "login_or_verification_keyword" for signal in data["signals"])


def test_at_symbol_deception():
    response = client.post("/api/analyze", json={"url": "https://amazon.com@evil-site.com"})
    assert response.status_code == 200
    data = response.json()
    finding = data["adversarial_findings"][0]
    assert data["classification"] == "CRITICAL"
    assert finding["technique"] == "at_symbol_deception"
    assert finding["actual_domain"] == "evil-site.com"
    assert finding["deceptive_domain"] == "amazon.com"


def test_subdomain_deception():
    response = client.post("/api/analyze", json={"url": "https://amazon.com.evil-site.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["features"]["registrable_domain"] == "evil-site.com"
    assert any(signal["signal"] == "brand_subdomain_deception" for signal in data["signals"])
    assert data["risk_score"] > 30


def test_ip_url_detection():
    response = client.post("/api/analyze", json={"url": "http://192.168.1.10/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["features"]["has_ip"] is True
    assert data["features"]["ip_address"] == "192.168.1.10"
    assert any(signal["signal"] == "ip_based_url" for signal in data["signals"])
    assert any(signal["signal"] == "login_or_verification_keyword" for signal in data["signals"])
    assert data["risk_score"] > 30


def test_normal_multilevel_domain_and_query():
    response = client.post(
        "/api/analyze",
        json={"url": "https://accounts.google.com/login?continue=https%3A%2F%2Fgoogle.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["LOW", "SUSPICIOUS"]
    assert data["brand_analysis"]["best_match"]["official_domain_matches"] is True


def test_threat_intel_feed_match():
    response = client.post(
        "/api/analyze",
        json={"url": "https://suspicious-bank-login.xyz/auth"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "CRITICAL"
    assert data["risk_score"] == 100
    assert any(signal["signal"] == "threat_intel_ioc_match" for signal in data["signals"])
    assert "threat_intel_match" in data["features"]
    assert data["features"]["threat_intel_match"]["source"] == "PhishTank"


def test_marketing_campaign_link_not_low():
    response = client.post(
        "/api/analyze",
        json={"url": "https://us5.campaign-archive.com/?u=55838c2cc5bb367ec752f3a46&id=97f8637581"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert any(signal["signal"] == "form_or_marketing_tracking" for signal in data["signals"])


def test_opaque_hsforms_link_not_low():
    response = client.post(
        "/api/analyze",
        json={"url": "https://share.hsforms.com/1nd2gzp2ht4y2h-xfwny0rwsofw8"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert any(signal["signal"] == "opaque_hosted_resource" for signal in data["signals"])


def test_shortened_link_detection():
    response = client.post(
        "/api/analyze",
        json={"url": "https://plink.me/pyzcbgzjeaw8?bs=db"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert any(signal["signal"] == "url_shortener" for signal in data["signals"])


def test_encoded_embedded_url_detection():
    response = client.post(
        "/api/analyze",
        json={"url": "https://l0v7bwbl.r.us-east-1.awstrack.me/l0/https%3A%2F%2Fpanel.stateaudit-irsreturncenter.com/1/"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert any(signal["signal"] == "embedded_url" for signal in data["signals"])


def test_brand_domain_hidden_in_path_detection():
    response = client.post(
        "/api/analyze",
        json={"url": "https://jncwdkj.com/www.rakuten-card.co.jp/"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert any(signal["signal"] == "brand_reference_in_path" for signal in data["signals"])


def test_trusted_domain_ioc_is_not_whitelisted():
    response = client.post(
        "/api/analyze",
        json={"url": "https://github.com/pistacchietto/Win-Python-Backdoor/raw/master/win.bat"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "CRITICAL"
    assert data["risk_score"] == 100
    assert any(signal["signal"] == "threat_intel_ioc_match" for signal in data["signals"])


def test_embedded_brand_in_suspicious_domain_detection():
    response = client.post(
        "/api/analyze",
        json={"url": "https://allegrolokalnie.pl-oferta196862.icu/"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ["SUSPICIOUS", "HIGH", "CRITICAL"]
    assert any(signal["signal"] == "brand_name_in_untrusted_domain" for signal in data["signals"])


def test_advanced_analyze_endpoint():
    response = client.post(
        "/api/advanced-analyze",
        json={
            "url": "https://example.com",
            "use_virustotal": False,
            "include_network": False
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "base_analysis" in data
    assert "advanced" in data
    assert "signals" in data
    assert "risk_score" in data


def test_content_scan_detects_login_form():
        from engine.network_intel import collect_content_scan
        from engine.url_utils import normalize_url
        from engine import network_intel

        html = """
        <html>
            <head><title>Secure Login</title></head>
            <body>
                <form action="/session">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <button>Sign in</button>
                </form>
            </body>
        </html>
        """

        network_intel._fetch_page_sample = lambda *args, **kwargs: {
                "status": "ok",
                "url": "https://example.com/login",
                "content_type": "text/html",
                "body": html,
                "truncated": False,
        }

        result = collect_content_scan(normalize_url("https://example.com/login"))
        assert result["status"] == "ok"
        assert result["password_field_count"] == 1
        assert any(finding["signal"] == "credential_form_detected" for finding in result["findings"])


def test_normalize_url_scheme_restrictions():
    from engine.url_utils import normalize_url

    with pytest.raises(ValueError, match="Only http/https URLs are allowed"):
        normalize_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="Only http/https URLs are allowed"):
        normalize_url("ftp://ftp.example.com/files")

    with pytest.raises(ValueError, match="Only http/https URLs are allowed"):
        normalize_url("javascript:alert(1)")


def test_normalize_url_strips_fragments_and_userinfo():
    from engine.url_utils import normalize_url

    norm = normalize_url("https://user:password@example.com:8080/path?query=1#frag")
    assert norm.scheme == "https"
    assert norm.hostname == "example.com"
    assert norm.port == 8080
    assert norm.username == "user"
    assert norm.password == "password"
    assert norm.fragment == "frag"
    # Netloc and normalized_url must NOT include userinfo or fragments
    assert norm.normalized_url == "https://example.com:8080/path?query=1"


def test_normalize_url_ipv6_literal():
    from engine.url_utils import normalize_url

    norm = normalize_url("http://[2001:db8::1]:8080/api")
    assert norm.hostname == "2001:db8::1"
    assert norm.port == 8080
    assert norm.registrable_domain == "2001:db8::1"
    assert norm.normalized_url == "http://[2001:db8::1]:8080/api"



def test_network_safety_ssrf_and_dns_fail():
    from engine.network_intel import evaluate_network_safety

    # Localhost check
    safety_local = evaluate_network_safety("localhost")
    assert safety_local["safe_for_network_probe"] is False
    assert "localhost_hostname" in safety_local["blocked_reasons"]

    # Private IP literal check
    safety_private = evaluate_network_safety("127.0.0.1")
    assert safety_private["safe_for_network_probe"] is False
    assert "private_or_reserved_address" in safety_private["blocked_reasons"]

    # Unresolvable hostname check (DNS fail = block)
    safety_unresolvable = evaluate_network_safety("this-is-a-completely-nonexistent-domain-123456789.xyz")
    assert safety_unresolvable["safe_for_network_probe"] is False
    assert "dns_resolution_failed" in safety_unresolvable["blocked_reasons"]


def test_scan_timing_metric_present():
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "scan_duration_ms" in data
    assert isinstance(data["scan_duration_ms"], (int, float))
    assert data["scan_duration_ms"] >= 0

