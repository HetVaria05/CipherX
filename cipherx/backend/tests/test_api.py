from fastapi.testclient import TestClient
import sys
import os

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "CipherX API"}

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
