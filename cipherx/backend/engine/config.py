RISK_WEIGHTS = {
    "at_symbol_deception": 85,
    "userinfo_in_url": 35,
    "brand_typosquatting": 40,
    "brand_subdomain_deception": 32,
    "brand_domain_mismatch": 18,
    "ip_based_url": 15,
    "suspicious_tld": 15,
    "suspicious_query_parameter": 10,
    "login_or_verification_keyword": 10,
    "suspicious_special_structure": 10,
    "http_with_sensitive_context": 10,
    "excessive_subdomains": 10,
    "excessive_hyphens": 7,
    "long_url": 5,
    "high_digit_ratio": 5,
    "high_domain_entropy": 5,
    "encoded_sensitive_character": 5,
    "encoded_characters": 3,
}

SUSPICIOUS_TLDS = {
    "biz",
    "click",
    "country",
    "gq",
    "info",
    "link",
    "loan",
    "mom",
    "party",
    "pw",
    "rest",
    "ru",
    "support",
    "tk",
    "top",
    "work",
    "xyz",
}

SUSPICIOUS_KEYWORDS = {
    "account",
    "banking",
    "confirm",
    "credential",
    "login",
    "password",
    "secure",
    "security",
    "signin",
    "sso",
    "update",
    "verify",
    "wallet",
}

SUSPICIOUS_QUERY_KEYS = {
    "callback",
    "continue",
    "next",
    "password",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "token",
    "url",
}

SUSPICIOUS_PORTS = {81, 82, 83, 88, 444, 4443, 8000, 8080, 8081, 8443, 8888}

TRUSTED_BRANDS = [
    {"brand": "Amazon", "domain": "amazon.com"},
    {"brand": "Google", "domain": "google.com"},
    {"brand": "Microsoft", "domain": "microsoft.com"},
    {"brand": "Apple", "domain": "apple.com"},
    {"brand": "Paytm", "domain": "paytm.com"},
    {"brand": "PhonePe", "domain": "phonepe.com"},
    {"brand": "SBI", "domain": "sbi.co.in"},
    {"brand": "HDFC", "domain": "hdfcbank.com"},
    {"brand": "ICICI", "domain": "icicibank.com"},
    {"brand": "Axis", "domain": "axisbank.com"},
]
