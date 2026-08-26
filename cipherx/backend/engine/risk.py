def score_risk(signals):
    total = sum(max(0, int(signal.get("score", 0))) for signal in signals)
    score = max(0, min(100, total))
    return score, classify(score), confidence(score, signals)


def classify(score):
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "SUSPICIOUS"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def confidence(score, signals):
    if not signals:
        return 0.55

    severity_values = {"low": 0.04, "medium": 0.07, "high": 0.11, "critical": 0.16}
    evidence_strength = sum(severity_values.get(signal.get("severity"), 0.04) for signal in signals)
    score_strength = min(score / 100, 1) * 0.18
    return round(min(0.98, 0.62 + evidence_strength + score_strength), 2)
