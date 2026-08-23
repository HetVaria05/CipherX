def make_signal(signal, severity, score, reason, details=None):
    return {
        "signal": signal,
        "name": signal.replace("_", " ").title(),
        "severity": severity,
        "score": score,
        "reason": reason,
        "details": details or {},
    }
