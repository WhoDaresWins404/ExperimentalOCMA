class ShadowReconError(Exception):
    pass

class TargetUnreachable(ShadowReconError):
    def __init__(self, target: str, reason: str = ""):
        self.target = target
        self.reason = reason
        super().__init__(f"Target unreachable: {target} — {reason}")

class WAFDetected(ShadowReconError):
    def __init__(self, waf_name: str, confidence: float):
        self.waf_name = waf_name
        self.confidence = confidence
        super().__init__(f"WAF detected: {waf_name} (confidence: {confidence:.2f})")

class RateLimited(ShadowReconError):
    def __init__(self, retry_after: int = 60):
        self.retry_after = retry_after
        super().__init__(f"Rate limited. Retry after {retry_after}s")

class ScanCancelled(ShadowReconError):
    pass

class ScanTimeout(ShadowReconError):
    def __init__(self, timeout: int):
        super().__init__(f"Scan timed out after {timeout}s")

class LLMUnavailable(ShadowReconError):
    def __init__(self, reason: str = ""):
        super().__init__(f"LLM unavailable: {reason}")

class DatabaseError(ShadowReconError):
    pass
