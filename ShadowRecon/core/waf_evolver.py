import random
from dataclasses import dataclass, field


EVASION_TECHNIQUES = [
    "none",
    "url_encode",
    "double_url_encode",
    "unicode_normalize",
    "case_swap",
    "comment_injection",
    "parameter_pollution",
    "mixed_encoding",
    "path_traversal_bypass",
    "header_bypass",
    "chunked_encoding",
    "null_byte_injection",
]

EVASION_PRIORITY: dict[str, list[str]] = {
    "cloudflare": ["header_bypass", "url_encode", "comment_injection", "case_swap", "mixed_encoding", "parameter_pollution"],
    "modsecurity": ["unicode_normalize", "double_url_encode", "comment_injection", "null_byte_injection"],
    "aws": ["url_encode", "double_url_encode", "header_bypass", "parameter_pollution"],
    "akamai": ["header_bypass", "chunked_encoding", "mixed_encoding", "unicode_normalize"],
    "generic": ["url_encode", "case_swap", "comment_injection", "parameter_pollution", "double_url_encode", "unicode_normalize", "header_bypass", "chunked_encoding", "null_byte_injection"],
}


@dataclass
class WafState:
    waf_name: str = "generic"
    blocked_last: int = 0
    current_technique: str = "none"
    technique_index: int = 0
    technique_history: list[tuple[str, bool]] = field(default_factory=list)
    consecutive_blocks: int = 0


class WafEvolver:
    def __init__(self):
        self._state: dict[str, WafState] = {}

    def get_state(self, target_url: str) -> WafState:
        if target_url not in self._state:
            self._state[target_url] = WafState()
        return self._state[target_url]

    def record_block(self, target_url: str):
        state = self.get_state(target_url)
        state.blocked_last += 1
        state.consecutive_blocks += 1
        state.technique_history.append((state.current_technique, True))
        self._escalate(state)

    def record_pass(self, target_url: str):
        state = self.get_state(target_url)
        state.consecutive_blocks = 0
        state.technique_history.append((state.current_technique, False))

    def current_technique(self, target_url: str) -> str:
        state = self.get_state(target_url)
        return state.current_technique

    def _escalate(self, state: WafState):
        waf_key = state.waf_name.lower() if state.waf_name else "generic"
        priority = EVASION_PRIORITY.get(waf_key, EVASION_PRIORITY["generic"])
        state.technique_index = min(state.technique_index + 1, len(priority) - 1)
        state.current_technique = priority[state.technique_index]

    def reset_state(self, target_url: str):
        if target_url in self._state:
            del self._state[target_url]

    def apply_evasion(self, payload: str, technique: str) -> str:
        import urllib.parse
        if technique == "none":
            return payload
        elif technique == "url_encode":
            return urllib.parse.quote(payload)
        elif technique == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif technique == "unicode_normalize":
            return payload.replace("<", "%u003c").replace(">", "%u003e")
        elif technique == "case_swap":
            return "".join(c.swapcase() if random.random() < 0.5 else c for c in payload)
        elif technique == "comment_injection":
            parts = list(payload)
            idx = random.randint(1, max(1, len(parts) - 1))
            parts.insert(idx, "/**/")
            return "".join(parts)
        elif technique == "parameter_pollution":
            return payload
        elif technique == "mixed_encoding":
            result = []
            for c in payload:
                if random.random() < 0.3:
                    result.append(urllib.parse.quote(c))
                else:
                    result.append(c)
            return "".join(result)
        elif technique == "null_byte_injection":
            return payload + "%00"
        elif technique == "header_bypass":
            return payload
        return payload
