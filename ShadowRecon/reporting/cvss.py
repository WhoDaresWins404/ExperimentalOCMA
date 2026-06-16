from core.models import CVSSVector, FindingSeverity


class CVSSScorer:
    VECTORS = {
        "attack_vector": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "attack_complexity": {"L": "Low", "H": "High"},
        "privileges_required": {"N": "None", "L": "Low", "H": "High"},
        "user_interaction": {"N": "None", "R": "Required"},
        "scope": {"U": "Unchanged", "C": "Changed"},
        "confidentiality": {"H": "High", "L": "Low", "N": "None"},
        "integrity": {"H": "High", "L": "Low", "N": "None"},
        "availability": {"H": "High", "L": "Low", "N": "None"},
    }

    @staticmethod
    def score_from_severity(severity: FindingSeverity) -> tuple[float, CVSSVector]:
        mapping = {
            FindingSeverity.CRITICAL: (9.0, CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H",
            )),
            FindingSeverity.HIGH: (7.0, CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H",
            )),
            FindingSeverity.MEDIUM: (5.0, CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="L", integrity="L", availability="N",
            )),
            FindingSeverity.LOW: (2.0, CVSSVector(
                attack_vector="N", attack_complexity="H", privileges_required="N",
                user_interaction="R", scope="U", confidentiality="L", integrity="N", availability="N",
            )),
            FindingSeverity.NONE: (0.0, CVSSVector()),
        }
        return mapping.get(severity, mapping[FindingSeverity.NONE])

    @staticmethod
    def compute(vector: CVSSVector) -> float:
        return vector.compute_score()

    @staticmethod
    def severity_from_score(score: float) -> FindingSeverity:
        if score >= 9.0:
            return FindingSeverity.CRITICAL
        elif score >= 7.0:
            return FindingSeverity.HIGH
        elif score >= 4.0:
            return FindingSeverity.MEDIUM
        elif score > 0.0:
            return FindingSeverity.LOW
        return FindingSeverity.NONE
