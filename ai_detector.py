import numpy as np # pyright: ignore[reportMissingImports]
from sklearn.ensemble import IsolationForest # type: ignore
import random

class AIDetector:
    def __init__(self):
        # Training data: [requests_per_second, failed_logins]
        # This is the "normal" baseline the SLM learns from
        normal_data = np.array([
            [20, 1],
            [25, 2],
            [30, 1],
            [35, 2],
            [40, 1],
            [22, 0],
            [28, 1],
            [33, 2],
            [18, 0],
            [26, 1],
        ])

        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(normal_data)

    def detect(self, traffic):
        data = [[traffic["requests"], traffic["failed_logins"]]]
        prediction = self.model.predict(data)
        return prediction[0] == -1

    def analyze_event(self, event_text):
        """Simulates the Lightweight SLM Decision Engine."""
        event_lower = event_text.lower()
        
        # HIGH RISK Indicators
        high_risk_keywords = ["failed login", "multiple login attempts", "brute force", "malware", "phishing", "attack detected", "ddos"]
        if any(keyword in event_lower for keyword in high_risk_keywords):
            from datetime import datetime
            conf = 95 if "critical" in event_lower else random.randint(85, 94)
            return {
                "event": event_text,
                "risk_level": "HIGH",
                "confidence": conf,
                "action": "Block",
                "reason": "Repeated authentication failures or malicious traffic detected",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ui": {
                    "color": "red",
                    "status_text": "Threat Blocked"
                }
            }
            
        # MEDIUM RISK Indicators
        medium_risk_keywords = ["unknown ip", "suspicious activity", "port scan", "unusual traffic", "spike"]
        if any(keyword in event_lower for keyword in medium_risk_keywords):
            from datetime import datetime
            return {
                "event": event_text,
                "risk_level": "MEDIUM",
                "confidence": random.randint(75, 85),
                "action": "Alert",
                "reason": "Unusual scanning or anomalous traffic pattern observed",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ui": {
                    "color": "yellow",
                    "status_text": "Suspicious Activity"
                }
            }
            
        # LOW RISK (Fallback)
        from datetime import datetime
        return {
            "event": event_text,
            "risk_level": "LOW",
            "confidence": random.randint(65, 75),
            "action": "Allow",
            "reason": "No abnormal traffic detected",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ui": {
                "color": "green",
                "status_text": "System Safe"
            }
        }