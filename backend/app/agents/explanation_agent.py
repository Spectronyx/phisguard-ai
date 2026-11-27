"""Explanation and recommendation stage.

All text is generated from observed component outputs. No claim is made about
data that was not analysed.
"""

from __future__ import annotations

from typing import Any

_COMPONENT_LABELS = {
    "email_model": "email NLP model",
    "url_model": "URL classifier",
    "email_rules": "email rule engine",
    "url_rules": "URL rule engine",
    "graph": "domain graph",
    "llm": "LLM semantic review",
}


class ExplanationAgent:
    name = "explanation"

    def build(
        self,
        scan_type: str,
        aggregated: dict[str, Any],
        components: list[dict[str, Any]],
        indicators: list[dict[str, Any]],
        llm_used: bool,
        llm_model: str | None = None,
        llm_backend: str | None = None,
        target_label: str | None = None,
    ) -> dict[str, str]:
        score = aggregated["risk_score"]
        level = aggregated["risk_level"]
        classification = aggregated["classification"]
        subject = target_label or ("email message" if scan_type == "email" else "URL")

        parts: list[str] = [
            f"PhishGuard AI classified this {subject} as {classification} with a risk score of "
            f"{score}/100 ({level} risk)."
        ]

        available = sorted(
            [item for item in aggregated["breakdown"] if item.get("score") is not None],
            key=lambda item: item.get("contribution") or 0.0,
            reverse=True,
        )
        for item in available[:2]:
            label = _COMPONENT_LABELS.get(item["name"], item["name"])
            text = f"The {label} contributed {item['contribution']:.1f} points (module risk {item['score']:.0f}/100"
            if item.get("confidence") is not None:
                text += f", model confidence {item['confidence']:.2f}"
            text += ")."
            if item.get("explanation"):
                text += " " + item["explanation"]
            parts.append(text)

        if aggregated.get("corroboration_bonus"):
            names = ", ".join(
                _COMPONENT_LABELS.get(name, name) for name in aggregated["high_signal_components"]
            )
            parts.append(
                f"Independent evidence from {names} exceeded the high-risk threshold, so a "
                f"{aggregated['corroboration_bonus']:.0f}-point corroboration adjustment was applied."
            )

        severe = [i["name"] for i in indicators if i.get("severity") in {"high", "critical"}]
        if severe:
            parts.append("Key indicators: " + "; ".join(severe[:4]) + ".")

        graph_status = next((c.get("status") for c in components if c.get("name") == "graph"), None)
        if graph_status == "no_data":
            parts.append(
                "The domain graph had no matching data for the analysed domain(s), so graph risk was "
                "excluded rather than treated as safe."
            )
        if llm_used:
            model_name = f" ({llm_model})" if llm_model else ""
            if llm_backend == "local_distilbert":
                parts.append(
                    f"A locally fine-tuned DistilBERT semantic classifier{model_name} also reviewed the text "
                    "on this machine; no content was sent externally, and it is one weighted component."
                )
            else:
                parts.append(
                    f"An optional external LLM semantic review{model_name} was also performed; its result "
                    "is one weighted component and does not override the local models."
                )

        explanation = " ".join(parts)
        return {
            "explanation": explanation,
            "recommendation": self._recommendation(classification, indicators),
        }

    @staticmethod
    def _recommendation(classification: str, indicators: list[dict[str, Any]]) -> str:
        names = {i.get("name", "").lower() for i in indicators}
        actions: list[str] = []

        if classification == "phishing":
            actions.append("Do not click any links, reply, or provide credentials or payment details.")
        elif classification == "suspicious":
            actions.append("Treat this as untrustworthy until independently verified through an official channel.")
        else:
            actions.append("No strong phishing signal was found, but stay cautious with unexpected requests.")

        if any("credential" in name or "password" in name or "sensitive data" in name for name in names):
            actions.append(
                "If you already entered credentials, change the password immediately and enable multi-factor authentication."
            )
        if any("financial" in name or "payment" in name or "invoice" in name for name in names):
            actions.append(
                "Verify payment requests by contacting the organisation using a number from its official website, not the message."
            )
        if any("attachment" in name for name in names):
            actions.append("Do not open unexpected attachments; submit them to your security team for scanning.")
        if any("link" in name or "brand" in name or "deceptive" in name for name in names):
            actions.append(
                "Navigate to the organisation's website manually or use a saved bookmark instead of the supplied link."
            )
        if any("threat" in name or "urgency" in name for name in names):
            actions.append(
                "Pause: urgency and account threats are pressure tactics. Confirm the claim through official support."
            )
        actions.append("Report the message to your organisation's security or IT team and then delete it.")

        # Keep the report concise and de-duplicated.
        unique: list[str] = []
        for action in actions:
            if action not in unique:
                unique.append(action)
        return " ".join(unique[:5])
