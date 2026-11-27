"""URL analysis service (lexical features + ML model + deterministic rules)."""

from __future__ import annotations

from typing import Any

from app.ml.model_registry import ModelRegistry, ModelUnavailable
from app.ml.url_features import (
    extract_features,
    evaluate_url_rules,
    normalize_url,
    registrable_domain,
)


class URLAnalysisService:
    """Analyse URL strings without ever fetching them."""

    def __init__(self, registry: ModelRegistry) -> None:
        self.registry = registry

    def analyze(self, url: str) -> dict[str, Any]:
        parsed = normalize_url(url)
        popular = self.registry.popular_domains()
        features, _ = extract_features(url, popular_domains=popular)
        rule_result = evaluate_url_rules(url)

        indicators = [dict(item, url=url) for item in rule_result.indicators]
        result: dict[str, Any] = {
            "url": parsed.normalized if parsed.is_valid else url,
            "raw_url": url,
            "host": parsed.host,
            "domain": registrable_domain(parsed.host) if parsed.host else "",
            "valid": parsed.is_valid,
            "error": parsed.error,
            "features": {name: round(value, 4) for name, value in features.items()},
            "indicators": indicators,
        }

        # ---- ML model (optional) -------------------------------------
        if parsed.is_valid:
            try:
                probability, confidence, algorithm = self.registry.predict_url(features, host=parsed.host)
                calibrated = self._popularity_calibrate(probability, parsed, features)
                confidence = max(calibrated, 1.0 - calibrated)
                explanation = (
                    f"The URL classifier ({algorithm}) estimated a "
                    f"{calibrated * 100:.1f}% probability that this URL is malicious."
                )
                if calibrated != probability:
                    explanation += (
                        f" Raw model output was {probability * 100:.1f}%; it was reduced because "
                        f"'{result['domain']}' is in the Cisco Umbrella top-10k popularity ranking "
                        f"and the host is the bare registrable domain. Popularity is a weak prior, "
                        f"not a guarantee; deterministic URL rules were still applied."
                    )
                result["model"] = {
                    "name": "url_model",
                    "label": "URL ML classifier",
                    "status": "ok",
                    "score": round(calibrated * 100, 2),
                    "confidence": round(confidence, 4),
                    "explanation": explanation,
                    "details": {
                        "algorithm": algorithm,
                        "probability": round(calibrated, 4),
                        "probability_raw": round(probability, 4),
                        "popularity_calibrated": calibrated != probability,
                    },
                }
            except ModelUnavailable as exc:
                result["model"] = {
                    "name": "url_model",
                    "label": "URL ML classifier",
                    "status": "unavailable",
                    "score": None,
                    "confidence": None,
                    "explanation": f"URL model unavailable ({exc}); rules-only assessment.",
                    "details": {"fallback": "rules_only"},
                }
            except Exception as exc:  # never let inference take down a scan
                result["model"] = {
                    "name": "url_model",
                    "label": "URL ML classifier",
                    "status": "error",
                    "score": None,
                    "confidence": None,
                    "explanation": f"URL model inference failed ({type(exc).__name__}).",
                    "details": {"fallback": "rules_only"},
                }
        else:
            result["model"] = {
                "name": "url_model",
                "label": "URL ML classifier",
                "status": "unavailable",
                "score": None,
                "confidence": None,
                "explanation": parsed.error or "URL could not be parsed.",
                "details": {"fallback": "rules_only"},
            }

        # ---- Deterministic rules -------------------------------------
        result["rules"] = {
            "name": "url_rules",
            "label": "URL rule engine",
            "status": "ok",
            "score": rule_result.score,
            "confidence": None,
            "explanation": (
                f"{len(indicators)} deterministic URL indicator(s) detected."
                if indicators
                else "No deterministic URL warning indicators were triggered."
            ),
            "details": {"indicator_count": len(indicators)},
        }

        # Local summary score for display; final risk uses the weighted engine.
        model_score = result["model"].get("score")
        rule_score = result["rules"].get("score")
        if model_score is not None and rule_score is not None:
            result["risk_score"] = round(0.7 * model_score + 0.3 * rule_score, 1)
        elif model_score is not None:
            result["risk_score"] = round(model_score, 1)
        else:
            result["risk_score"] = round(rule_score or 0.0, 1)

        result["classification"] = _classify(result["risk_score"])
        return result

    def _popularity_calibrate(self, probability: float, parsed, features: dict[str, float]) -> float:
        """Shrink the model probability for a bare, top-ranked registrable domain.

        The training corpus does not cover most major brands and does contain
        abusive *subdomains* of popular hosting platforms, so character n-grams
        can over-predict on bare domains such as ``github.com``. This is a
        documented calibration using the same public ranking as the
        ``is_popular_domain`` feature. It is deliberately limited to bare
        registrable domains so that hosted phishing on a subdomain is not
        suppressed, and it is not a whitelist: the raw probability is retained
        in the response and all deterministic rules still run.
        """
        factor = float(self.registry.settings.url_popularity_calibration)
        is_bare = parsed.host == registrable_domain(parsed.host)
        if features.get("is_popular_domain") and is_bare and 0.0 < factor < 1.0:
            return probability * factor
        return probability

    def analyze_many(self, urls: list[str]) -> dict[str, Any]:
        """Analyse up to N URLs and produce aggregate components for a scan."""
        results = [self.analyze(url) for url in urls]
        model_scores = [r["model"]["score"] for r in results if r["model"]["status"] == "ok"]
        rule_scores = [r["rules"]["score"] for r in results if r["rules"]["status"] == "ok"]
        indicators: list[dict] = []
        for result in results:
            for indicator in result["indicators"]:
                item = dict(indicator)
                item["description"] = f"[{result['host'] or result['url']}] {item['description']}"
                indicators.append(item)

        details = {
            "urls_analyzed": len(results),
            "domains": sorted({r["domain"] for r in results if r["domain"]}),
            "per_url": [
                {
                    "url": r["url"],
                    "domain": r["domain"],
                    "risk_score": r["risk_score"],
                    "classification": r["classification"],
                    "indicator_count": len(r["indicators"]),
                    "valid": r["valid"],
                }
                for r in results
            ],
        }

        model_component: dict[str, Any]
        if model_scores:
            worst = max(model_scores)
            worst_result = max(results, key=lambda r: r["model"].get("score") or 0.0)
            model_component = {
                "name": "url_model",
                "label": "URL ML classifier",
                "status": "ok",
                "score": round(worst, 2),
                "confidence": worst_result["model"]["confidence"],
                "explanation": (
                    f"Highest malicious probability across {len(results)} embedded link(s) was "
                    f"{worst:.1f}% ({worst_result['url'][:80]})."
                ),
                "details": details,
            }
        else:
            model_component = {
                "name": "url_model",
                "label": "URL ML classifier",
                "status": "unavailable",
                "score": None,
                "confidence": None,
                "explanation": "No embedded URL could be scored by the URL model.",
                "details": details,
            }

        rules_component = {
            "name": "url_rules",
            "label": "URL rule engine",
            "status": "ok" if rule_scores else "unavailable",
            "score": round(max(rule_scores), 2) if rule_scores else None,
            "confidence": None,
            "explanation": (
                f"Highest deterministic URL risk across embedded links: {max(rule_scores):.0f}/100."
                if rule_scores
                else "No embedded URLs were available for rule-based analysis."
            ),
            "details": details,
        }

        return {
            "model_component": model_component,
            "rules_component": rules_component,
            "indicators": indicators,
            "results": results,
            "summaries": [
                {
                    "url": r["url"],
                    "domain": r["domain"],
                    "risk_score": r["risk_score"],
                    "classification": r["classification"],
                    "indicators": r["indicators"],
                    "error": r["error"],
                }
                for r in results
            ],
        }


def _classify(score: float) -> str:
    if score >= 60:
        return "phishing"
    if score >= 30:
        return "suspicious"
    return "safe"
