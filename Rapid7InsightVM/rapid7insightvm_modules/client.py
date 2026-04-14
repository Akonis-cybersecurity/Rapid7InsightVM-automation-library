import logging
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

ASSETS_PATH = "/vm/v4/integration/assets"
VULNERABILITIES_PATH = "/vm/v4/integration/vulnerabilities"
VALIDATE_PATH = "/validate"

# Progressive delays (seconds) for 429 and 5xx retries
RETRY_DELAYS = [60, 120, 240]


class InsightVMAPIError(Exception):
    pass


class InsightVMAuthError(InsightVMAPIError):
    pass


class InsightVMRateLimitError(InsightVMAPIError):
    pass


class InsightVMClient:
    def __init__(self, api_key: str, base_url: str) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-Api-Key": self._api_key,
                "Content-Type": "application/json",
            }
        )

    def _request_with_retry(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        last_error: Optional[Exception] = None
        max_attempts = len(RETRY_DELAYS) + 1

        for attempt in range(max_attempts):
            try:
                resp = self._session.request(method, url, timeout=120, **kwargs)
            except requests.RequestException as exc:
                last_error = exc
                logger.warning("Request to %s failed: %s", path, exc)
                if attempt < len(RETRY_DELAYS):
                    delay = RETRY_DELAYS[attempt]
                    logger.warning("Retrying in %ds (attempt %d/%d)", delay, attempt + 1, max_attempts)
                    time.sleep(delay)
                continue

            if resp.status_code == 429:
                last_error = InsightVMRateLimitError(f"Rate limit reached (attempt {attempt + 1})")
                # Honour the Retry-After header when present; fall back to progressive backoff
                retry_after_header = resp.headers.get("Retry-After")
                if retry_after_header is not None:
                    try:
                        sleep_time = int(retry_after_header)
                    except (ValueError, TypeError):
                        sleep_time = RETRY_DELAYS[attempt] if attempt < len(RETRY_DELAYS) else RETRY_DELAYS[-1]
                else:
                    sleep_time = RETRY_DELAYS[attempt] if attempt < len(RETRY_DELAYS) else RETRY_DELAYS[-1]
                logger.warning("Rate limit hit on %s, retrying in %ds (attempt %d/%d)", path, sleep_time, attempt + 1, max_attempts)
                time.sleep(sleep_time)
                continue

            if resp.status_code in (401, 403):
                raise InsightVMAuthError(
                    f"Authentication error {resp.status_code} on {path}"
                )

            if resp.status_code >= 500:
                last_error = InsightVMAPIError(f"Server error {resp.status_code} on {path}")
                if attempt < len(RETRY_DELAYS):
                    delay = RETRY_DELAYS[attempt]
                    logger.warning("Server error %d on %s, retrying in %ds (attempt %d/%d)", resp.status_code, path, delay, attempt + 1, max_attempts)
                    time.sleep(delay)
                continue

            if not resp.ok:
                raise InsightVMAPIError(
                    f"HTTP {resp.status_code} on {path}: {resp.text[:200]}"
                )

            return resp.json()

        raise last_error or InsightVMAPIError(f"Request to {path} failed after all retries")

    def validate(self) -> bool:
        """Check that the API key is valid."""
        result = self._request_with_retry("GET", VALIDATE_PATH)
        return result.get("message") == "Authorized"

    def search_assets(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /vm/v4/integration/assets — paginated asset search with embedded findings."""
        return self._request_with_retry("POST", ASSETS_PATH, json=body)

    def get_asset(self, asset_id: str) -> Dict[str, Any]:
        """GET /vm/v4/integration/assets/{id} — single asset detail."""
        return self._request_with_retry("GET", f"{ASSETS_PATH}/{asset_id}")

    def search_vulnerabilities(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /vm/v4/integration/vulnerabilities — vulnerability catalogue search."""
        return self._request_with_retry("POST", VULNERABILITIES_PATH, json=body)
