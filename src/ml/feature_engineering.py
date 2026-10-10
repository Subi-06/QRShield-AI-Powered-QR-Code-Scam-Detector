"""URL feature engineering module for QRShield AI.

Extracts lexical, structural, and security features from URLs for threat
detection and machine learning model training and inference.
"""

from collections import Counter
import ipaddress
import math
from pathlib import Path
import re
import sys
from typing import Dict, List, Optional
import urllib.parse

import pandas as pd

# Handle imports whether package is installed or run directly
try:
    from config.settings import SUSPICIOUS_KEYWORDS, URL_SHORTENERS
except ImportError:
    # Add project root to sys.path if not present
    _project_root = str(Path(__file__).resolve().parent.parent.parent)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    from config.settings import SUSPICIOUS_KEYWORDS, URL_SHORTENERS


FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "is_https",
    "has_ip_address",
    "num_subdomains",
    "num_dots_hostname",
    "num_dots_url",
    "num_hyphens_hostname",
    "num_hyphens_url",
    "num_underscores_url",
    "num_slashes_url",
    "num_at_signs",
    "num_ampersands",
    "num_exclamation",
    "num_tilde",
    "num_percent",
    "num_digits_hostname",
    "num_digits_url",
    "digit_ratio_hostname",
    "digit_ratio_url",
    "has_port",
    "is_url_shortener",
    "num_suspicious_keywords",
    "has_suspicious_keyword",
    "hostname_has_digits",
    "path_has_double_slash",
    "has_encoded_chars",
    "special_char_ratio",
    "has_at_sign",
    "tld_length",
    "has_www",
    "url_entropy",
]

FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "url_length": "Total character count of the full URL string.",
    "hostname_length": "Length of the extracted hostname or domain.",
    "path_length": "Length of the URL path component.",
    "query_length": "Length of the URL query parameter string.",
    "fragment_length": "Length of the URL anchor/fragment component.",
    "is_https": "Binary flag (1.0 if URL uses HTTPS scheme, 0.0 otherwise).",
    "has_ip_address": "Binary flag (1.0 if hostname is an IPv4 or IPv6 address, 0.0 otherwise).",
    "num_subdomains": "Number of subdomain levels preceding the domain name.",
    "num_dots_hostname": "Count of period (.) characters in the hostname.",
    "num_dots_url": "Total count of period (.) characters in the full URL.",
    "num_hyphens_hostname": "Count of hyphen (-) characters in the hostname.",
    "num_hyphens_url": "Total count of hyphen (-) characters in the full URL.",
    "num_underscores_url": "Total count of underscore (_) characters in the full URL.",
    "num_slashes_url": "Total count of forward slash (/) characters in the full URL.",
    "num_at_signs": "Total count of at (@) signs in the URL (often used for credential trickery).",
    "num_ampersands": "Total count of ampersand (&) characters in the URL.",
    "num_exclamation": "Total count of exclamation marks (!) in the URL.",
    "num_tilde": "Total count of tilde (~) characters in the URL.",
    "num_percent": "Total count of percent (%) characters indicating URL encoding.",
    "num_digits_hostname": "Count of numerical digits present in the hostname.",
    "num_digits_url": "Total count of numerical digits present in the full URL.",
    "digit_ratio_hostname": "Proportion of numeric digit characters within the hostname.",
    "digit_ratio_url": "Proportion of numeric digit characters within the full URL.",
    "has_port": "Binary flag (1.0 if explicit non-standard port is specified, 0.0 otherwise).",
    "is_url_shortener": "Binary flag (1.0 if domain matches known URL shortening services, 0.0 otherwise).",
    "num_suspicious_keywords": "Total count of occurrences of known phishing/fraud keywords.",
    "has_suspicious_keyword": "Binary flag (1.0 if any suspicious keyword is found, 0.0 otherwise).",
    "hostname_has_digits": "Binary flag (1.0 if hostname contains any numeric digits, 0.0 otherwise).",
    "path_has_double_slash": "Binary flag (1.0 if URL path contains '//' redirection patterns, 0.0 otherwise).",
    "has_encoded_chars": "Binary flag (1.0 if URL contains percent-encoded hex patterns '%xx', 0.0 otherwise).",
    "special_char_ratio": "Proportion of non-alphanumeric special characters within the URL.",
    "has_at_sign": "Binary flag (1.0 if URL contains at least one '@' sign, 0.0 otherwise).",
    "tld_length": "Character length of the top-level domain (TLD).",
    "has_www": "Binary flag (1.0 if hostname begins with 'www', 0.0 otherwise).",
    "url_entropy": "Shannon entropy score measuring randomness/complexity of the URL string.",
}


def get_feature_descriptions() -> Dict[str, str]:
    """Return a mapping of feature names to human-readable descriptions.

    Returns:
        Dict[str, str]: Feature names mapped to their descriptions.
    """
    return dict(FEATURE_DESCRIPTIONS)


class URLFeatureExtractor:
    """Extractor for engineering numeric feature vectors from raw URLs."""

    def __init__(
        self,
        suspicious_keywords: Optional[List[str]] = None,
        url_shorteners: Optional[List[str]] = None,
    ) -> None:
        """Initialize the URL feature extractor.

        Args:
            suspicious_keywords: Optional custom list of suspicious keywords.
                Defaults to SUSPICIOUS_KEYWORDS from config.settings.
            url_shorteners: Optional custom list of known URL shortening domains.
                Defaults to URL_SHORTENERS from config.settings.
        """
        self.feature_names: List[str] = list(FEATURE_NAMES)
        self.suspicious_keywords: List[str] = (
            list(suspicious_keywords)
            if suspicious_keywords is not None
            else list(SUSPICIOUS_KEYWORDS)
        )
        self.url_shorteners: List[str] = (
            list(url_shorteners)
            if url_shorteners is not None
            else list(URL_SHORTENERS)
        )

    def get_feature_names(self) -> List[str]:
        """Return the ordered list of feature names.

        Returns:
            List[str]: Ordered list of feature names.
        """
        return list(self.feature_names)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the given text using math.log2.

        Args:
            text: Input string to evaluate.

        Returns:
            float: Shannon entropy value.
        """
        if not text:
            return 0.0
        length = len(text)
        freq = Counter(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        return float(entropy)

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is a valid IPv4 or IPv6 address.

        Args:
            hostname: Hostname string to check.

        Returns:
            bool: True if hostname is an IP address, False otherwise.
        """
        if not hostname:
            return False
        clean_host = hostname.strip("[]")
        try:
            ipaddress.ip_address(clean_host)
            return True
        except ValueError:
            return False

    def _get_tld(self, hostname: str) -> str:
        """Extract top-level domain from hostname.

        Args:
            hostname: Hostname string.

        Returns:
            str: Extracted TLD or empty string.
        """
        if not hostname or self._is_ip_address(hostname):
            return ""
        clean_host = hostname.strip().rstrip(".")
        parts = clean_host.split(".")
        if len(parts) > 1:
            return parts[-1].lower()
        return ""

    def _count_suspicious_keywords(self, url: str) -> int:
        """Count total occurrences of suspicious keywords in the URL.

        Args:
            url: Raw or normalized URL string.

        Returns:
            int: Number of suspicious keyword occurrences.
        """
        if not url:
            return 0
        url_lower = url.lower()
        return sum(url_lower.count(kw.lower()) for kw in self.suspicious_keywords)

    def _is_url_shortener(self, hostname: str) -> bool:
        """Determine if hostname matches a known URL shortener service.

        Args:
            hostname: Hostname to check.

        Returns:
            bool: True if hostname matches a known URL shortener.
        """
        if not hostname:
            return False
        host = hostname.lower().strip()
        if host.startswith("www."):
            host = host[4:]
        for shortener in self.url_shorteners:
            s = shortener.lower().strip()
            if host == s or host.endswith("." + s):
                return True
        return False

    def extract_features(self, url: str) -> Dict[str, float]:
        """Extract all 35 numeric features from a raw URL string.

        Handles malformed URLs gracefully by returning default numeric values.

        Args:
            url: The raw URL string to extract features from.

        Returns:
            Dict[str, float]: Dictionary mapping feature names to numeric values.
        """
        # Handle non-string or empty URL gracefully
        if not isinstance(url, str) or not url.strip():
            return {feature: 0.0 for feature in self.feature_names}

        raw_url = url.strip()
        url_len = len(raw_url)

        try:
            parsed = urllib.parse.urlsplit(raw_url)
            # If no scheme was present (e.g. 'example.com/login'), parse with netloc indicator
            if not parsed.scheme and not parsed.netloc:
                parsed_helper = urllib.parse.urlsplit(f"//{raw_url}")
                hostname = parsed_helper.hostname or ""
                path = parsed_helper.path or ""
                query = parsed_helper.query or ""
                fragment = parsed_helper.fragment or ""
                try:
                    port = parsed_helper.port
                except ValueError:
                    port = None
            else:
                hostname = parsed.hostname or ""
                path = parsed.path or ""
                query = parsed.query or ""
                fragment = parsed.fragment or ""
                try:
                    port = parsed.port
                except ValueError:
                    port = None
        except Exception:
            return {feature: 0.0 for feature in self.feature_names}

        # Normalize hostname for feature evaluation
        hostname_lower = hostname.lower()

        # 1. url_length
        url_length = float(url_len)

        # 2. hostname_length
        hostname_length = float(len(hostname))

        # 3. path_length
        path_length = float(len(path))

        # 4. query_length
        query_length = float(len(query))

        # 5. fragment_length
        fragment_length = float(len(fragment))

        # 6. is_https (1 if https, 0 otherwise)
        is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0

        # 7. has_ip_address
        is_ip = self._is_ip_address(hostname)
        has_ip_address = 1.0 if is_ip else 0.0

        # 8. num_subdomains (e.g., a.b.example.com = 2 subdomains)
        if is_ip or not hostname:
            num_subdomains = 0.0
        else:
            clean_host = hostname_lower.rstrip(".")
            parts = clean_host.split(".")
            num_subdomains = float(max(0, len(parts) - 2))

        # 9. num_dots_hostname
        num_dots_hostname = float(hostname.count("."))

        # 10. num_dots_url
        num_dots_url = float(raw_url.count("."))

        # 11. num_hyphens_hostname
        num_hyphens_hostname = float(hostname.count("-"))

        # 12. num_hyphens_url
        num_hyphens_url = float(raw_url.count("-"))

        # 13. num_underscores_url
        num_underscores_url = float(raw_url.count("_"))

        # 14. num_slashes_url
        num_slashes_url = float(raw_url.count("/"))

        # 15. num_at_signs
        num_at_signs = float(raw_url.count("@"))

        # 16. num_ampersands
        num_ampersands = float(raw_url.count("&"))

        # 17. num_exclamation
        num_exclamation = float(raw_url.count("!"))

        # 18. num_tilde
        num_tilde = float(raw_url.count("~"))

        # 19. num_percent
        num_percent = float(raw_url.count("%"))

        # 20. num_digits_hostname
        num_digits_hostname = float(sum(c.isdigit() for c in hostname))

        # 21. num_digits_url
        num_digits_url = float(sum(c.isdigit() for c in raw_url))

        # 22. digit_ratio_hostname
        digit_ratio_hostname = (
            float(num_digits_hostname / len(hostname)) if hostname else 0.0
        )

        # 23. digit_ratio_url
        digit_ratio_url = (
            float(num_digits_url / url_len) if url_len > 0 else 0.0
        )

        # 24. has_port (1 if explicit port is present, not default 80/443)
        has_port = (
            1.0 if (port is not None and port not in (80, 443)) else 0.0
        )

        # 25. is_url_shortener
        is_url_shortener = 1.0 if self._is_url_shortener(hostname) else 0.0

        # 26. num_suspicious_keywords
        kw_count = self._count_suspicious_keywords(raw_url)
        num_suspicious_keywords = float(kw_count)

        # 27. has_suspicious_keyword
        has_suspicious_keyword = 1.0 if kw_count > 0 else 0.0

        # 28. hostname_has_digits
        hostname_has_digits = 1.0 if num_digits_hostname > 0 else 0.0

        # 29. path_has_double_slash
        path_has_double_slash = 1.0 if "//" in path else 0.0

        # 30. has_encoded_chars (%xx patterns)
        has_encoded_chars = 1.0 if bool(re.search(r"%[0-9a-fA-F]{2}", raw_url)) else 0.0

        # 31. special_char_ratio
        special_char_count = sum(not c.isalnum() for c in raw_url)
        special_char_ratio = (
            float(special_char_count / url_len) if url_len > 0 else 0.0
        )

        # 32. has_at_sign
        has_at_sign = 1.0 if "@" in raw_url else 0.0

        # 33. tld_length
        tld = self._get_tld(hostname)
        tld_length = float(len(tld))

        # 34. has_www
        has_www = 1.0 if hostname_lower.startswith("www") else 0.0

        # 35. url_entropy
        url_entropy = self._calculate_entropy(raw_url)

        return {
            "url_length": url_length,
            "hostname_length": hostname_length,
            "path_length": path_length,
            "query_length": query_length,
            "fragment_length": fragment_length,
            "is_https": is_https,
            "has_ip_address": has_ip_address,
            "num_subdomains": num_subdomains,
            "num_dots_hostname": num_dots_hostname,
            "num_dots_url": num_dots_url,
            "num_hyphens_hostname": num_hyphens_hostname,
            "num_hyphens_url": num_hyphens_url,
            "num_underscores_url": num_underscores_url,
            "num_slashes_url": num_slashes_url,
            "num_at_signs": num_at_signs,
            "num_ampersands": num_ampersands,
            "num_exclamation": num_exclamation,
            "num_tilde": num_tilde,
            "num_percent": num_percent,
            "num_digits_hostname": num_digits_hostname,
            "num_digits_url": num_digits_url,
            "digit_ratio_hostname": digit_ratio_hostname,
            "digit_ratio_url": digit_ratio_url,
            "has_port": has_port,
            "is_url_shortener": is_url_shortener,
            "num_suspicious_keywords": num_suspicious_keywords,
            "has_suspicious_keyword": has_suspicious_keyword,
            "hostname_has_digits": hostname_has_digits,
            "path_has_double_slash": path_has_double_slash,
            "has_encoded_chars": has_encoded_chars,
            "special_char_ratio": special_char_ratio,
            "has_at_sign": has_at_sign,
            "tld_length": tld_length,
            "has_www": has_www,
            "url_entropy": url_entropy,
        }

    def extract_features_dataframe(self, urls: List[str]) -> pd.DataFrame:
        """Extract features for a list of URLs and return a DataFrame.

        The returned DataFrame maintains consistent column ordering matching
        `get_feature_names()`.

        Args:
            urls: List or sequence of raw URL strings.

        Returns:
            pd.DataFrame: DataFrame containing numeric feature values for each URL.
        """
        if not urls:
            return pd.DataFrame(columns=self.feature_names)

        records = [self.extract_features(url) for url in urls]
        df = pd.DataFrame.from_records(records)
        return df[self.feature_names]
