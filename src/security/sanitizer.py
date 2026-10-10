"""Security sanitization module for QRShield AI application.

Provides input sanitization, URL validation, file upload verification,
SSRF protection, content type classification, and safe storage/display helpers.
"""

import html
import ipaddress
import os
from pathlib import Path
import re
import socket
from typing import Any, BinaryIO, Optional, Tuple, Union
import urllib.parse

import numpy as np

try:
    from config.settings import (
        ALLOWED_EXTENSIONS,
        MAX_FILE_SIZE_MB,
        MAX_IMAGE_DIMENSION,
    )
except ImportError:
    ALLOWED_EXTENSIONS = [".png", ".jpg", ".jpeg"]
    MAX_FILE_SIZE_MB = 10
    MAX_IMAGE_DIMENSION = 4096

# Magic byte signatures for image formats
MAGIC_BYTES_PNG: bytes = b"\x89PNG\r\n\x1a\n"
MAGIC_BYTES_JPEG: bytes = b"\xff\xd8\xff"

# Regex patterns for content type classification
REGEX_UPI: re.Pattern = re.compile(r"^upi://", re.IGNORECASE)
REGEX_WIFI: re.Pattern = re.compile(r"^wifi:", re.IGNORECASE)
REGEX_VCARD: re.Pattern = re.compile(r"BEGIN:VCARD", re.IGNORECASE)
REGEX_GEO: re.Pattern = re.compile(
    r"^geo:[-+]?[0-9]*\.?[0-9]+,[-+]?[0-9]*\.?[0-9]+", re.IGNORECASE
)
REGEX_EMAIL: re.Pattern = re.compile(
    r"^(?:mailto:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$",
    re.IGNORECASE,
)
REGEX_PHONE: re.Pattern = re.compile(
    r"^(?:tel:\+?[0-9\s\-()]{3,20}|\+?[0-9\s\-()]{7,20})$",
    re.IGNORECASE,
)
REGEX_URL: re.Pattern = re.compile(
    r"^(?:https?://|www\.)[^\s/$.?#].[^\s]*$",
    re.IGNORECASE,
)

# UPI sensitive query parameter names to redact
UPI_SENSITIVE_PARAMS = (
    "pin",
    "mpin",
    "otp",
    "secret",
    "password",
    "pwd",
    "token",
    "acc",
    "account",
    "accno",
    "accountno",
    "aadhaar",
    "cvv",
)


def escape_html(text: str) -> str:
    """HTML-escape untrusted text to prevent XSS.

    Args:
        text: Untrusted string input.

    Returns:
        HTML-escaped string with quotes converted.
    """
    if not text:
        return ""
    return html.escape(str(text), quote=True)


def is_safe_redirect(url: str) -> bool:
    """Check that URL uses http/https and does not resolve to private IPs.

    Protects against SSRF via redirects.

    Args:
        url: Redirect destination URL to evaluate.

    Returns:
        True if redirect URL is safe to follow, False otherwise.
    """
    if not url or not isinstance(url, str):
        return False

    cleaned_url = url.strip()
    try:
        parsed = urllib.parse.urlsplit(cleaned_url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        return not InputSanitizer.is_private_ip(hostname)
    except Exception:
        return False


class InputSanitizer:
    """Provides security controls, validation, and sanitization for QRShield."""

    @staticmethod
    def sanitize_text(text: str) -> str:
        """HTML-escape untrusted text, strip null bytes, and limit length to 10000 chars.

        Args:
            text: Untrusted text string.

        Returns:
            Sanitized, HTML-escaped string with maximum length of 10000 characters.
        """
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)

        cleaned = text.replace("\x00", "")[:10000]
        escaped = html.escape(cleaned, quote=True)
        return escaped[:10000]

    @staticmethod
    def sanitize_url(url: str) -> Optional[str]:
        """Validate and sanitize URLs.

        Only permits http and https schemes. Strips whitespace, rejects URLs
        with embedded credentials, and rejects data: and javascript: schemes.

        Args:
            url: URL string to sanitize.

        Returns:
            Sanitized URL string if valid, None if invalid or dangerous.
        """
        if not url or not isinstance(url, str):
            return None

        cleaned = url.strip()
        if not cleaned or "\x00" in cleaned:
            return None

        # Disallow control characters
        if re.search(r"[\r\n\t]", cleaned):
            return None

        try:
            parsed = urllib.parse.urlsplit(cleaned)
            scheme = parsed.scheme.lower()

            if scheme not in ("http", "https"):
                return None

            # Reject URLs with embedded credentials (user:pass@host)
            if parsed.username or parsed.password:
                return None

            # Reject empty hostname/netloc
            if not parsed.netloc or not parsed.hostname:
                return None

            return cleaned
        except Exception:
            return None

    @staticmethod
    def validate_image_upload(
        uploaded_file: Any,
    ) -> Tuple[bool, str]:
        """Validate uploaded file for safe processing.

        Checks file extension (.png, .jpg, .jpeg), file size (max 10MB),
        and verifies that magic bytes match the expected image format.

        Args:
            uploaded_file: File-like object, Streamlit UploadedFile, file path,
                or bytes.

        Returns:
            Tuple of (is_valid, error_message). On success, (True, "").
        """
        if uploaded_file is None:
            return False, "No file provided"

        # Determine filename
        filename = ""
        if hasattr(uploaded_file, "name"):
            filename = str(uploaded_file.name)
        elif isinstance(uploaded_file, (str, Path)):
            filename = str(uploaded_file)

        # Validate file extension
        ext = Path(filename).suffix.lower() if filename else ""
        if not ext or ext not in ALLOWED_EXTENSIONS:
            allowed_str = ", ".join(ALLOWED_EXTENSIONS)
            return False, f"Invalid file extension '{ext}'. Allowed extensions: {allowed_str}"

        max_size_bytes = MAX_FILE_SIZE_MB * 1024 * 1024

        # Determine file size
        file_size = None
        if hasattr(uploaded_file, "size"):
            file_size = uploaded_file.size
        elif hasattr(uploaded_file, "getbuffer"):
            file_size = len(uploaded_file.getbuffer())
        elif isinstance(uploaded_file, (str, Path)) and os.path.exists(uploaded_file):
            file_size = os.path.getsize(uploaded_file)
        elif isinstance(uploaded_file, bytes):
            file_size = len(uploaded_file)

        if file_size is not None and file_size > max_size_bytes:
            size_mb = file_size / (1024 * 1024)
            return (
                False,
                f"File size ({size_mb:.2f}MB) exceeds maximum limit of {MAX_FILE_SIZE_MB}MB",
            )

        # Read magic bytes
        header = b""
        try:
            if hasattr(uploaded_file, "read"):
                current_pos = uploaded_file.tell() if hasattr(uploaded_file, "tell") else 0
                header = uploaded_file.read(32)
                if hasattr(uploaded_file, "seek"):
                    uploaded_file.seek(current_pos)
            elif hasattr(uploaded_file, "getbuffer"):
                header = bytes(uploaded_file.getbuffer()[:32])
            elif isinstance(uploaded_file, (str, Path)) and os.path.exists(uploaded_file):
                with open(uploaded_file, "rb") as f:
                    header = f.read(32)
            elif isinstance(uploaded_file, bytes):
                header = uploaded_file[:32]
        except Exception as e:
            return False, f"Failed to read file header: {e}"

        # Verify magic bytes matching the file extension
        if ext == ".png":
            if not header.startswith(MAGIC_BYTES_PNG):
                return False, "File content does not match PNG format magic bytes"
        elif ext in (".jpg", ".jpeg"):
            if not header.startswith(MAGIC_BYTES_JPEG):
                return False, "File content does not match JPEG format magic bytes"

        return True, ""

    @staticmethod
    def validate_image_dimensions(image: np.ndarray) -> Tuple[bool, str]:
        """Check image dimensions do not exceed MAX_IMAGE_DIMENSION (4096x4096).

        Args:
            image: NumPy array representing decoded image.

        Returns:
            Tuple of (is_valid, error_message). On success, (True, "").
        """
        if not isinstance(image, np.ndarray):
            return False, "Invalid image object: expected numpy.ndarray"

        if image.ndim < 2:
            return False, "Invalid image dimensions: expected at least 2 dimensions"

        height, width = image.shape[:2]

        if height <= 0 or width <= 0:
            return False, "Image dimensions must be greater than 0"

        if height > MAX_IMAGE_DIMENSION or width > MAX_IMAGE_DIMENSION:
            return (
                False,
                f"Image dimensions ({width}x{height}) exceed maximum allowed dimensions of "
                f"{MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION}",
            )

        return True, ""

    @staticmethod
    def is_private_ip(hostname: str) -> bool:
        """Check if hostname resolves to private/internal IP ranges.

        Guards against Server-Side Request Forgery (SSRF) for ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.0/8 (loopback)
        - 169.254.0.0/16 (link-local)
        - ::1 (IPv6 loopback)
        - fc00::/7 (IPv6 Unique Local)
        - fe80::/10 (IPv6 link-local)
        - 0.0.0.0/8 & unspecified addresses

        Args:
            hostname: Domain name or IP address string.

        Returns:
            True if hostname is private/internal/loopback, False otherwise.
        """
        if not hostname or not isinstance(hostname, str):
            return True

        cleaned_host = hostname.strip().lower()

        # Handle IPv6 brackets and port stripping
        if cleaned_host.startswith("[") and "]" in cleaned_host:
            cleaned_host = cleaned_host[1 : cleaned_host.index("]")]
        elif ":" in cleaned_host and cleaned_host.count(":") == 1:
            cleaned_host = cleaned_host.split(":")[0]

        # Explicit loopback hostnames
        if cleaned_host in ("localhost", "localhost.localdomain", "broadcasthost"):
            return True

        # Check if direct IP literal
        try:
            ip = ipaddress.ip_address(cleaned_host)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            )
        except ValueError:
            pass

        # Resolve hostname via DNS
        try:
            addr_info = socket.getaddrinfo(cleaned_host, None)
            for _, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_reserved
                        or ip.is_multicast
                        or ip.is_unspecified
                    ):
                        return True
                except ValueError:
                    continue
        except (socket.gaierror, socket.herror, OSError):
            return False

        return False

    @staticmethod
    def sanitize_for_display(content: str, max_length: int = 500) -> str:
        """Prepare decoded QR content for safe display.

        Removes null bytes, truncates to maximum length with ellipsis,
        and escapes HTML to prevent XSS.

        Args:
            content: Decoded content string.
            max_length: Maximum allowed display length before truncation.

        Returns:
            Safe HTML-escaped string with ellipsis if truncated.
        """
        if not content or not isinstance(content, str):
            return ""

        cleaned = content.replace("\x00", "")
        if len(cleaned) > max_length:
            truncated = cleaned[:max_length] + "..."
        else:
            truncated = cleaned

        return html.escape(truncated, quote=True)

    @staticmethod
    def sanitize_for_storage(
        content: str, content_type: str, max_length: int = 4096
    ) -> str:
        """Prepare content for database storage.

        - For UPI content: Redacts sensitive fields (PINs, passwords, OTPs, accounts).
        - For URLs: Stores as-is (clean null bytes), truncated.
        - For other content: Escapes HTML and truncates.

        Args:
            content: Raw content string to store.
            content_type: Classification type ('upi', 'url', 'text', etc.).
            max_length: Maximum storage string length.

        Returns:
            Sanitized and appropriately redacted/escaped string.
        """
        if not content or not isinstance(content, str):
            return ""

        cleaned = content.replace("\x00", "")
        ctype = str(content_type).lower().strip()

        if ctype == "upi":
            # Redact sensitive parameters
            redacted = cleaned
            for param in UPI_SENSITIVE_PARAMS:
                redacted = re.sub(
                    rf"(?i)(?<=[?&]|\b)({param})=([^&]*)",
                    r"\1=***REDACTED***",
                    redacted,
                )
            return redacted[:max_length]

        if ctype == "url":
            return cleaned[:max_length]

        # For text and other content types: escape and truncate
        escaped = html.escape(cleaned, quote=True)
        return escaped[:max_length]

    @staticmethod
    def validate_content_type(content: str) -> str:
        """Classify content into supported QR payload categories.

        Classifications: 'url', 'upi', 'email', 'phone', 'text', 'vcard', 'wifi', 'geo'.

        Args:
            content: Decoded string content to classify.

        Returns:
            Content category string.
        """
        if not content or not isinstance(content, str):
            return "text"

        cleaned = content.strip()
        if not cleaned:
            return "text"

        if REGEX_UPI.match(cleaned):
            return "upi"

        if REGEX_WIFI.match(cleaned):
            return "wifi"

        if REGEX_VCARD.search(cleaned):
            return "vcard"

        if REGEX_GEO.match(cleaned):
            return "geo"

        if REGEX_EMAIL.match(cleaned):
            return "email"

        if REGEX_PHONE.match(cleaned) and any(c.isdigit() for c in cleaned):
            return "phone"

        if REGEX_URL.match(cleaned):
            return "url"

        return "text"
