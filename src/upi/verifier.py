"""
UPI Payment QR Code Verification Module.

This module provides rule-based verification and safety analysis for UPI (Unified
Payments Interface) QR codes and URIs. It is strictly rule-based and does NOT
perform ML classification or connect to banking APIs.

Standard UPI URI Format:
    upi://pay?pa=<payee_address>&pn=<payee_name>&am=<amount>&cu=<currency>&tr=<transaction_ref>&tn=<transaction_note>&mc=<merchant_code>&tid=<transaction_id>&url=<url>
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class UPIPaymentInfo:
    """Structured representation of parsed UPI payment parameters."""

    payee_address: Optional[str]  # UPI ID (e.g., merchant@upi)
    payee_name: Optional[str]
    amount: Optional[float]
    currency: Optional[str]
    transaction_ref: Optional[str]
    transaction_note: Optional[str]
    merchant_code: Optional[str]
    transaction_id: Optional[str]
    url: Optional[str]
    raw_uri: str
    extra_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class UPIVerificationResult:
    """Result of rule-based verification on a UPI payment URI."""

    payment_info: UPIPaymentInfo
    status: str  # 'verification_required', 'info_incomplete', 'potential_concern'
    concerns: List[str]
    warnings: List[str]
    info_messages: List[str]
    risk_level: str  # 'low', 'medium', 'high'
    recommendations: List[str]


class UPIVerifier:
    """
    Rule-based verifier for UPI payment QR codes and deep links.

    Performs structural, syntactical, and heuristic anomaly checks to highlight
    safety concerns before any payment interaction.
    """

    # Common and recognized Payment Service Provider (PSP) / Bank handles in India
    KNOWN_PSP_HANDLES: Set[str] = {
        "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "ybl", "ibl", "axl",
        "barodampay", "upi", "postbank", "idfcbank", "federal", "airtel", "icici",
        "hdfcbank", "sbi", "kotak", "indus", "pnb", "cnrb", "unionbank", "aubank",
        "equitas", "jupiteraxis", "freecharge", "amazonpay", "apl", "rapl", "waaxis",
        "wahdfcbank", "waicici", "wasbi", "sliceaxis", "tapicici", "timecosmos",
        "pingpay", "kmbl", "boi", "citi", "sc", "hsbc", "dbs", "rbl", "yesbank",
    }

    # Standard UPI query parameters defined by NPCI specification
    STANDARD_UPI_PARAMS: Set[str] = {
        "pa", "pn", "am", "cu", "tr", "tn", "mc", "tid", "url",
        "mam", "mode", "purpose", "orgid", "sign", "mid", "msid", "mtid",
    }

    # High-risk social engineering / phishing keywords in notes
    SUSPICIOUS_NOTE_KEYWORDS: Set[str] = {
        "lottery", "prize", "won", "winner", "reward", "cashback", "refund",
        "bonus", "gift", "kyc", "kyc update", "urgent", "verify pin", "claim",
        "free", "congratulations", "lucky draw", "income tax refund", "electricity bill",
        "overdue", "account blocked", "unblock",
    }

    # Common generic names that obscure actual recipient identity
    GENERIC_NAMES: Set[str] = {
        "user", "admin", "payment", "cash", "upi", "merchant", "customer",
        "pay", "bill", "official", "support", "helpdesk", "care", "service",
    }

    DISCLAIMER_NOTE: str = (
        "This analysis is based on the QR code content only. "
        "Verify the recipient independently before making any payment."
    )

    def parse_upi_uri(self, uri: str) -> Optional[UPIPaymentInfo]:
        """
        Parse a raw URI string into a UPIPaymentInfo object.

        Args:
            uri: Raw string extracted from a QR code or payment link.

        Returns:
            UPIPaymentInfo if the URI is a valid UPI scheme, or None otherwise.
        """
        if not uri or not isinstance(uri, str):
            return None

        clean_uri = uri.strip()

        # Parse URI
        try:
            parsed = urllib.parse.urlparse(clean_uri)
        except Exception:
            return None

        # Check scheme and netloc/path for UPI structure (upi://pay or upi:pay)
        scheme = parsed.scheme.lower()
        if scheme != "upi":
            return None

        # In standard upi://pay?... netloc is 'pay' and path is empty or '/'
        # In upi:pay?... path is 'pay'
        action = (parsed.netloc or parsed.path).strip("/").lower()
        if action != "pay":
            return None

        query_str = parsed.query
        if not query_str and "?" in clean_uri:
            # Handle cases where urllib didn't split query cleanly
            query_str = clean_uri.split("?", 1)[1]

        params = urllib.parse.parse_qs(query_str, keep_blank_values=True)

        def get_single(key: str) -> Optional[str]:
            val = params.get(key)
            if val and len(val) > 0 and val[0].strip() != "":
                return val[0].strip()
            return None

        # Parse amount as float if valid
        amount_str = get_single("am")
        amount: Optional[float] = None
        if amount_str is not None:
            try:
                amount = float(amount_str)
            except (ValueError, TypeError):
                amount = None

        # Extract extra/non-standard params
        extra_params: Dict[str, str] = {}
        for k, v in params.items():
            if k.lower() not in self.STANDARD_UPI_PARAMS and v:
                extra_params[k] = v[0]

        return UPIPaymentInfo(
            payee_address=get_single("pa"),
            payee_name=get_single("pn"),
            amount=amount,
            currency=get_single("cu"),
            transaction_ref=get_single("tr"),
            transaction_note=get_single("tn"),
            merchant_code=get_single("mc"),
            transaction_id=get_single("tid"),
            url=get_single("url"),
            raw_uri=clean_uri,
            extra_params=extra_params,
        )

    def _determine_status(
        self, concerns: List[str], warnings: List[str]
    ) -> Tuple[str, str]:
        """
        Determine overall verification status and risk level.

        Args:
            concerns: List of critical security or validity issues found.
            warnings: List of cautionary warnings found.

        Returns:
            Tuple of (status, risk_level) where:
                status: 'potential_concern', 'info_incomplete', or 'verification_required'
                risk_level: 'high', 'medium', or 'low'
        """
        if len(concerns) > 0:
            return "potential_concern", "high"

        if len(warnings) >= 2:
            return "potential_concern", "medium"
        elif len(warnings) == 1:
            return "info_incomplete", "medium"

        return "verification_required", "low"

    def verify(self, uri: str) -> UPIVerificationResult:
        """
        Run comprehensive rule-based checks on the provided UPI URI.

        Args:
            uri: Raw UPI QR code payload or payment URI.

        Returns:
            UPIVerificationResult detailing safety findings, status, and recommendations.
        """
        concerns: List[str] = []
        warnings: List[str] = []
        info_messages: List[str] = []
        recommendations: List[str] = []

        payment_info = self.parse_upi_uri(uri)

        # Check: Valid UPI URI structure
        if payment_info is None:
            concerns.append("Payload is not a valid UPI payment URI (expected 'upi://pay?...').")
            empty_info = UPIPaymentInfo(
                payee_address=None,
                payee_name=None,
                amount=None,
                currency=None,
                transaction_ref=None,
                transaction_note=None,
                merchant_code=None,
                transaction_id=None,
                url=None,
                raw_uri=str(uri or ""),
            )
            recommendations.extend([
                self.DISCLAIMER_NOTE,
                "Do not attempt payment with invalid or malformed QR codes.",
            ])
            return UPIVerificationResult(
                payment_info=empty_info,
                status="potential_concern",
                concerns=concerns,
                warnings=warnings,
                info_messages=info_messages,
                risk_level="high",
                recommendations=recommendations,
            )

        # 1. Payee Address (pa) Validation
        pa = payment_info.payee_address
        if not pa:
            concerns.append("Missing mandatory payee address ('pa'). Payment cannot be routed.")
        else:
            if "@" not in pa:
                concerns.append(f"Invalid UPI ID format ('{pa}'): missing '@' symbol.")
            else:
                parts = pa.split("@", 1)
                user_part, handle = parts[0].strip(), parts[1].strip().lower()

                if not user_part:
                    concerns.append(f"Invalid UPI ID ('{pa}'): empty username before '@'.")
                if not handle:
                    concerns.append(f"Invalid UPI ID ('{pa}'): empty PSP handle after '@'.")

                # Check for suspicious patterns in username: excessive digits or pure random-looking strings
                if len(user_part) > 25:
                    warnings.append(
                        f"Unusually long payee handle username ('{user_part[:15]}...')."
                    )
                if user_part.isdigit() and len(user_part) > 12:
                    warnings.append(
                        "Payee address consists of an unusually long numeric sequence."
                    )

                # Heuristic: Detect characters not typical in standard UPI IDs
                if not re.match(r"^[a-zA-Z0-9.\-_]+$", user_part):
                    warnings.append(
                        f"Payee address username contains non-standard characters: '{user_part}'."
                    )

                # Check if handle is known PSP
                if handle and handle not in self.KNOWN_PSP_HANDLES:
                    info_messages.append(
                        f"Payee handle '@{handle}' is not in the common PSP bank list. Ensure this corresponds to an authorized PSP."
                    )

        # 2. Amount Validation
        # Check raw query for amount format (e.g. multiple decimals or negative)
        raw_parsed = urllib.parse.parse_qs(urllib.parse.urlparse(payment_info.raw_uri).query)
        raw_am_list = raw_parsed.get("am")
        if raw_am_list:
            raw_am = raw_am_list[0].strip()
            try:
                parsed_float = float(raw_am)
                if parsed_float <= 0:
                    concerns.append(f"Invalid amount specified ({parsed_float}). Amount must be strictly positive.")
                elif parsed_float > 50000.0:
                    warnings.append(
                        f"Unusually high preset payment amount: INR {parsed_float:,.2f} (> 50,000 threshold)."
                    )

                # Check decimal precision
                if "." in raw_am:
                    decimals = len(raw_am.split(".", 1)[1])
                    if decimals > 2:
                        warnings.append(
                            f"Amount has abnormal decimal precision ({decimals} decimal places: '{raw_am}')."
                        )
            except ValueError:
                concerns.append(f"Amount parameter ('am={raw_am}') is not a valid numeric value.")
        else:
            info_messages.append("No preset amount specified. Payer must manually enter the amount.")

        # 3. Currency Validation
        cu = payment_info.currency
        if cu:
            cu_upper = cu.strip().upper()
            if cu_upper != "INR":
                concerns.append(f"Unrecognized or non-standard UPI currency '{cu}' (expected 'INR').")
            else:
                info_messages.append("Currency specified as INR.")
        else:
            info_messages.append("Currency parameter ('cu') omitted (defaults to INR in standard UPI apps).")

        # 4. Payee Name Checks
        pn = payment_info.payee_name
        if not pn:
            warnings.append("Payee name ('pn') is missing. Recipient identity cannot be previewed from QR.")
        else:
            clean_pn = pn.strip()
            if len(clean_pn) < 2:
                warnings.append(f"Payee name is suspiciously short ('{clean_pn}').")
            elif clean_pn.lower() in self.GENERIC_NAMES:
                warnings.append(f"Payee name appears generic or uninformative ('{clean_pn}').")

            # Check potential impersonation or name-address discrepancy
            if pa and "@" in pa:
                user_lower = pa.split("@")[0].lower()
                # If name claims to be official bank/utility but user part is arbitrary numeric or random
                high_trust_keywords = ["bank", "support", "refund", "official", "care", "tax", "police"]
                name_lower = clean_pn.lower()
                for kw in high_trust_keywords:
                    if kw in name_lower and kw not in user_lower and user_lower.isdigit():
                        warnings.append(
                            f"Potential mismatch: Payee name claims '{clean_pn}' while address is purely numeric ('{pa}')."
                        )
                        break

        # 5. URL Field Check
        if payment_info.url:
            concerns.append(
                f"Contains embedded external URL parameter ('{payment_info.url}'). "
                "Embedded URLs pose phishing and malicious redirection risks."
            )

        # 6. General / Transaction Note Checks
        tn = payment_info.transaction_note
        if tn:
            tn_lower = tn.lower()
            found_keywords = [
                kw for kw in self.SUSPICIOUS_NOTE_KEYWORDS if kw in tn_lower
            ]
            if found_keywords:
                warnings.append(
                    f"Transaction note contains high-risk/phishing keywords: {', '.join(repr(k) for k in found_keywords)}."
                )

        # Extra non-standard parameters
        if payment_info.extra_params:
            extra_keys = list(payment_info.extra_params.keys())
            info_messages.append(
                f"Non-standard parameters detected in URI: {', '.join(extra_keys)}."
            )

        # Merchant Code Info
        if payment_info.merchant_code:
            info_messages.append(f"Merchant Category Code (MCC) present: '{payment_info.merchant_code}'.")

        # Determine overall status and risk level
        status, risk_level = self._determine_status(concerns, warnings)

        # Standard recommendations & disclaimers
        recommendations.append(self.DISCLAIMER_NOTE)
        recommendations.append(
            "Always verify the payee name and UPI ID displayed by your official banking app before authorizing payment."
        )
        recommendations.append(
            "Entering your UPI PIN always DEBITS money from your account. Never enter your PIN to receive money or refunds."
        )

        if payment_info.url:
            recommendations.append(
                "Do NOT click or navigate to the embedded URL included in the QR parameters."
            )

        if risk_level == "high":
            recommendations.append(
                "Caution: Significant security or structural anomalies detected. Proceed with extreme caution."
            )

        return UPIVerificationResult(
            payment_info=payment_info,
            status=status,
            concerns=concerns,
            warnings=warnings,
            info_messages=info_messages,
            risk_level=risk_level,
            recommendations=recommendations,
        )
