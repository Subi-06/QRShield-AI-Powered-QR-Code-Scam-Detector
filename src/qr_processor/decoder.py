"""QR Code Decoder module for QRShield.

Handles QR code decoding from raw image bytes and camera frames using a multi-engine
fallback strategy (pyzbar -> OpenCV QRCodeDetector -> preprocessed image variants).
"""

from dataclasses import dataclass
import logging
from typing import List, Optional

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    cv2 = None
    CV2_AVAILABLE = False

import numpy as np

# Configure module logger
logger = logging.getLogger(__name__)

# Attempt pyzbar import gracefully
try:
    from pyzbar import pyzbar  # type: ignore

    PYZBAR_AVAILABLE = True
except (ImportError, Exception) as import_err:
    logger.warning(
        "pyzbar is not available (%s). Falling back to OpenCV QRCodeDetector only.",
        import_err,
    )
    pyzbar = None
    PYZBAR_AVAILABLE = False


@dataclass
class QRDecodeResult:
    """Dataclass encapsulating the result of a QR code decoding operation."""

    success: bool
    content: Optional[str] = None
    content_type: Optional[str] = None  # 'url', 'upi', 'text', 'vcard', 'wifi', 'email', 'phone', 'geo'
    error_message: Optional[str] = None
    decoder_used: Optional[str] = None  # 'pyzbar' or 'opencv'
    raw_bytes: Optional[bytes] = None


class QRDecoder:
    """Multi-stage QR Code Decoder supporting pyzbar, OpenCV, and preprocessed retries."""

    def __init__(self) -> None:
        """Initialize OpenCV QRCodeDetector and internal state."""
        self._cv_detector = cv2.QRCodeDetector() if (CV2_AVAILABLE and cv2 is not None) else None

    @staticmethod
    def detect_content_type(content: str) -> str:
        """Detect content payload type from the decoded string.

        Args:
            content: Decoded string payload.

        Returns:
            One of 'url', 'upi', 'vcard', 'wifi', 'email', 'phone', 'geo', or 'text'.
        """
        if not content:
            return "text"

        trimmed = content.strip()
        lower = trimmed.lower()
        upper = trimmed.upper()

        if lower.startswith(("http://", "https://")):
            return "url"
        if lower.startswith("upi://"):
            return "upi"
        if upper.startswith("BEGIN:VCARD"):
            return "vcard"
        if upper.startswith("WIFI:"):
            return "wifi"
        if lower.startswith("mailto:"):
            return "email"
        if lower.startswith("tel:"):
            return "phone"
        if lower.startswith("geo:"):
            return "geo"
        return "text"

    def preprocess_image(self, image: np.ndarray) -> List[np.ndarray]:
        """Generate multiple preprocessed variations of the input image to maximize detection.

        Variations returned:
        1. Original grayscale
        2. Adaptive threshold
        3. OTSU threshold
        4. Gaussian blur + OTSU threshold
        5. Contrast enhanced (CLAHE)

        Args:
            image: Grayscale or BGR/RGB numpy image array.

        Returns:
            List of preprocessed single-channel (grayscale) numpy arrays.
        """
        if image is None or image.size == 0:
            return []

        # Convert to grayscale if image has color channels
        if len(image.shape) == 3 and image.shape[2] in (3, 4):
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        elif len(image.shape) == 2:
            gray = image.copy()
        else:
            gray = image

        processed_images: List[np.ndarray] = []

        # 1. Original grayscale
        processed_images.append(gray)

        try:
            # 2. Adaptive threshold
            adaptive_thresh = cv2.adaptiveThreshold(
                gray,
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                11,
                2,
            )
            processed_images.append(adaptive_thresh)
        except Exception as e:
            logger.debug("Failed adaptive threshold preprocessing: %s", e)

        try:
            # 3. OTSU threshold
            _, otsu_thresh = cv2.threshold(
                gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
            )
            processed_images.append(otsu_thresh)
        except Exception as e:
            logger.debug("Failed OTSU threshold preprocessing: %s", e)

        try:
            # 4. Gaussian blur + threshold
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            _, blur_otsu = cv2.threshold(
                blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
            )
            processed_images.append(blur_otsu)
        except Exception as e:
            logger.debug("Failed Gaussian blur + OTSU threshold preprocessing: %s", e)

        try:
            # 5. Contrast enhanced (CLAHE)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            clahe_img = clahe.apply(gray)
            processed_images.append(clahe_img)
        except Exception as e:
            logger.debug("Failed CLAHE preprocessing: %s", e)

        return processed_images

    def _decode_with_pyzbar(self, img: np.ndarray) -> Optional[QRDecodeResult]:
        """Attempt QR decoding using pyzbar.

        Args:
            img: Image numpy array.

        Returns:
            QRDecodeResult if successfully decoded, None otherwise.
        """
        if not PYZBAR_AVAILABLE or pyzbar is None:
            return None

        try:
            decoded_objects = pyzbar.decode(img)
            for obj in decoded_objects:
                if obj.data:
                    raw_bytes = obj.data
                    content = raw_bytes.decode("utf-8", errors="replace")
                    content_type = self.detect_content_type(content)
                    return QRDecodeResult(
                        success=True,
                        content=content,
                        content_type=content_type,
                        decoder_used="pyzbar",
                        raw_bytes=raw_bytes,
                    )
        except Exception as e:
            logger.debug("pyzbar decoding encountered error: %s", e)

        return None

    def _decode_with_opencv(self, img: np.ndarray) -> Optional[QRDecodeResult]:
        """Attempt QR decoding using OpenCV's QRCodeDetector.

        Args:
            img: Image numpy array.

        Returns:
            QRDecodeResult if successfully decoded, None otherwise.
        """
        try:
            content, _, _ = self._cv_detector.detectAndDecode(img)
            if content and content.strip():
                content_str = content.strip()
                raw_bytes = content_str.encode("utf-8")
                content_type = self.detect_content_type(content_str)
                return QRDecodeResult(
                    success=True,
                    content=content_str,
                    content_type=content_type,
                    decoder_used="opencv",
                    raw_bytes=raw_bytes,
                )
        except Exception as e:
            logger.debug("OpenCV QRCodeDetector encountered error: %s", e)

        return None

    def _execute_decoding_pipeline(
        self, image: np.ndarray, gray: np.ndarray
    ) -> QRDecodeResult:
        """Run standard decoding pipeline: pyzbar -> OpenCV -> preprocessed variants.

        Args:
            image: Color or grayscale base image.
            gray: Grayscale converted image.

        Returns:
            QRDecodeResult with outcome.
        """
        # Step 3: Try pyzbar first on grayscale, then on color
        res = self._decode_with_pyzbar(gray)
        if res:
            return res

        if len(image.shape) == 3:
            res = self._decode_with_pyzbar(image)
            if res:
                return res

        # Step 4: If pyzbar fails or returns empty, try OpenCV's QRCodeDetector
        res = self._decode_with_opencv(gray)
        if res:
            return res

        if len(image.shape) == 3:
            res = self._decode_with_opencv(image)
            if res:
                return res

        # Step 5: If both fail, apply image preprocessing (thresholding, blur) and retry
        preprocessed_variants = self.preprocess_image(gray)
        for variant in preprocessed_variants:
            # Try pyzbar on preprocessed variant
            res = self._decode_with_pyzbar(variant)
            if res:
                return res

            # Try OpenCV on preprocessed variant
            res = self._decode_with_opencv(variant)
            if res:
                return res

        # If all attempts fail
        return QRDecodeResult(
            success=False,
            error_message="No QR code could be detected in the provided image after multiple enhancement stages.",
        )

    def decode_from_image(self, image_bytes: bytes) -> QRDecodeResult:
        """Decode a QR code from raw image bytes.

        Steps:
        1. Convert bytes to numpy array using cv2.imdecode
        2. Convert to grayscale
        3. Try pyzbar.decode() first
        4. If pyzbar fails or returns empty, try OpenCV's QRCodeDetector
        5. If both fail, apply image preprocessing (thresholding, blur) and retry
        6. Return QRDecodeResult dataclass

        Args:
            image_bytes: Raw bytes of the image file.

        Returns:
            QRDecodeResult with decoding outcome and payload.
        """
        if not image_bytes:
            return QRDecodeResult(
                success=False,
                error_message="Image bytes are empty or None.",
            )

        try:
            # 1. Convert bytes to numpy array using cv2.imdecode with UNCHANGED to keep alpha channel
            nparr = np.frombuffer(image_bytes, np.uint8)
            raw_img = cv2.imdecode(nparr, cv2.IMREAD_UNCHANGED)

            if raw_img is None or raw_img.size == 0:
                return QRDecodeResult(
                    success=False,
                    error_message="Failed to decode image: unsupported format or corrupt image data.",
                )

            # If PNG has alpha channel (4 channels), blend onto solid white background
            if len(raw_img.shape) == 3 and raw_img.shape[2] == 4:
                b, g, r, a = cv2.split(raw_img)
                alpha_factor = a.astype(float) / 255.0
                white_bg = np.ones_like(b, dtype=np.uint8) * 255
                b_out = (b * alpha_factor + white_bg * (1.0 - alpha_factor)).astype(np.uint8)
                g_out = (g * alpha_factor + white_bg * (1.0 - alpha_factor)).astype(np.uint8)
                r_out = (r * alpha_factor + white_bg * (1.0 - alpha_factor)).astype(np.uint8)
                image = cv2.merge([b_out, g_out, r_out])
            elif len(raw_img.shape) == 3 and raw_img.shape[2] == 3:
                image = raw_img
            else:
                image = cv2.cvtColor(raw_img, cv2.COLOR_GRAY2BGR)

            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

            # Run primary pipeline
            res = self._execute_decoding_pipeline(image=image, gray=gray)
            if res.success:
                return res

            # Fallback 1: Add white padding border (essential for tightly-cropped or transparent stock PNGs)
            padded = cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=[255, 255, 255])
            padded_color = cv2.copyMakeBorder(image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=[255, 255, 255])
            res_padded = self._execute_decoding_pipeline(image=padded_color, gray=padded)
            if res_padded.success:
                return res_padded

            # Fallback 2: Resize up/down if image is very small or very large
            h, w = gray.shape[:2]
            if max(h, w) < 300:
                scale_up = cv2.resize(padded, (w * 3, h * 3), interpolation=cv2.INTER_NEAREST)
                scale_color = cv2.resize(padded_color, (w * 3, h * 3), interpolation=cv2.INTER_NEAREST)
                res_scaled = self._execute_decoding_pipeline(image=scale_color, gray=scale_up)
                if res_scaled.success:
                    return res_scaled

            return res

        except Exception as e:
            logger.error("Unexpected error in decode_from_image: %s", e, exc_info=True)
            return QRDecodeResult(
                success=False,
                error_message=f"Error processing image: {str(e)}",
            )

    def decode_from_camera_frame(self, frame: np.ndarray) -> QRDecodeResult:
        """Decode a QR code directly from a camera frame numpy array.

        Args:
            frame: Camera frame as a numpy array.

        Returns:
            QRDecodeResult with decoding outcome and payload.
        """
        if frame is None or not isinstance(frame, np.ndarray) or frame.size == 0:
            return QRDecodeResult(
                success=False,
                error_message="Camera frame is invalid or empty.",
            )

        try:
            # Convert to grayscale if frame has color channels
            if len(frame.shape) == 3 and frame.shape[2] in (3, 4):
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            elif len(frame.shape) == 2:
                gray = frame.copy()
            else:
                gray = frame

            return self._execute_decoding_pipeline(image=frame, gray=gray)

        except Exception as e:
            logger.error("Unexpected error in decode_from_camera_frame: %s", e, exc_info=True)
            return QRDecodeResult(
                success=False,
                error_message=f"Error processing camera frame: {str(e)}",
            )
