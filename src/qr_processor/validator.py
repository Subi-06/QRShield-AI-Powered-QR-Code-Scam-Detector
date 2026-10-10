"""Image validation module for QRShield.

Validates uploaded files for allowed extensions, file size limits, magic bytes integrity,
and image dimension boundaries before processing.
"""

import logging
from pathlib import Path
import sys
from typing import Any, Optional, Tuple

import numpy as np

# Ensure project root is in sys.path for config import
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from config.settings import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_MB, MAX_IMAGE_DIMENSION
except ImportError:
    # Fallback default values matching config/settings.py
    ALLOWED_EXTENSIONS = [".png", ".jpg", ".jpeg"]
    MAX_FILE_SIZE_MB = 10
    MAX_IMAGE_DIMENSION = 4096

logger = logging.getLogger(__name__)

# Magic byte signatures
PNG_MAGIC_BYTES = bytes.fromhex("89504E47")
JPG_MAGIC_BYTES = bytes.fromhex("FFD8FF")


class ImageValidator:
    """Validates user-uploaded image files and image dimensions for QR processing."""

    def __init__(
        self,
        allowed_extensions: Optional[list] = None,
        max_file_size_mb: Optional[int] = None,
        max_image_dimension: Optional[int] = None,
    ) -> None:
        """Initialize validator with configurable limits.

        Args:
            allowed_extensions: List of allowed file extensions (e.g. ['.png', '.jpg']).
            max_file_size_mb: Maximum allowed file size in megabytes.
            max_image_dimension: Maximum allowed width or height in pixels.
        """
        self.allowed_extensions = (
            [ext.lower() for ext in allowed_extensions]
            if allowed_extensions is not None
            else [ext.lower() for ext in ALLOWED_EXTENSIONS]
        )
        self.max_file_size_mb = (
            max_file_size_mb if max_file_size_mb is not None else MAX_FILE_SIZE_MB
        )
        self.max_bytes = self.max_file_size_mb * 1024 * 1024
        self.max_image_dimension = (
            max_image_dimension
            if max_image_dimension is not None
            else MAX_IMAGE_DIMENSION
        )

    def validate_upload(
        self, uploaded_file: Any
    ) -> Tuple[bool, str, Optional[bytes]]:
        """Validate an uploaded file object, path, or bytes.

        Checks:
        1. File is not None
        2. File extension is in ALLOWED_EXTENSIONS
        3. File size <= MAX_FILE_SIZE_MB
        4. File magic bytes verify as PNG (89504E47) or JPG (FFD8FF)

        Args:
            uploaded_file: Streamlit UploadedFile, file-like object, Path, str, or bytes.

        Returns:
            Tuple containing:
            - is_valid (bool): True if file passed all checks, False otherwise.
            - error_message (str): Reason for failure if invalid, empty string if valid.
            - file_bytes (Optional[bytes]): The verified file bytes if valid, None otherwise.
        """
        # 1. Check file is not None
        if uploaded_file is None:
            return False, "No file provided.", None

        # Determine file name
        filename: Optional[str] = None
        if hasattr(uploaded_file, "name") and isinstance(uploaded_file.name, str):
            filename = uploaded_file.name
        elif hasattr(uploaded_file, "filename") and isinstance(
            uploaded_file.filename, str
        ):
            filename = uploaded_file.filename
        elif isinstance(uploaded_file, (str, Path)):
            filename = str(uploaded_file)

        # 2. Check file extension is in ALLOWED_EXTENSIONS
        if filename:
            file_suffix = Path(filename).suffix.lower()
            if not file_suffix:
                return (
                    False,
                    f"Uploaded file '{filename}' has no extension. Allowed extensions: {', '.join(self.allowed_extensions)}",
                    None,
                )
            if file_suffix not in self.allowed_extensions:
                return (
                    False,
                    f"Unsupported file extension '{file_suffix}'. Allowed extensions: {', '.join(self.allowed_extensions)}",
                    None,
                )
        else:
            # If no filename attribute exists, check if it's raw bytes or file-like
            if not hasattr(uploaded_file, "read") and not isinstance(
                uploaded_file, (bytes, bytearray)
            ):
                return False, "Invalid file object: unable to determine file name.", None

        # Check preliminary size attribute if present
        if hasattr(uploaded_file, "size") and isinstance(uploaded_file.size, (int, float)):
            if uploaded_file.size > self.max_bytes:
                return (
                    False,
                    f"File size ({uploaded_file.size / (1024 * 1024):.2f}MB) exceeds limit of {self.max_file_size_mb}MB.",
                    None,
                )

        # Read file bytes
        file_bytes: bytes
        try:
            if hasattr(uploaded_file, "getvalue") and callable(uploaded_file.getvalue):
                file_bytes = uploaded_file.getvalue()
            elif hasattr(uploaded_file, "read") and callable(uploaded_file.read):
                file_bytes = uploaded_file.read()
                # Reset stream position if seekable
                if hasattr(uploaded_file, "seek") and callable(uploaded_file.seek):
                    uploaded_file.seek(0)
            elif isinstance(uploaded_file, (str, Path)):
                file_path = Path(uploaded_file)
                if not file_path.is_file():
                    return False, f"File not found: {uploaded_file}", None
                file_bytes = file_path.read_bytes()
            elif isinstance(uploaded_file, (bytes, bytearray)):
                file_bytes = bytes(uploaded_file)
            else:
                return False, "Unsupported file format or unreadable stream.", None
        except Exception as e:
            logger.error("Failed to read file bytes: %s", e)
            return False, f"Failed to read file: {str(e)}", None

        # Check if bytes are empty
        if not file_bytes:
            return False, "Uploaded file is empty (0 bytes).", None

        # 3. Check file size <= MAX_FILE_SIZE_MB
        if len(file_bytes) > self.max_bytes:
            return (
                False,
                f"File size ({len(file_bytes) / (1024 * 1024):.2f}MB) exceeds limit of {self.max_file_size_mb}MB.",
                None,
            )

        # 4. Read bytes and verify magic bytes (PNG: 89504E47, JPG: FFD8FF)
        is_png = file_bytes.startswith(PNG_MAGIC_BYTES)
        is_jpg = file_bytes.startswith(JPG_MAGIC_BYTES)

        if not (is_png or is_jpg):
            return (
                False,
                "Invalid image format: file contents do not match PNG (89504E47) or JPG (FFD8FF) magic bytes.",
                None,
            )

        # Validate matching extension with detected magic bytes if filename is known
        if filename:
            file_suffix = Path(filename).suffix.lower()
            if is_png and file_suffix not in [".png"]:
                return (
                    False,
                    f"File extension '{file_suffix}' does not match PNG file signature.",
                    None,
                )
            if is_jpg and file_suffix not in [".jpg", ".jpeg"]:
                return (
                    False,
                    f"File extension '{file_suffix}' does not match JPEG file signature.",
                    None,
                )

        return True, "", file_bytes

    def validate_dimensions(self, image: np.ndarray) -> Tuple[bool, str]:
        """Validate dimensions of an image numpy array.

        Checks:
        1. Image dimensions do not exceed MAX_IMAGE_DIMENSION
        2. Image is not too small (< 10x10)

        Args:
            image: Image as a numpy array.

        Returns:
            Tuple containing:
            - is_valid (bool): True if dimensions are within valid range, False otherwise.
            - error_message (str): Error message describing violation, empty if valid.
        """
        if image is None or not isinstance(image, np.ndarray) or image.size == 0:
            return False, "Image array is invalid or empty."

        if len(image.shape) < 2:
            return False, "Image array must have at least 2 dimensions (height, width)."

        height, width = image.shape[:2]

        # Check minimum dimensions (10x10)
        if width < 10 or height < 10:
            return (
                False,
                f"Image dimensions ({width}x{height}) are too small. Minimum required dimension is 10x10 pixels.",
            )

        # Check maximum dimensions (MAX_IMAGE_DIMENSION)
        if width > self.max_image_dimension or height > self.max_image_dimension:
            return (
                False,
                f"Image dimensions ({width}x{height}) exceed maximum allowed dimension of {self.max_image_dimension} pixels.",
            )

        return True, ""
