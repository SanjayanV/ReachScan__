"""
image_handler.py — User-uploaded image processor.

VULNERABILITY: No size or bomb check before Image.open().
CVE-2022-22817 (Pillow): Decompression bomb attack leading to DoS.

Call chain: main() → process_image() → Image.open()
"""

from PIL import Image


# Maximum pixel dimensions we accept (should be enforced BEFORE open())
MAX_PIXELS = 10_000 * 10_000


def process_image(image_path: str) -> dict:
    """
    Open and inspect a user-supplied image file.

    ⚠️  VULNERABLE: Image.open() is called with no prior size check.
    A crafted image (decompression bomb) can exhaust memory and crash
    the process.  CVE-2022-22817.

    Fix: Use PIL.Image.MAX_IMAGE_PIXELS = MAX_PIXELS before opening,
    or check file size / image dimensions before calling Image.open().
    """
    # SINK: Image.open — CVE-2022-22817
    img = Image.open(image_path)  # noqa

    width, height = img.size
    mode = img.mode

    # Convert to RGB for uniform downstream processing
    if mode != "RGB":
        img = img.convert("RGB")

    return {
        "width": width,
        "height": height,
        "mode": mode,
        "format": img.format,
    }


def generate_thumbnail(image_path: str, size: tuple = (128, 128)) -> Image.Image:
    """
    Create a thumbnail from an uploaded image.

    ⚠️  Also calls Image.open() — same CVE applies.
    Call chain: main() → generate_thumbnail() → Image.open()
    """
    # SINK: Image.open — CVE-2022-22817
    img = Image.open(image_path)  # noqa
    img.thumbnail(size)
    return img
