import os


# --------------------------------
# SUSPICIOUS EXTENSIONS
# --------------------------------

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".msi",
    ".jar",
    ".hta"
}


def analyze_attachment(part):
    """
    Analyze attachment metadata safely.

    This function does NOT execute or open
    the attachment contents.
    """

    filename = part.get_filename()

    content_type = part.get_content_type()

    payload = part.get_payload(
        decode=True
    )

    if payload is None:

        size = 0

    else:

        size = len(payload)

    extension = ""

    if filename:

        extension = os.path.splitext(
            filename
        )[1].lower()

    # --------------------------------
    # SECURITY INDICATORS
    # --------------------------------

    suspicious_extension = (
        extension in SUSPICIOUS_EXTENSIONS
    )

    double_extension = False

    if filename:

        filename_lower = filename.lower()

        suspicious_names = [
            ".pdf.exe",
            ".doc.exe",
            ".docx.exe",
            ".xls.exe",
            ".xlsx.exe",
            ".jpg.exe",
            ".png.exe",
            ".txt.exe"
        ]

        double_extension = any(
            filename_lower.endswith(name)
            for name in suspicious_names
        )

    indicators = {
        "suspicious_extension": suspicious_extension,
        "double_extension": double_extension
    }

    return {
        "filename": filename,
        "extension": extension,
        "content_type": content_type,
        "size_bytes": size,
        "indicators": indicators
    }


def extract_attachments(message):
    """
    Find attachments in an email message
    and return their metadata and indicators.
    """

    attachments = []

    for part in message.walk():

        if part.get_content_disposition() == "attachment":

            attachment = analyze_attachment(
                part
            )

            attachments.append(
                attachment
            )

    return attachments


if __name__ == "__main__":

    print(
        "=== ATTACHMENT ANALYZER ==="
    )

    print(
        "Attachment analyzer loaded successfully."
    )