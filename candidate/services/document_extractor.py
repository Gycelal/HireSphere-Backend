import io
import requests
import pdfplumber 
import docx


def extract_text(file_url: str) -> str:
    """
    Downloads file from the URL (Cloudinary) and extracts text from it based on its format.
    Handles corruption, invalid syntax, and unreadable scanned files.
    """
    try:
        response = requests.get(file_url, timeout=10)
        response.raise_for_status()
        file_bytes = response.content
    except Exception:
        raise ValueError("Failed to download the file from the provided URL.")

    clean_url = file_url.split("?")[0].lower()

    try:
        if clean_url.endswith(".pdf"):
            text = _extract_text_from_pdf(file_bytes)
        elif clean_url.endswith(".docx"):
            text = _extract_text_from_docx(file_bytes)
        else:
            raise ValueError("Unsupported file format. Only PDF and DOCX are supported.")
    except Exception:
        raise ValueError("Failed to extract text from the file. The file may be corrupted or unreadable.")

    if not text or len(text.strip()) < 50:
        raise ValueError(
            "The uploaded PDF appears to be a scanned image or empty. Please upload a standard text PDF."
        )

    return text.strip()


def _extract_text_from_pdf(file_bytes: bytes) -> str:
    extracted_text = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                extracted_text.append(t)
    return "\n".join(extracted_text)


def _extract_text_from_docx(file_bytes: bytes) -> str:
    with io.BytesIO(file_bytes) as stream:
        doc = docx.Document(stream)
        extracted_text = []
    
        for p in doc.paragraphs:
            if p.text.strip():
                extracted_text.append(p.text.strip())
    
        for table in doc.tables:
            for row in table.rows:
                row_text = [cell.text.text.strip() for cell in row.cells if cell.text.strip()]
                if row_text:
                    extracted_text.append(" | ".join(row_text))

    return "\n".join(extracted_text)