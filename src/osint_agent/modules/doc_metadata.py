"""
Document & image metadata forensics.

Classic OSINT technique (FOCA-style): documents and images often carry
embedded metadata — author names, usernames, software versions, internal
file paths, GPS coordinates in photo EXIF — that the publisher never meant
to expose. Useful for verifying provenance of leaked/public documents or
tracing an organization's internal tooling and staff names from PDFs they
published.

Works on local files (already downloaded) or a URL (downloaded first).
"""
import os
import requests
from ..config import Config

try:
    from pypdf import PdfReader
except ImportError:
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        PdfReader = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    Image = None


def _download_if_url(path_or_url: str, tmp_dir: str = "/tmp/osint_agent_dl") -> str:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        os.makedirs(tmp_dir, exist_ok=True)
        local_name = os.path.join(tmp_dir, os.path.basename(path_or_url.split("?")[0]) or "downloaded_file")
        headers = {"User-Agent": Config.USER_AGENT}
        resp = requests.get(path_or_url, headers=headers, timeout=Config.REQUEST_TIMEOUT + 20, stream=True)
        resp.raise_for_status()
        with open(local_name, "wb") as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)
        return local_name
    return path_or_url


def _pdf_metadata(path: str) -> dict:
    if PdfReader is None:
        return {"error": "pypdf/PyPDF2 not installed"}
    try:
        reader = PdfReader(path)
        meta = reader.metadata or {}
        result = {str(k).lstrip("/"): str(v) for k, v in meta.items()}
        result["page_count"] = len(reader.pages)

        # Pull any URLs embedded as link annotations (can reveal internal domains)
        links = set()
        for page in reader.pages:
            if "/Annots" in page:
                try:
                    for annot in page["/Annots"]:
                        obj = annot.get_object()
                        uri = obj.get("/A", {}).get("/URI")
                        if uri:
                            links.add(uri)
                except Exception:
                    pass
        result["embedded_links"] = sorted(links)
        return result
    except Exception as e:
        return {"error": str(e)}


def _image_exif(path: str) -> dict:
    if Image is None:
        return {"error": "Pillow not installed"}
    try:
        img = Image.open(path)
        exif_data = img._getexif()
        if not exif_data:
            return {"note": "No EXIF data found"}

        result = {}
        gps_info = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                for gps_id, gps_val in value.items():
                    gps_tag = GPSTAGS.get(gps_id, gps_id)
                    gps_info[gps_tag] = str(gps_val)
            else:
                result[str(tag)] = str(value)
        if gps_info:
            result["GPS"] = gps_info
        return result
    except Exception as e:
        return {"error": str(e)}


def run(path_or_url: str) -> dict:
    print(f"  [metadata] Analyzing {path_or_url}...")
    try:
        local_path = _download_if_url(path_or_url)
    except Exception as e:
        return {"source": path_or_url, "error": f"Failed to fetch: {e}"}

    ext = os.path.splitext(local_path)[1].lower()
    if ext == ".pdf":
        meta = _pdf_metadata(local_path)
        filetype = "pdf"
    elif ext in (".jpg", ".jpeg", ".tiff", ".png"):
        meta = _image_exif(local_path)
        filetype = "image"
    else:
        meta = {"error": f"Unsupported file type: {ext}"}
        filetype = "unknown"

    return {"source": path_or_url, "filetype": filetype, "metadata": meta}
