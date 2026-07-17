"""
File Ingestion Module
Handles file walking, hashing, and MIME-type detection.
"""

import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger("SENTINEL_INGESTOR")


class Ingestor:
    """File ingestion and indexing system."""

    def __init__(self, db):
        self.db = db

    def scan_directory(self, root_path: str) -> int:
        """
        Recursively scan a directory and index files in the database.
        """
        if len(root_path) == 2 and root_path[1] == ":":
            root_path = root_path + "\\"

        logger.info("Scanning directory: %s", root_path)
        indexed_count = 0
        error_count = 0

        try:
            for dirpath, _, filenames in os.walk(root_path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    try:
                        if self._file_exists(file_path):
                            continue

                        try:
                            file_size = os.path.getsize(file_path)
                        except OSError:
                            continue

                        if file_size > 1_000_000_000:
                            logger.debug("Skipping large file: %s (%d bytes)", file_path, file_size)
                            continue

                        file_hash = self._hash_file(file_path)
                        mime_type = self._detect_mime_type(file_path)

                        self.db.insert_file(
                            path=file_path,
                            file_hash=file_hash,
                            size=file_size,
                            mime=mime_type,
                        )
                        indexed_count += 1

                        if indexed_count % 50 == 0:
                            logger.info("Indexed %d files...", indexed_count)
                    except PermissionError:
                        error_count += 1
                    except Exception as exc:
                        logger.debug("Failed to index %s: %s", file_path, exc)
                        error_count += 1
        except Exception as exc:
            logger.error("Fatal error during directory scan: %s", exc)
            return indexed_count

        logger.info("Scanning complete: %d files indexed, %d errors", indexed_count, error_count)
        return indexed_count

    def _file_exists(self, file_path: str) -> bool:
        conn = self.db.get_connection()
        try:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM files WHERE file_path = ?",
                (file_path,),
            )
            return cursor.fetchone()[0] > 0
        finally:
            conn.close()

    @staticmethod
    def _hash_file(file_path: str, algorithm: str = "sha256") -> str:
        hash_obj = hashlib.new(algorithm)
        try:
            with open(file_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return "unknown"

    def _detect_mime_type(self, file_path: str) -> str:
        try:
            import magic

            return magic.from_file(file_path, mime=True)
        except Exception:
            return self._mime_from_extension(file_path)

    @staticmethod
    def _mime_from_extension(file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        mime_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
            ".webp": "image/webp",
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".txt": "text/plain",
            ".log": "text/plain",
            ".csv": "text/csv",
            ".xml": "text/xml",
            ".html": "text/html",
            ".json": "application/json",
            ".zip": "application/zip",
            ".rar": "application/x-rar-compressed",
            ".7z": "application/x-7z-compressed",
            ".exe": "application/x-msdownload",
            ".dll": "application/x-msdownload",
            ".ps1": "application/x-powershell",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
            ".avi": "video/x-msvideo",
            ".mkv": "video/x-matroska",
        }
        return mime_map.get(ext, "application/octet-stream")
