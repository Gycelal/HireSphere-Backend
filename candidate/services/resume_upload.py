from datetime import timedelta
from pathlib import Path
import io
import zipfile
import hashlib
import logging
import uuid

import pdfplumber
from docx import Document
import cloudinary.uploader

from rest_framework.exceptions import APIException, ValidationError
from django.db import transaction
from ..models import ResumeUploadAttempt, Resume, Candidate
from django.utils import timezone

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_DOCX_EXPANDED_SIZE = 25 * 1024 * 1024
MAX_DOCX_MEMBERS = 2000
STALE_AFTER = timedelta(minutes=30)


class UploadConflict(APIException):
    status_code = 409
    default_detail = "The upload cannot currently be processed."


class UploadUnavailable(APIException):
    status_code = 503
    default_detail = (
        "Resume upload failed. Retry using the same upload key " "to check its outcome."
    )


def validate_resume(file):
    filename = Path(file.name).name
    extension = Path(filename).suffix.lower()

    if not filename:
        raise ValidationError({"file": "A filename is required."})

    if len(filename) > 255:
        raise ValidationError({"file": "Filename must not exceed 255 charecters."})

    if extension not in {".pdf", ".docx"}:
        raise ValidationError({"file": "Only PDF and DOCX files are supported."})

    if not file.size or file.size > MAX_FILE_SIZE:
        raise ValidationError({"file": "Resume must be between 1 byte and 5 MiB"})

    file.seek(0)
    data = file.read(MAX_FILE_SIZE + 1)
    file.seek(0)

    if not data or len(data) > MAX_FILE_SIZE:
        raise ValidationError({"file": "Resume must be between 1 byte and 5 Mib"})

    try:
        if extension == ".pdf":
            if not data.startswith(b"%PDF-"):
                raise ValueError("Invalid PDF signature")

            with pdfplumber.open(io.BytesIO(data)) as document:
                if not document.pages:
                    raise ValueError("PDF has no pages.")
        else:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                names = [member.filename for member in members]

                if len(members) > MAX_DOCX_MEMBERS:
                    raise ValueError("Too many DOCX archive members")

                if len(names) != len(set(names)):
                    raise ValueError("Duplicate DOCX archive members")

                expanded_size = sum(member.file_size for member in members)
                if expanded_size > MAX_DOCX_EXPANDED_SIZE:
                    raise ValueError("DOCX expands beyong the allowed size.")

                required = {
                    "[Content_Types].xml",
                    "word/document.xml",
                }

                if not required.issubset(names):
                    raise ValueError("Invalid DOCX structure.")

                if any(name.lower().endswith("vbaproject.bin") for name in names):
                    raise ValueError("Macro-enabled files are unsupported.")

            # checks the word package type and parses the document.
            Document(io.BytesIO(data))
    except Exception as exc:
        raise ValidationError(
            {"file": ("The file is invalid, encrypted, corrupted," "or unsupported.")}
        ) from exc

    file_hash = file_hash = hashlib.sha256(data).hexdigest()
    fingerprint = hashlib.sha256(filename.encode("utf-8") + b"\0" + data).hexdigest()

    return data, filename, extension, file_hash, fingerprint


def delete_asset(public_id):
    result = cloudinary.uploader.destroy(
        public_id=public_id,
        resource_type="raw",
        type="upload",
        invalidate=True,
        timeout=30,
    )

    if result.get("result") not in {"ok", "not found"}:
        raise RuntimeError("Cloudinary did not confirm asset deletion.")


def cleanup_upload(attempt_id, *, force=False):
    """
    Lock and permenantly abandon an unsuccessful attempt before deleting.
    Successful attempts and assets referenced by Resumes are never deleted.
    """

    with transaction.atomic(durable=True):
        attempt = (
            ResumeUploadAttempt.objects.select_for_update(skip_locked=True)
            .filter(pk=attempt_id)
            .first()
        )

        if attempt is None:
            return

        if (
            attempt.state == ResumeUploadAttempt.State.SAVED
            or attempt.resume_id is not None
            or Resume.objects.filter(public_id=attempt.public_id).exists()
        ):
            return

        now = timezone.now()

        if not force:
            if attempt.state == ResumeUploadAttempt.State.PENDING:
                if attempt.created_at > now - STALE_AFTER:
                    return
            elif attempt.next_cleanup_at is not None and attempt.next_cleanup_at > now:
                return

        # a try can no longer upload/save using this attempt
        attempt.state = ResumeUploadAttempt.State.ABANDONED

        try:
            delete_asset(attempt.public_id)
        except Exception:
            attempt.cleanup_failures += 1

            delay_seconds = min(
                60 * (2 ** min(attempt.cleanup_failures, 10)),
                86400,
            )
            attempt.next_cleanup_at = now + timedelta(seconds=delay_seconds)

            logger.exception(
                "Resume asset cleanup failed: attempt_id=%s public_Id=%s",
                attempt.pk,
                attempt.public_id,
            )
        else:
            attempt.cleanup_failures = 0

            # A remote upload could finish after our upload timed out.
            # Retain this abandoned attempt and recheck its asset daily.
            attempt.next_cleanup_at = now + timedelta(days=1)

        attempt.save(update_fields=["state", "cleanup_failures", "next_cleanup_at"])


def upload_resume(*, user, file, key, purpose):
    (
        data,
        filename,
        extension,
        file_hash,
        fingerprint,
    ) = validate_resume(file)

    with transaction.atomic(durable=True):
        candidate, _ = Candidate.objects.get_or_create(user=user)

        attempt, _ = ResumeUploadAttempt.objects.get_or_create(
            candidate=candidate,
            purpose=purpose,
            key=key,
            defaults={
                "fingerprint": fingerprint,
                "public_id":(
                    f"candidate_resumes/{candidate.pk}/"
                    f"{uuid.uuid4().hex}{extension}"
                )
            }
        )

    try:
        with transaction.atomic(durable=True):
            # Serialize resume uploads for this candidate, including
            # requests with different keys but identical file contents.
            #
            # PostgreSQL's no_key lock permits unrelated FK inserts,
            # including creation of another upload-attempt record.

            profile = (
                Candidate.objects.select_for_update(skip_locked=True, no_key=True).filter(pk=candidate.pk).first()
            )

            if profile is None:
                raise UploadConflict(
                    "another resume upload is processing. "
                    "retry with the same key."
                )

            locked_attempt = (
                ResumeUploadAttempt.objects.select_for_update(skip_locked=True).filter(pk=attempt.pk).first()
            )

            if locked_attempt is None:
                raise UploadConflict(
                    "This upload is processing. Retry with he same key."
                )

            if locked_attempt.fingerprint != fingerprint:
                raise UploadConflict(
                    "This upload key was already used with"
                    "different file contents or a different filename. "
                )
            if locked_attempt.state == ResumeUploadAttempt.State.SAVED:
                # This request already succeeded. Return its resume 
                # without changing the current default.
                resume = Resume.objects.get(pk=locked_attempt.resume_id)
                return resume, locked_attempt.created_resume, True

            if locked_attempt.state == ResumeUploadAttempt.State.ABANDONED:
                raise UploadConflict(
                    "This attempt was abandoned."
                    "Start a new upload with a new key."
                )

            resume = Resume.objects.filter(
                candidate=profile,
                file_hash=file_hash,
            ).first()

            created_resume = resume is None

            if created_resume:
                # Cloudinary upload and response check
                result = cloudinary.uploader.upload(
                    io.BytesIO(data),
                    resource_type="raw",
                    type="upload",
                    public_id=locked_attempt.public_id,
                    overwrite=False,
                    unique_filename=False,
                    timeout=60,
                )
                if(result.get("public_id") != locked_attempt.public_id or not result.get("secure_url")):
                    raise RuntimeError("Invalid Cloudinary upload response.")

                resume = Resume(
                    candidate=profile,
                    file_url=result["secure_url"],
                    public_id=locked_attempt.public_id,
                    file_name=filename,
                    file_hash=file_hash,
                )
                resume.full_clean()
                resume.save()

            if purpose == ResumeUploadAttempt.Purpose.PROFILE:
                profile.default_resume = resume
                profile.save(update_fields=["default_resume"])

            locked_attempt.resume = resume
            locked_attempt.created_resume = created_resume
            locked_attempt.state = ResumeUploadAttempt.State.SAVED
            locked_attempt.save(update_fields=[
                "resume",
                "created_resume",
                "state"
            ])
        
        return resume, created_resume, False

    except UploadConflict:
        raise
    except Exception as exc:
        logger.exception(
            "resume upload/save failed: attempt_id=%s",
            attempt.pk,
        )

        try:
            cleanup_upload(attempt.pk, force=True)
        except Exception:
            # Log the cleanup failure and keep the original upload/save error.
            # The background task will retry cleanup later.

            logger.exception(
                "Immediate resume cleanup failed: atttempt_id=%s",
                attempt.pk,
            )
        raise UploadUnavailable() from exc
            
             


