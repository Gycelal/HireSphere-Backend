import logging
from celery import shared_task
from django.utils import timezone
from django.db.models import Q

from .models import ResumeUploadAttempt
from .services.resume_upload import STALE_AFTER, cleanup_upload
logger = logging.getLogger(__name__)


@shared_task
def cleanup_resume_uploads():
    now = timezone.now()

    attempt_ids = list(
        ResumeUploadAttempt.objects.filter(
            Q(
                state=ResumeUploadAttempt.State.PENDING,
                created_at__lte=now - STALE_AFTER,
            )
            |
            Q(
                state=ResumeUploadAttempt.State.ABANDONED,
                next_cleanup_at__lte=now,
            )
        )
        .order_by("next_cleanup_at", "created_at")
        .values_list("pk", flat=True)[:100]
    )
    for attempt_id in attempt_ids:
        try:
            cleanup_upload(attempt_id)
        except Exception:
            logger.exception(
                "Resume cleanup sweep failed: attempt_id=%s",
                attempt_id
            )