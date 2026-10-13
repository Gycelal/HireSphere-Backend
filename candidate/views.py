from rest_framework.views import APIView, Response
import cloudinary.uploader
from rest_framework import status
import logging
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import ListModelMixin, CreateModelMixin, RetrieveModelMixin
from rest_framework.decorators import action
from django.db.models import Max
from django.core.cache import cache
from jobs.models import Job
from google.genai.errors import APIError
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .services.cover_letter_generator import generate_cover_letter
from .services.job_matcher import analyze_resume_job_match
from .serializers import JobAIPromptSerializer
from .services.document_extractor import extract_text
from .models import Candidate, Resume
from core.serializers import ProfilePictureSerializer
from accounts.permissions import IsCandidate
from rest_framework.generics import RetrieveUpdateAPIView
from .serializers import CandidateSerializer, ResumeSerializer, ResumeUploadSerializer, GenerateCoverLetterRequestSerializer
from .services.gemini_service import AIResponseBlockedError, AIServiceError



logger = logging.getLogger(__name__)

class CandidateProfileView(RetrieveUpdateAPIView):
    """
    Handle Updation of Profile and retrieval of profile data for candidate
    """

    permission_classes = [IsCandidate]
    serializer_class = CandidateSerializer

    def get_object(self):
        return self.request.user


class CandidateProfilePhotoView(APIView):
    """
    Handle updating and deleting candidate profile picture
    """

    permission_classes = [IsCandidate]

    def patch(self, request):
        serializer = ProfilePictureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        image = serializer.validated_data["profile_picture"]

        # upload new picture to cloudinary
        try:
            upload_res = cloudinary.uploader.upload(image, folder="profile_pictures")
        except Exception as e:
            logger.error(f"Failed to upload new profile picture: {e}")
            return Response(
                {"detail": "Failed to upload profile picture."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        img_url = upload_res.get("secure_url")
        public_id = upload_res.get("public_id")

        try:
            profile, created = Candidate.objects.get_or_create(user=request.user)
        except Exception as e:
            logger.error(f"Failed to get/create profile: {e}")
            return Response(
                {"detail": "Failed to process profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        old_public_id = profile.profile_picture_public_id
        profile.profile_picture = img_url
        profile.profile_picture_public_id = public_id

        try:
            profile.save()
        except Exception as e:
            logger.error(f"Failed to save profile with new picture: {e}")
            return Response(
                {"detail": "Failed to save profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        # delete old picture from cloudinary
        if old_public_id:
            try:
                cloudinary.uploader.destroy(old_public_id, invalidate=True)
            except Exception as e:
                logger.error(f"Failed to delete old profile picture: {e}")
        return Response({"profile_picture": img_url}, status=status.HTTP_200_OK)

    def delete(self, request):
        # get profile
        try:
            profile = Candidate.objects.get(user=request.user)
        except Candidate.DoesNotExist:
            return Response(
                {"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        # store old public id before clearing picture
        old_public_id = profile.profile_picture_public_id

        # save profile with picture fields cleared
        profile.profile_picture = None
        profile.profile_picture_public_id = None
        try:
            profile.save()
        except Exception as e:
            logger.error(f"Failed to remove profile picture: {e}")
            return Response(
                {"detail": "Failed to remove profile picture."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # remove image from cloudinary if exists
        try:
            if old_public_id:
                cloudinary.uploader.destroy(old_public_id, invalidate=True)
        except Exception as e:
            logger.error(f"Failed to delete profile picture from cloudinary: {e}")
        return Response(
            {"detail": "Profile picture removed."}, status=status.HTTP_200_OK
        )


class CandidateProfileResumeUploadView(APIView):
    """
    Handle uploading or changing candidate default resume
    """

    permission_classes = [IsCandidate]

    def patch(self, request):
        serializer = ResumeUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        candidate, created = Candidate.objects.get_or_create(user=request.user)

        resume = Resume.objects.create(
            candidate=candidate,
            file_url=serializer.validated_data["file_url"],
            public_id=serializer.validated_data["public_id"],
            file_name=serializer.validated_data["file_name"],
        )

        candidate.default_resume = resume
        candidate.save(update_fields=["default_resume"])

        return Response(
            {
                "resume": {
                    "id": resume.id,
                    "file_url": resume.file_url,
                    "public_id": resume.public_id,
                    "file_name": resume.file_name,
                }
            },
            status=status.HTTP_200_OK,
        )

    def delete(self, request):

        try:
            candidate = Candidate.objects.get(user=request.user)
        except Candidate.DoesNotExist:
            return Response(
                {"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        if not candidate.default_resume:
            return Response(
                {"detail": "No resume to remove."}, status=status.HTTP_404_NOT_FOUND
            )

        candidate.default_resume = None

        try:
            candidate.save(update_fields=["default_resume"])
        except Exception as e:
            logger.error(f"Failed to remove resume: {e}")
            return Response(
                {"detail": "Failed to remove resume."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({"detail": "Resume Removed."}, status=status.HTTP_200_OK)


class ResumeViewSet(ListModelMixin, CreateModelMixin, RetrieveModelMixin, GenericViewSet):

    permission_classes = [IsCandidate]
    serializer_class = ResumeSerializer
    pagination_class = None
    print("hits the view")

    def get_queryset(self):
        return Resume.objects.filter(candidate__user=self.request.user).order_by(
            "-created_at"
        )

    def perform_create(self, serializer):
        candidate, created = Candidate.objects.get_or_create(user=self.request.user)
        serializer.save(candidate=candidate)

    @action(detail=False, methods=["get"], url_path="recent")
    def recent(self, request):
        logger.info(f"Fetching recent resumes for user: {request.user.email}")
        print("in recent resumes view")

        candidate = request.user.candidate

        resumes = (
            Resume.objects.filter(
                candidate=candidate, applications__candidate=candidate
            )
            .annotate(last_used=Max("applications__applied_at"))
            .distinct()
            .order_by("-last_used")[:3]
        )

        serializer = self.get_serializer(resumes, many=True)
        logger.info(
            f"Recent resumes data: {serializer.data}"
        ) 
        return Response(serializer.data, status=status.HTTP_200_OK)


class AnalyzeMatchView(APIView):
    """
    Perform Ai-driven analysis matching a candidate's resume against a job's requirements. 
    """
    permission_classes = [IsCandidate]

    def post(self, request):
        """
        Processes candidate matching request. Checks cache before invoking AI service.
        """
        job_id = request.data.get("job_id")
        resume_id = request.data.get("resume_id")

        if not job_id or not resume_id:
            return Response(
                {"detail": "Job ID and Resume ID are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            job = Job.objects.get(id=job_id, is_active=True)
            resume = Resume.objects.get(id=resume_id, candidate__user=request.user)
        except (Job.DoesNotExist, Resume.DoesNotExist):
            return Response(
                {"detail": "Job or Resume not found."}, status=status.HTTP_404_NOT_FOUND
            )

        cache_key = f"ai_match:{job_id}:{resume_id}"
        cached_result = cache.get(cache_key)

        if cached_result:
            return Response(cached_result, status=status.HTTP_200_OK)

        # Extract text from the resume using the document extractor service
        try:
            resume_text = extract_text(resume.file_url)
        except ValueError as e:
            logger.error(f"Text extraction failed for resume {resume_id}: {e}")
            return Response(
                {"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )
        
        if not resume_text:
            return Response(
                {"detail": "Failed to extract text from resume."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        job_details = JobAIPromptSerializer(job).data

        try:
            match_result = analyze_resume_job_match(job_details, resume_text)

            cache.set(cache_key, match_result, timeout=86400)
            return Response(match_result, status=status.HTTP_200_OK)
        
        except APIError as e:
            logger.error(f"AI service API failure: {e}")
            return Response({"detail": "AI service is currently unavailable."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        except Exception as e:
            logger.error(f"Unexpected internal error: {e}", exc_info=True)
            return Response(
                {"detail": "An internal error occurred while processing your request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GenerateCoverLetterView(APIView):
    """Generate a cover letter draft without saving it."""

    permission_classes = [IsCandidate]

    def post(self, request):
        request_serializer = GenerateCoverLetterRequestSerializer(data=request.data)

        request_serializer.is_valid(raise_exception=True)
        data = request_serializer.validated_data

        job = get_object_or_404(
            Job,
            id=data["job_id"],
            is_active=True,
            application_deadline__gte=timezone.localdate(),
        )

        resume = get_object_or_404(
            Resume,
            id=data["resume_id"],
            candidate__user=request.user,
        )

        try:
            resume_text = extract_text(resume.file_url)
        except ValueError as exc:
            logger.warning(
                "Cover-letter resume extraction failed: resume_id=%s",
                resume.id,
            )
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not resume_text or not resume_text.strip():
            return Response(
                {"detail": "The resume contains no readable text."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        job_details = JobAIPromptSerializer(job).data

        try:
            result = generate_cover_letter(
                job_details=job_details,
                resume_text = resume_text,
            )
        except AIResponseBlockedError:
            logger.warning(
                "Cover letter generation failed: job_id=%s resume_id=%s",
                job.id,
                resume.id
            )

            return Response(
                {"detail": "The AI service could not process this content."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except AIServiceError:
            logger.warning(
                "Cover letter generation blocked: job_id=%s resume_id=%s",
                job.id,
                resume.id
            )
            return Response(
                {"detail": "Ai generation failed. Please try again later."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except APIError as exc:
            logger.error(
                "Unexpected cover-letter generation failure: type=%s",
                type(exc).__name__
            )
            return Response(
                {"detail": "An internal error occured during generation."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        return Response(result, status=status.HTTP_200_OK)

