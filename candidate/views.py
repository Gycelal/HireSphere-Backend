from rest_framework.generics import RetrieveUpdateAPIView
from .serializers import CandidateSerializer, ResumeUploadSerializer
from accounts.permissions import IsCandidate
from core.serializers import ProfilePictureSerializer
from rest_framework.views import APIView, Response
import cloudinary.uploader
from rest_framework import status
import logging
from .models import Candidate

logger = logging.getLogger(__name__)

# Create your views here.
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

        image = serializer.validated_data['profile_picture']

        # upload new picture to cloudinary
        try:
            upload_res = cloudinary.uploader.upload(image, folder='profile_pictures')
        except Exception as e:
            logger.error(f"Failed to upload new profile picture: {e}")
            return Response(
        {"detail": "Failed to upload profile picture."},
        status = status.HTTP_500_INTERNAL_SERVER_ERROR
    )
        img_url = upload_res.get('secure_url')
        public_id = upload_res.get('public_id')

        try:
            profile, created = Candidate.objects.get_or_create(user=request.user)
        except Exception as e:
            logger.error(f"Failed to get/create profile: {e}")
            return Response(
                {"detail": "Failed to process profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
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
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
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
            return Response({"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)

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
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # remove image from cloudinary if exists
        try:
            if old_public_id:
                cloudinary.uploader.destroy(old_public_id, invalidate=True)
        except Exception as e:
            logger.error(f"Failed to delete profile picture from cloudinary: {e}")
        return Response({"detail": "Profile picture removed."}, status=status.HTTP_200_OK)

class CandidateResumeUploadView(APIView):
    """
    Handle updating and deleting candidate resume
    """
    permission_classes = [IsCandidate]
    
    def patch(self, request):
        serializer = ResumeUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        resume_public_id = serializer.validated_data['resume_public_id']
        resume_url = serializer.validated_data['resume_url']
        resume_filename = serializer.validated_data['resume_filename']

        # get the candidate profile if already exists or create a new one
        try:
            profile, created = Candidate.objects.get_or_create(user=request.user)
        except Exception as e:
            logger.error(f"Failed to get/create profile: {e}")
            return Response(
                {"detail": "Failed to process profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # store old resume public id before updating
        old_resume_id = profile.resume_public_id
        profile.resume_public_id = resume_public_id
        profile.resume_url = resume_url
        profile.resume_filename = resume_filename

        # update the profile with new resume public id
        try:
            profile.save()
        except Exception as e:
            logger.error(f"Failed to save profile with new resume: {e}")
            return Response(
                {"detail": "Failed to save profile."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        # delete old resume from cloudinary if exists and its different from the new one
        if old_resume_id and old_resume_id != resume_public_id:
            try:
                cloudinary.uploader.destroy(old_resume_id, resource_type="raw", invalidate=True)
            except Exception as e:
                logger.error(f"Failed to delete old resume from cloudinary: {e}")
        return Response({"resume_public_id": resume_public_id}, status=status.HTTP_200_OK)

    def delete(self, request):
        # get profile
        try:
            profile = Candidate.objects.get(user=request.user)
        except Candidate.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # store old resume public id before clearing
        old_resume_id = profile.resume_public_id

        # clear resume public id from profile
        profile.resume_public_id = None
        profile.resume_url = None
        profile.resume_filename = None
        try:
            profile.save()
        except Exception as e:
            logger.error(f"Failed to remove resume: {e}")
            return Response(
                {"detail": "Failed to remove resume."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # remove resume from cloudinary if exists
        if old_resume_id:
            try:
                cloudinary.uploader.destroy(old_resume_id, resource_type="raw", invalidate=True)
            except Exception as e:
                logger.error(f"Failed to delete resume from cloudinary: {e}")
        return Response({"detail": "Resume removed."}, status=status.HTTP_200_OK)
