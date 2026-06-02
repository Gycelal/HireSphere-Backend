import profile

from rest_framework.generics import RetrieveUpdateAPIView
from urllib3 import request
from accounts.permissions import IsRecruiter
from .serializers import  RecruiterProfileSerializer, ProfilePictureSerializer
import cloudinary
import logging
from rest_framework.views import APIView
from .models import RecruiterProfile
from rest_framework.response import Response
from rest_framework import status
# Create your views here.

logger = logging.getLogger(__name__)

class RecruiterProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsRecruiter]
    serializer_class = RecruiterProfileSerializer

    def get_object(self):
        return self.request.user



class RecruiterProfilePhotoUpdateView(APIView):
    permission_classes = [IsRecruiter]
    serializer_class = ProfilePictureSerializer
    
    def patch(self, request):
        
        serializer = ProfilePictureSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        image = serializer.validated_data['profile_picture']

        # upload new picture to cloudinary
        try:
            upload_res = cloudinary.uploader.upload(image)
        except Exception as e:
            logger.error(f"Failed to upload new profile picture: {e}")
            return Response(
        {"detail": "Failed to upload profile picture."},
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
        img_url = upload_res.get('secure_url')
        public_id = upload_res.get('public_id')
        
        try:
            profile, created = RecruiterProfile.objects.get_or_create(
        user=request.user
    )
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
            logger.error(f"Failed to save profile picture: {e}")
            return Response(
                {"detail": "Failed to save profile picture."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # delete old picture from cloudinary if exists
        if old_public_id:
            try:
                cloudinary.uploader.destroy(old_public_id)
            except Exception as e:
                logger.error(f"Failed to delete old profile picture: {e}")
        return Response({"profile_picture": img_url}, status=status.HTTP_200_OK)
    
    def delete(self, request):
        pass