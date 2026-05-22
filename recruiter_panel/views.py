from rest_framework.generics import RetrieveUpdateAPIView
from accounts.permissions import IsRecruiter
from .serializers import  UserProfileSerializer
import cloudinary.uploader
import logging
# Create your views here.

logger = logging.getLogger(__name__)

class RecruiterProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsRecruiter]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user

    def perform_update(self, serializer):

        image = self.request.FILES.get("profile_picture")
        profile_data = {}

        if image:   
            image_url = cloudinary.uploader.upload(image)["secure_url"]
            logger.info(f"Uploaded image URL: {image_url}")
            profile_data["profile_picture"] = image_url
        serializer.save(recruiterprofile=profile_data if profile_data else None)