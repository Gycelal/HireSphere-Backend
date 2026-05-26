from rest_framework.generics import RetrieveUpdateAPIView
from accounts.permissions import IsRecruiter
from .serializers import  RecruiterProfileSerializer
import cloudinary.uploader
import logging
# Create your views here.

logger = logging.getLogger(__name__)

class RecruiterProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsRecruiter]
    serializer_class = RecruiterProfileSerializer

    def get_object(self):
        return self.request.user

    

class RecruiterProfilePhotoUpdateView():
    pass