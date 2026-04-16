from rest_framework.generics import RetrieveUpdateAPIView
from accounts.permissions import IsRecruiter
from .serializers import RecruiterProfileSerializer, UserProfileSerializer
from  .models import RecruiterProfile
from accounts.models import User
from rest_framework.response import Response
from rest_framework import status

# Create your views here.


class RecruiterProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsRecruiter]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user
    