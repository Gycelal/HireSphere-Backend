from rest_framework.generics import RetrieveUpdateAPIView
from accounts.permissions import IsRecruiter
from .serializers import RecruiterProfileSerializer
from .models import RecruiterProfile

# Create your views here.


class RecruiterProfileView(RetrieveUpdateAPIView):
    permission_classes = [IsRecruiter]
    serializer_class = RecruiterProfileSerializer

    def get_object(self):
        profile, created = RecruiterProfile.objects.get_or_create(user=self.request.user)
        return profile