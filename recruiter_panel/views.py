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
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)
    