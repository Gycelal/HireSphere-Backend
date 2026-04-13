from django.shortcuts import render
from rest_framework.generics import RetrieveUpdateAPIView
from .serializers import CandidateSerializer
from accounts.permissions import IsCandidate
from accounts.models import User

# Create your views here.


class CandidateProfileView(RetrieveUpdateAPIView):
    perrmission_classes = [IsCandidate]
    serializer_class = CandidateSerializer
    queryset = User.objects.all()

    def get_object(self):
        return self.request.user 
    
