from .views import CandidateProfileView
from django.urls import path


urlpatterns = [
    path('profile/', CandidateProfileView.as_view(), name='candidate-profile'),
]
