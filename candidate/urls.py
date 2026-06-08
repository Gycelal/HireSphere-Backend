from .views import CandidateProfileView, CandidateProfilePhotoView, CandidateResumeUploadView
from django.urls import path


urlpatterns = [
    path('profile/', CandidateProfileView.as_view(), name='candidate-profile'),
    path('profile/photo/', CandidateProfilePhotoView.as_view(), name='candidate-profile-photo'),
    path('profile/resume/', CandidateResumeUploadView.as_view(), name='candidate-profile-resume'),
]
