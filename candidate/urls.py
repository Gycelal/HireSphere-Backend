from .views import CandidateProfileView, CandidateProfilePhotoView
from django.urls import path


urlpatterns = [
    path('profile/', CandidateProfileView.as_view(), name='candidate-profile'),
    path('profile/photo/', CandidateProfilePhotoView.as_view(), name='candidate-profile-photo')
]
