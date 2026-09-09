from .views import CandidateProfileView, CandidateProfilePhotoView, CandidateProfileResumeUploadView, ResumeViewSet
from django.urls import path


urlpatterns = [
    path('profile/', CandidateProfileView.as_view(), name='candidate-profile'),
    path('profile/photo/', CandidateProfilePhotoView.as_view(), name='candidate-profile-photo'),
    path('profile/resume/', CandidateProfileResumeUploadView.as_view(), name='candidate-profile-resume'),
    path('resume/recent/', ResumeViewSet.as_view({"get": "recent"}), name='candidate-resume-recent'),
    path('resumes/', ResumeViewSet.as_view({"post": "create"}), name='candidate-resumes'),
]
