from django.urls import path
from .views import RecruiterProfileView, RecruiterProfilePhotoUpdateView


urlpatterns = [
    path('profile/',RecruiterProfileView.as_view(), name='recruiter-profile'),
    path('profile/photo/', RecruiterProfilePhotoUpdateView.as_view(), name='recruiter-profile-photo')
]

