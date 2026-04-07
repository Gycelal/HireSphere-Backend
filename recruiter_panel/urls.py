from django.urls import path
from .views import RecruiterProfileView

urlpatterns = [
    path('profile/',RecruiterProfileView.as_view(), name='recruiter-profile'),
]
