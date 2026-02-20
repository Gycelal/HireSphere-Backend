from django.urls import path
from .views import RecruiterProfileView

urlpatterns = [
    path('recruiter/profile/',RecruiterProfileView.as_view(), name='recruiter-profile'),
]
