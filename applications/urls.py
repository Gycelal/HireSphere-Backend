from rest_framework.routers import DefaultRouter
from .views import (
    ApplicationViewSet,
    JobApplicationsListAPIView
)
from django.urls import path 

router = DefaultRouter()
router.register("", ApplicationViewSet, basename="application") 

urlpatterns = router.urls + [
    path("job/<int:job_id>/", JobApplicationsListAPIView.as_view(), name="job-applications")
]
