from django.urls import path
from .views import AdminRecruiterViewSet
from rest_framework.routers import DefaultRouter
from .views import AdminRecruiterViewSet

router = DefaultRouter()
router.register(r"recruiters", AdminRecruiterViewSet, basename="admin-recruiters")

urlpatterns = router.urls


