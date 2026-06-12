from django.urls import path
from .views import AdminRecruiterViewSet
from rest_framework.routers import DefaultRouter
from .views import AdminRecruiterViewSet, UserManagementViewSet
from django.urls import include

router = DefaultRouter()
router.register(r"recruiters", AdminRecruiterViewSet, basename="recruiters")
router.register(r"users", UserManagementViewSet, basename="users")

urlpatterns = [
    path('', include(router.urls)), 
]




