from django.urls import path
from .views import AdminRecruiterViewSet
from rest_framework.routers import DefaultRouter
from .views import AdminRecruiterViewSet
from django.urls import include

router = DefaultRouter()
router.register(r"recruiters", AdminRecruiterViewSet, basename="admin-recruiters")

urlpatterns = [
    path('', include(router.urls)), 
]


