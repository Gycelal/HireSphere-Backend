from django.urls import path
from .views import AdminLoginView,AdminLogout


urlpatterns = [
    path('admin-login/',AdminLoginView.as_view(),name='admin-login'),
    path('admin-logout/',AdminLogout.as_view(),name='admin-logout'),
]
