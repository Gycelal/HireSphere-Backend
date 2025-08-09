from django.urls import path
from .views import AdminLoginView,AdminLogoutView, PendingCompaniesView


urlpatterns = [
    path('admin-login/',AdminLoginView.as_view(),name='admin-login'),
    path('admin-logout/',AdminLogoutView.as_view(),name='admin-logout'),
    path('pending-companies',PendingCompaniesView.as_view(),name='pending-companies'),
]
