from django.urls import path
from .views import AdminLoginView,AdminLogoutView, PendingCompaniesView, UpdateCompanyApprovalStatusView


urlpatterns = [
    path('admin-login/',AdminLoginView.as_view(),name='admin-login'),
    path('admin-logout/',AdminLogoutView.as_view(),name='admin-logout'),
    path('pending-companies/',PendingCompaniesView.as_view(),name='pending-companies'),
    path('company/<int:company_id>/update-status/',UpdateCompanyApprovalStatusView.as_view(),name='update-status'),
]
