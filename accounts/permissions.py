from rest_framework.permissions import BasePermission

class IsGoogleUser(BasePermission):
    # Allows access only to the users registered via Google.
    def has_permission(self, request, view):
        return (request.user and request.user.is_authenticated and request.user.registration_method == 'google')