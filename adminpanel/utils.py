# utils.py

from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.response import Response

def handle_logout(request):
    try:
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
    except TokenError:
        pass  # Optional logging

    response = Response({'detail': 'Logged out successfully.'}, status=200)
    response.delete_cookie('refresh_token')
    return response
