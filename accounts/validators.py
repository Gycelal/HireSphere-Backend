import re
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()

def validate_password_strength(password):
    if len(password) < 8:
        raise serializers.ValidationError("Password must be at least 8 characters long.")
    if not re.search(r'[A-Za-z]', password):
        raise serializers.ValidationError("Password must include at least one letter.")
    if not re.search(r'\d', password):
        raise serializers.ValidationError("Password must include at least one number.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise serializers.ValidationError("Password must include at least one special character.")

def validate_password_match(password,confirm_password):
    if password != confirm_password:
        raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
    
# This one will check whether the email already exist while registering  and also check if no account exisit while logging in.
def validate_email_exists(email,should_exist=True):
    exists = User.objects.filter(email=email).exists()
    errors = {}
    if should_exist and not exists:
        errors['email'] = "No account found with this email."
    elif not should_exist and exists:
        errors['email'] = "Email is already registered."
    if errors:
        raise serializers.ValidationError(errors)

