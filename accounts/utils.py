import random
from django.core.cache import cache
from rest_framework import serializers
import re

def generate_otp():
    return str(random.randint(100000, 999999))

def store_otp(user_id, otp):
    # Store the OTP in the database or cache with an expiration time
    key = f"otp:verify_email:{user_id}"
    cache.set(key, otp, timeout=300)


def get_stored_otp(user_id):
    key = f"otp:verify_email:{user_id}"
    return cache.get(key)

def delete_stored_otp(user_id):
    key = f"otp:verify_email:{user_id}"
    cache.delete(key)
    
def get_otp_resend_count(user_id):
    key = f"otp:resend_count:{user_id}"
    count = cache.get(key, 0)
    return count


def validate_password(password, confirm_password):
    
    if password != confirm_password:
        raise serializers.ValidationError({"confirm_password": "Password do not match."})
        
    if not re.search(r"\d", password):
        raise serializers.ValidationError({"password": "Password must contain at least one digit."})
    if not re.search(r"[A-Z]", password):
        raise serializers.ValidationError({"password": "Password must contain at least one uppercase letter."})
    
    return True
