import random
from django.core.cache import cache


OTP_EXPIRE_TIME = 300

def generate_otp():
    return str(random.randint(100000, 999999))

def store_otp(email,otp):
    cache.set(f"otp:{email}",otp,timeout=OTP_EXPIRE_TIME)

def verify_otp(email,user_input_otp):
    key = f"otp:{email}"
    stored_otp = cache.get(key)
    if stored_otp == user_input_otp:
        cache.delete(key)
        return True
    return False

def can_resend_otp(email):
    key = f'otp_cooldown:{email}'
    if cache.get(key):
        return False
    cache.set(key,1,timeout=60)
    return True

