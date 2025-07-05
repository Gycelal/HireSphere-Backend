from celery import shared_task
from django.core.mail import send_mail


@shared_task
def send_otp_email(email,otp):
    subject = "HireSphere OTP verification"
    message = f"""
Hello,

Thank you for registering with HireSphere.

Your One-Time Password (OTP) for email verification is:

👉 {otp}

This OTP is valid for 5 minutes. Do not share it with anyone.

Regards,  
HireSphere Team
"""
    send_mail(subject,message,'krgycelal@gmail.com',[email])


@shared_task
def send_password_reset_email(email,reset_url):
    subject = "HireSphere Password Reset Link"
    message = f"""
Hello,

You can use the Reset link for createing new password.

Your One Time password reset link is:

👉 {reset_url}

This link is valid for 15 minutes. Do not share it with anyone.

Regards,  
HireSphere Team
"""
    send_mail(subject,message,'krgycelal@gmail.com',[email])



