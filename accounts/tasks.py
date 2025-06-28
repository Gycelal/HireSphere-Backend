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




