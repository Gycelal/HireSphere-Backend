from celery import shared_task
from django.core.mail import send_mail

@shared_task
def send_verification_email(email, otp):
    subject = 'Verify Your Email Address'
    message = f'Your OTP for email verification is: {otp}'
    from_email = 'krgycelal@gmail.com'
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)