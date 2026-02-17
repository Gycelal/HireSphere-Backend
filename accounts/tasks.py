from celery import shared_task
from django.core.mail import send_mail

@shared_task
def send_verification_email(email, otp):
    subject = 'Verify Your Email Address'
    message = f'Your OTP for email verification is: {otp}'
    from_email = 'krgycelal@gmail.com'
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)

@shared_task
def send_forgot_password_email(email, token):
    subject = "Password Reset Request"
    message = f"Use the following Link to reset your password: http://localhost:3000/reset-password?token={token}"
    from_email = "krgycelal@gmail.com"
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)