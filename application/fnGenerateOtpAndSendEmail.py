from application import app
import random
import socket
import sys
from flask_mail import Mail, Message

mail = Mail(app)

def is_connected():
    """Check for internet connection."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

# Function to generate OTP
def generateOtp():
    return str(random.randint(100000, 999999))

def send_email_otp(user):
    if not user.email:
        print("User email is missing.")
        return

    if not is_connected():
        return "No internet connection."

    otp = generateOtp()
    if not otp:
        print("OTP generation failed.")
        return

    user.otp = otp
    user.save()  # Save OTP to database

    msg = Message("Your OTP Code", recipients=[user.email])
    msg.body = f"Your OTP code is: {otp}"
    try:
        mail.send(msg)  # Send email
    except Exception as e:
        print(f"Failed to send email: {e}")
