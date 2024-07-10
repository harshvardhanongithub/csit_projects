import smtplib
import random
import string
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from getpass import getpass

class TwoFactorAuth:
    def __init__(self, smtp_server, smtp_port, smtp_username, smtp_password, from_email):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.otp_expiry = 300  # OTP expiry time in seconds (5 minutes)

    def generate_otp(self, length=6):
        """Generate a random OTP of specified length."""
        digits = string.digits
        otp = ''.join(random.choices(digits, k=length))
        return otp

    def send_otp(self, to_email, otp):
        """Send OTP to the specified email address."""
        subject = "Your OTP Code"
        body = f"Your OTP code is {otp}. It is valid for {self.otp_expiry // 60} minutes."
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
                print("OTP sent successfully.")
        except smtplib.SMTPException as e:
            print(f"Failed to send OTP: {e}")

    def verify_otp(self, user_otp, generated_otp, otp_timestamp):
        """Verify the provided OTP."""
        current_time = time.time()
        if current_time - otp_timestamp > self.otp_expiry:
            return False, "OTP expired."
        if user_otp == generated_otp:
            return True, "OTP verified successfully."
        return False, "Invalid OTP."

if __name__ == "__main__":
    # Ask the user for their email, username, and app-specific password
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = input("Enter your email (Gmail): ")
    smtp_password = getpass("Enter your app-specific password: ")
    from_email = smtp_username

    # Create an instance of the 2FA system
    two_fa = TwoFactorAuth(smtp_server, smtp_port, smtp_username, smtp_password, from_email)

    # Ask the user for the recipient's email
    user_email = input("Enter the recipient's EMAIL: ")

    # Generate an OTP and send it to the user's email
    otp = two_fa.generate_otp()
    two_fa.send_otp(user_email, otp)
    otp_timestamp = time.time()

    # Simulate user entering the OTP
    user_entered_otp = input("Enter the OTP sent to your EMAIL:  ")

    # Verify the OTP
    is_valid, message = two_fa.verify_otp(user_entered_otp, otp, otp_timestamp)
    print(message)
