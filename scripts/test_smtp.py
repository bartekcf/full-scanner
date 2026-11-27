import smtplib
import ssl
from getpass import getpass

email = input("Adres e-mail: ").strip()
password = getpass("Hasło: ")

with smtplib.SMTP_SSL(
    "ssl0.ovh.net",
    465,
    context=ssl.create_default_context(),
    timeout=15
) as smtp:
    smtp.login(email, password)
    print("SMTP działa poprawnie!")