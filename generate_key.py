import secrets
secret_key = secrets.token_hex(32)
print(secret_key)
# Use the output as your FLASK_SECRET_KEY