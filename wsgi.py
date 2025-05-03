from waitress import serve
from app import app  # assuming your Flask app is in app.py and called `app`

serve(app, host="0.0.0.0", port=10000)
