import os
import re
import json
import logging
import threading
import base64
from datetime import datetime, timedelta # Import timedelta
# Removed: from venv import logger # Incorrect import
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# Set up basic logging - this will capture logs from the application
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Use the root logger or get a specific logger instance
# logger = logging.getLogger(__name__) # Optional: get a specific logger

from sqlalchemy import desc # Import desc for ordering
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

import secrets
print(secrets.token_hex(32))
# Allow OAuthlib to use HTTP localhost (development only)
# IMPORTANT: Remove or set to '0' in production environments!
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# App configuration
app = Flask(__name__,
            static_folder='static',  # Specify the static folder
            static_url_path='/static')  # Specify the URL path for static files
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'b51ab4564ed11a1b9bdb9081a2e13ecb967bddd08ac0be4460fbbf0caad314a0')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///email_sender.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure permanent session lifetime (e.g., 31 days)
# This requires session.permanent = True to be set for a specific session
app.permanent_session_lifetime = timedelta(days=31)

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file('credentials.json',
    scopes=['https://www.googleapis.com/auth/drive.metadata.readonly',
            'https://www.googleapis.com/auth/calendar.readonly'])

flow.redirect_uri = 'https://codecraftco.onrender.com/oauth2callback'

# Generate URL for request to Google's OAuth 2.0 server.
# Use kwargs to set optional request parameters.
authorization_url, state = flow.authorization_url(
    # Recommended, enable offline access so that you can refresh an access token without
    # re-prompting the user for permission. Recommended for web server apps.
    access_type='offline',
    # Optional, enable incremental authorization. Recommended as a best practice.
    include_granted_scopes='true',
    # Optional, if your application knows which user is trying to authenticate, it can use this
    # parameter to provide a hint to the Google Authentication Server.
    login_hint='hint@example.com',
    # Optional, set prompt to 'consent' will prompt the user for consent
    prompt='consent')


UPLOAD_FOLDER = 'uploaded_cvs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# Google OAuth Config
CLIENT_SECRETS_FILE = "credentials.json"
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid',
]
# Make sure this REDIRECT_URI matches the one configured in your Google Cloud Console
REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI', 'https://codecraftco.onrender.com/oauth2callback')

# Admin credentials
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'adminpass123') # Consider using env var for production
LEARNERSHIPS_JSON_PATH = 'learnerships.json'

# Make redirect URI dynamic based on environment
def get_redirect_uri():
    if os.environ.get('FLASK_ENV') == 'production':
        return 'http://codecraftco.onrender.com/oauth2callback'
    return 'http://localhost:5000/oauth2callback'


def load_learnerships():
    """
    Load learnerships from JSON file with comprehensive error handling
    """
    try:
        # Ensure the file path is absolute or relative to the current script
        # os.path.dirname(__file__) gets the directory where the current script is
        json_path = os.path.join(os.path.dirname(__file__), LEARNERSHIPS_JSON_PATH)

        # Check if file exists before attempting to open
        if not os.path.exists(json_path):
            logging.error(f"Learnerships file not found: {json_path}")
            return [], []

        with open(json_path, 'r', encoding='utf-8') as f:
            # Add additional validation
            data = json.load(f)

            # Ensure data is a dictionary and has required keys
            if not isinstance(data, dict):
                logging.error("Invalid JSON structure")
                return [], []

            learnerships = data.get('learnerships', [])
            categories = data.get('categories', [])

            # Basic validation for learnerships structure
            if not isinstance(learnerships, list):
                 logging.error("'learnerships' key is not a list")
                 learnerships = []

            if not isinstance(categories, list):
                logging.error("'categories' key is not a list")
                categories = []

            logging.info(f"Successfully loaded {len(learnerships)} learnerships")
            logging.info(f"Successfully loaded {len(categories)} categories")

            return learnerships, categories

    except FileNotFoundError:
        logging.error(f"Learnerships JSON file not found at {json_path}")
        return [], []

    except json.JSONDecodeError as e:
        logging.error(f"JSON Parsing Error in {json_path}: {e}")
        return [], []

    except Exception as e:
        logging.error(f"Unexpected error loading learnerships from {json_path}: {e}")
        return [], []


# Models
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    token = db.Column(db.Text, nullable=False) # Google access token
    refresh_token = db.Column(db.Text, nullable=True) # Google refresh token
    token_uri = db.Column(db.Text, nullable=True) # Google token URI
    client_id = db.Column(db.Text, nullable=True) # Your Google OAuth client ID
    client_secret = db.Column(db.Text, nullable=True) # Your Google OAuth client secret
    scopes = db.Column(db.Text, nullable=True) # Scopes granted by the user
    batches = db.relationship('Batch', backref='client')

class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    cv_filename = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending') # e.g., 'pending', 'approved', 'rejected', 'sending', 'completed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime, nullable=True)
    emails = db.relationship('BatchEmail', backref='batch', cascade='all, delete-orphan')

class BatchEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey('batch.id'), nullable=False)
    recipient_email = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending') # e.g., 'pending', 'sent', 'failed'
    error = db.Column(db.Text) # Store error message if sending failed

# Utility Functions
def is_valid_email(email):
    """Basic email format validation"""
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email.strip()) is not None

def create_message_with_attachment(to_email, subject, body, attachment_path=None):
    """Creates a MIME message suitable for Gmail API, including an attachment"""
    message = MIMEMultipart()
    message['to'] = to_email
    message['subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    if attachment_path and os.path.exists(attachment_path):
        filename = os.path.basename(attachment_path)
        try:
            with open(attachment_path, 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            message.attach(part)
        except FileNotFoundError:
            logging.error(f"Attachment file not found: {attachment_path}")
        except Exception as e:
             logging.error(f"Error attaching file {attachment_path}: {e}")


    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_email_gmail_api(creds, to_email, subject, body, attachment_path=None):
    """Sends an email using the Gmail API with given credentials"""
    try:
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=creds)
        message = create_message_with_attachment(to_email, subject, body, attachment_path)
        # Note: The 'me' user ID refers to the authenticated user.
        sent_message = service.users().messages().send(userId='me', body=message).execute()
        logging.info(f"Message sent successfully to {to_email}. Message Id: {sent_message['id']}")
        return True # Indicate success
    except googleapiclient.errors.HttpError as error:
        logging.error(f'An API error occurred: {error}')
        return False, str(error) # Indicate failure and return error message
    except Exception as e:
        logging.error(f'An unexpected error occurred while sending email to {to_email}: {e}')
        return False, str(e) # Indicate failure and return error message


def admin_required(f):
    """Decorator to restrict routes to logged-in administrators."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash("Admin login required.", "warning")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def send_batch_emails_async(batch_id):
    """Background task to send emails for a batch after admin approval."""
    # Need app_context for SQLAlchemy and configuration access
    with app.app_context():
        batch = Batch.query.get(batch_id)
        if not batch or batch.status != 'approved':
            logging.warning(f"Batch {batch_id} not found or not approved for sending.")
            return

        # Prevent double-sending if task is somehow triggered twice
        if batch.status == 'sending':
             logging.info(f"Batch {batch.id} already in sending status.")
             return

        batch.status = 'sending'
        # Optionally, update sent_at now or per email
        db.session.commit() # Commit status change

        client = batch.client
        if not client:
            logging.error(f"Client not found for batch {batch.id}")
            batch.status = 'failed'
            db.session.commit()
            return

        try:
            # Create credentials object from stored data
            creds = google.oauth2.credentials.Credentials(
                token=client.token,
                refresh_token=client.refresh_token,
                token_uri=client.token_uri,
                client_id=client.client_id,
                client_secret=client.client_secret,
                scopes=client.scopes.split() # Ensure scopes are a list
            )

            # The credentials object will automatically handle token refresh if needed
            # when making API calls, using the stored refresh_token.
            # You might add logic here to explicitly refresh if creds.expired and creds.refresh_token is present,
            # and save the new token, but the google-auth library often handles this implicitly
            # during API execution if you pass the creds object.

        except Exception as e:
             logging.error(f"Failed to create credentials for client {client.id} (Batch {batch.id}): {e}")
             batch.status = 'failed'
             batch.error = f"Credential error: {e}"
             db.session.commit()
             return

        cv_path = os.path.join(app.config['UPLOAD_FOLDER'], batch.cv_filename) if batch.cv_filename else None
        if cv_path and not os.path.exists(cv_path):
             logging.warning(f"CV file not found for batch {batch.id}: {cv_path}")
             # Decide how to handle missing CV: skip batch, mark failed?
             # For now, log warning and continue without attachment for this batch.
             cv_path = None # Treat as no attachment


        success_count = 0
        failed_count = 0
        # Iterate through emails associated with this batch
        for email_entry in batch.emails:
            if email_entry.status in ('sent', 'failed'):
                 logging.info(f"Skipping email {email_entry.id} to {email_entry.recipient_email} in batch {batch.id} (already processed).")
                 continue # Skip if already sent or failed in a previous attempt (shouldn't happen in single run, but good for robustness)

            logging.info(f"Attempting to send email to {email_entry.recipient_email} for batch {batch.id}")
            send_success, error_message = send_email_gmail_api(
                creds,
                to_email=email_entry.recipient_email,
                subject=batch.subject,
                body=batch.body,
                attachment_path=cv_path
            )

            if send_success:
                email_entry.status = 'sent'
                success_count += 1
                logging.info(f"Successfully sent email to {email_entry.recipient_email}")
            else:
                email_entry.status = 'failed'
                email_entry.error = error_message if error_message else "Unknown error"
                failed_count += 1
                logging.error(f"Failed to send email to {email_entry.recipient_email}: {error_message}")

            # Commit frequently in a long-running task to save progress
            db.session.commit()

        # Update batch status once all emails are processed
        batch.status = 'completed'
        batch.sent_at = datetime.utcnow()
        db.session.commit()

        logging.info(f"Batch {batch.id} sending completed: {success_count} success, {failed_count} failed.")


# Static Page Routes
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Routes
@app.route('/')
def index():
    # Check if the client is already logged in via session
    if 'client_id' in session:
        logging.info(f"Client ID {session['client_id']} found in session. Redirecting to submit.")
        # If session is permanent, this check will persist login across browser restarts
        return redirect(url_for('submit_batch'))

    logging.info("No client ID in session. Rendering index page.")
    return render_template('index.html')

@app.route('/client/login')
def client_login():
    # Check if the client is already logged in before starting OAuth flow
    if 'client_id' in session:
         logging.info(f"Client ID {session['client_id']} already in session. Redirecting to submit.")
         flash("You are already logged in.", "info")
         return redirect(url_for('submit_batch'))

    logging.info("Initiating Google OAuth login flow.")
    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = get_redirect_uri()
        # 'access_type': 'offline' is crucial to get a refresh token
        # 'prompt': 'consent' ensures the user is shown the consent screen on the first login
        # If the user has already granted permission and 'prompt' is omitted or set to 'select_account',
        # Google might skip the consent screen.
        authorization_url, state = flow.authorization_url(
            access_type='offline', # Request refresh token
            include_granted_scopes='true', # Include all previously granted scopes
            prompt='consent' # Forces consent screen, can remove 'prompt' after initial testing
        )
        session['state'] = state
        return redirect(authorization_url)
    except FileNotFoundError:
        logging.error(f"Client secrets file not found at {CLIENT_SECRETS_FILE}")
        flash("Configuration error: Google credentials not found.", "danger")
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error initiating OAuth flow: {e}")
        flash("An error occurred initiating login. Please try again.", "danger")
        return redirect(url_for('index'))


@app.route('/oauth2callback')
def oauth2callback():
    # Log request details for debugging
    logging.info(f"OAuth callback received. URL: {request.url}")
    logging.info(f"Request headers: {dict(request.headers)}")
    logging.info(f"Environment: {os.environ.get('FLASK_ENV', 'prouction')}")

    stored_state = session.get('state')
    returned_state = request.args.get('state')

    logging.info(f"Stored state: {stored_state}")
    logging.info(f"Returned state: {returned_state}")

    if not stored_state or stored_state != returned_state:
        logging.error("State mismatch or missing")
        flash("Invalid state parameter. Please try again.", "danger")
        session.pop('state', None)
        return redirect(url_for('client_login'))

    session.pop('state', None)

    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=returned_state
        )

        # Set redirect URI based on environment
        if os.environ.get('FLASK_ENV') == 'production':
            redirect_uri = 'https://codecraftco.onrender.com/oauth2callback'
        else:
            redirect_uri = 'http://localhost:5000/oauth2callback'
        
        flow.redirect_uri = redirect_uri
        logging.info(f"Using redirect URI: {redirect_uri}")

        # Handle the authorization response
        authorization_response = request.url
        if request.headers.get('X-Forwarded-Proto') == 'https':
            authorization_response = request.url.replace('http://', 'https://')
        
        logging.info(f"Authorization response URL: {authorization_response}")

        # Fetch the token
        flow.fetch_token(authorization_response=authorization_response)
        creds = flow.credentials
        logging.info("Successfully obtained credentials")

        # Get user info
        oauth2client = googleapiclient.discovery.build("oauth2", "v2", credentials=creds)
        user_info = oauth2client.userinfo().get().execute()
        logging.info("Successfully retrieved user info")

        google_id = user_info.get("id")
        email = user_info.get("email")
        name = user_info.get("name", "User")

        if not google_id or not email:
            logging.error("Missing user info fields")
            flash("Could not retrieve user information.", "danger")
            return redirect(url_for('client_login'))

        # Check existing client
        client = Client.query.filter_by(google_id=google_id).first()
        
        # Prepare token data
        token_data = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': " ".join(creds.scopes) if creds.scopes else None
        }

        if client:
            logging.info(f"Updating existing client: {client.id}")
            for key, value in token_data.items():
                if key == 'refresh_token' and value is None:
                    continue
                setattr(client, key, value)
            client.email = email
            client.name = name
        else:
            logging.info(f"Creating new client for: {email}")
            client = Client(
                google_id=google_id,
                email=email,
                name=name,
                **token_data
            )
            db.session.add(client)

        db.session.commit()
        logging.info(f"Database updated for client: {client.id}")

        # Set session
        session['client_id'] = client.id
        session.permanent = True
        logging.info(f"Session established for client: {client.id}")

        flash(f"Welcome, {name}! You are now logged in.", "success")
        return redirect(url_for('submit_batch'))

    except Exception as e:
        logging.error(f"Error in oauth2callback: {str(e)}", exc_info=True)
        flash("An error occurred during login. Please try again.", "danger")
        return redirect(url_for('client_login'))
    except googleapiclient.errors.FlowExchangeError as e:
         logging.error(f"OAuth token exchange failed: {e}")
         flash("Failed to get login tokens from Google. Please try again.", "danger")
         return redirect(url_for('client_login'))
    except FileNotFoundError:
        logging.error(f"Client secrets file not found during callback: {CLIENT_SECRETS_FILE}")
        flash("Configuration error during login. Please try again.", "danger")
        return redirect(url_for('client_login'))
    except Exception as e:
        # Catch any other unexpected errors during the process
        logging.error(f"Unexpected error during OAuth callback: {str(e)}")
        flash("An error occurred during login. Please try again.", "danger")
        return redirect(url_for('client_login'))


@app.route('/logout')
def logout():
    logging.info(f"Logging out client ID: {session.get('client_id')}")
    session.clear() # Clears all session data, including 'client_id' and 'permanent' flag
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
         flash("You are already logged in as admin.", "info")
         return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        password_attempt = request.form.get('admin_password')
        if password_attempt == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            # Admin session does not need to be permanent unless explicitly desired
            # session.permanent = True # Optional for admin session
            logging.info("Admin logged in successfully.")
            flash("Admin login successful.", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            logging.warning("Failed admin login attempt.")
            flash("Incorrect password.", "danger")

    return render_template('admin_login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
     logging.info("Admin logging out.")
     session.pop('admin_logged_in', None)
     flash("Admin logged out.", "info")
     return redirect(url_for('admin_login'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    # Order batches by creation date descending
    batches = Batch.query.order_by(Batch.created_at.desc()).all()
    return render_template('admin_dashboard.html', batches=batches)

@app.route('/admin/batch/<int:batch_id>', methods=['GET', 'POST'])
@admin_required
def admin_batch_detail(batch_id):
    batch = Batch.query.get_or_404(batch_id)
    if request.method == 'POST':
        action = request.form.get('action')
        logging.info(f"Admin action '{action}' requested for batch {batch_id} (current status: {batch.status}).")

        if batch.status == 'pending':
            if action == 'approve':
                batch.status = 'approved'
                db.session.commit()
                flash(f"Batch {batch.id} approved.", "success")
                # Start sending in a background thread immediately upon approval
                threading.Thread(target=send_batch_emails_async, args=(batch.id,)).start()
                flash("Sending emails for this batch has started in the background.", "info")
            elif action == 'reject':
                batch.status = 'rejected'
                db.session.commit()
                flash(f"Batch {batch.id} rejected.", "warning")
            else:
                flash("Invalid action.", "danger")
        elif batch.status in ('approved', 'sending', 'completed'):
             flash(f"Batch {batch.id} cannot be approved or rejected (current status: {batch.status}).", "warning")
        else: # Rejected status
             flash(f"Batch {batch.id} has already been rejected.", "warning")


        return redirect(url_for('admin_batch_detail', batch_id=batch.id))

    # For GET request, render the detail page
    return render_template('admin_batch_detail.html', batch=batch)


@app.route('/submit', methods=['GET', 'POST'])
def submit_batch():
    # Check if client is logged in using the persistent session
    if 'client_id' not in session:
        logging.warning("Access to submit page without client_id in session. Redirecting to index.")
        flash("Please login first.", "warning")
        return redirect(url_for('index'))

    # Load learnerships and categories
    learnerships, categories = load_learnerships()

    # Provide fallback data if loading fails or file is empty
    if not learnerships:
        app.logger.warning("Learnerships data is empty or failed to load.")
        learnerships = [
            {
                "id": 0,
                "company": "Placeholder Company",
                "program": "Placeholder Program",
                "email": "placeholder@example.com",
                "icon": "default.png", # Use default icon
                "category": "Uncategorized"
            }
        ]
    if not categories:
        app.logger.warning("Categories data is empty or failed to load.")
        categories = ["Uncategorized"]

    client = Client.query.get(session['client_id'])
    if not client:
        # This case indicates a potential issue (client_id in session but no matching user in DB)
        logging.error(f"Client with ID {session['client_id']} not found in database despite session.")
        session.clear() # Clear invalid session
        flash("Your user data was not found. Please log in again.", "danger")
        return redirect(url_for('index'))


    # Fetch the latest batch for this client for status display
    latest_batch = (
        Batch.query.filter_by(client_id=client.id)
        .order_by(desc(Batch.created_at)) # Order by creation date, latest first
        .first()
    )

    batch_status = None
    sending_summary = None
    if latest_batch:
        batch_status = latest_batch.status
        logging.info(f"Latest batch for client {client.id} is batch {latest_batch.id} with status: {batch_status}")

        # Build sending summary for relevant statuses
        if batch_status in ('approved', 'sending', 'completed', 'failed'): # Include failed batches to show attempt status
             total_emails = db.session.query(BatchEmail).filter_by(batch_id=latest_batch.id).count()
             sent_count = db.session.query(BatchEmail).filter_by(batch_id=latest_batch.id, status='sent').count()
             failed_count = db.session.query(BatchEmail).filter_by(batch_id=latest_batch.id, status='failed').count()
             pending_count = total_emails - sent_count - failed_count # Emails that haven't been processed yet in 'sending' state

             sending_summary = {
                'total': total_emails,
                'sent': sent_count,
                'failed': failed_count,
                'pending': pending_count, # Useful for 'sending' state
                'status': batch_status, # Pass the batch status as well
                'created_at': latest_batch.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'sent_at': latest_batch.sent_at.strftime('%Y-%m-%d %H:%M:%S') if latest_batch.sent_at else 'N/A'
             }
             logging.debug(f"Sending summary for batch {latest_batch.id}: {sending_summary}")

    if request.method == 'POST':
        # Prevent new submission if the latest batch is still pending or sending
        if latest_batch and latest_batch.status in ('pending', 'approved', 'sending'):
             flash("You have a pending or active application batch. Please wait for it to be processed.", "warning")
             logging.warning(f"Client {client.id} attempted to submit new batch while latest batch {latest_batch.id} is {latest_batch.status}.")
             return redirect(url_for('submit_batch'))


        selected_learnership_ids = request.form.getlist('learnerships[]')
        cv_file = request.files.get('cv_file')
        subject = request.form.get('subject')
        body = request.form.get('body')

        if not selected_learnership_ids:
            flash("Please select at least one learnership.", "danger")
            return redirect(url_for('submit_batch'))

        if not cv_file or cv_file.filename == '':
            flash("Please upload your CV.", "danger")
            return redirect(url_for('submit_batch'))

        if not subject or not body:
            flash("Subject and body are required.", "danger")
            return redirect(url_for('submit_batch'))

        # Basic CV file type validation (optional but recommended)
        allowed_extensions = {'pdf', 'doc', 'docx'}
        if '.' not in cv_file.filename or cv_file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
             flash("Invalid file type. Please upload a PDF, DOC, or DOCX file.", "danger")
             return redirect(url_for('submit_batch'))


        try:
            # Securely save the CV file
            filename = secure_filename(cv_file.filename)
            # Prepend client ID or timestamp to filename to avoid conflicts if multiple clients upload files with the same name
            # Adding a unique prefix ensures filenames are distinct, even if clients have same original filename
            unique_filename = f"{client.id}_{int(datetime.utcnow().timestamp())}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

            cv_file.save(filepath)
            logging.info(f"CV saved to {filepath}")


            # Create a new batch record
            batch = Batch(
                client=client,
                subject=subject,
                body=body,
                cv_filename=unique_filename, # Save the unique filename
                status='pending',
                created_at=datetime.utcnow()
            )
            db.session.add(batch)
            db.session.flush() # Assigns an ID to the batch before adding emails

            # Add recipient emails for each selected learnership
            added_emails = 0
            for learnership_id_str in selected_learnership_ids:
                try:
                    learnership_id = int(learnership_id_str)
                    learnership = next((l for l in learnerships if l['id'] == learnership_id), None)
                    if learnership and is_valid_email(learnership.get('email')):
                        email_entry = BatchEmail(
                            batch_id=batch.id, # Link to the created batch
                            recipient_email=learnership['email'],
                            status='pending'
                        )
                        db.session.add(email_entry)
                        added_emails += 1
                    elif learnership:
                        logging.warning(f"Learnership ID {learnership_id} has invalid or missing email: {learnership.get('email')}")
                    else:
                        logging.warning(f"Learnership ID {learnership_id} not found in loaded data.")

                except ValueError:
                    logging.warning(f"Invalid learnership ID received: {learnership_id_str}")
                    flash(f"Skipping invalid learnership selection: {learnership_id_str}", "warning")

            if added_emails == 0:
                # If no valid emails were added, abort the batch
                db.session.rollback() # Rollback the batch creation and any associated emails
                # Clean up the uploaded file if no batch was created
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        logging.info(f"Removed orphaned CV file: {filepath}")
                    except Exception as remove_e:
                        logging.error(f"Error removing orphaned CV file {filepath}: {remove_e}")

                flash("No valid learnership emails were selected or found. Application not submitted.", "danger")
                logging.error(f"Batch creation aborted for client {client.id}: no valid emails added.")
                return redirect(url_for('submit_batch'))


            db.session.commit() # Commit the batch and all associated emails

            flash("Application batch submitted successfully! Awaiting admin approval.", "success")
            logging.info(f"Batch {batch.id} created for client {client.id} with {added_emails} recipients.")
            return redirect(url_for('submit_batch'))

        except Exception as e:
            # Catch any exception during processing, rollback transaction
            db.session.rollback()
            logging.error(f"Error during batch submission for client {client.id}: {str(e)}", exc_info=True)
            flash(f"Error submitting application: {str(e)}", "danger")

            # Attempt to clean up the uploaded file if it exists and error occurred after saving
            if 'filepath' in locals() and os.path.exists(filepath):
                 try:
                     os.remove(filepath)
                     logging.info(f"Removed orphaned CV file after error: {filepath}")
                 except Exception as remove_e:
                     logging.error(f"Error removing orphaned CV file {filepath} after error: {remove_e}")

            return redirect(url_for('submit_batch'))

    # For GET request, render the submission form
    return render_template(
        'submit.html',
        learnerships=learnerships,
        categories=categories,
        batch_status=batch_status,
        sending_summary=sending_summary
    )

# Debug route for learnerships
@app.route('/debug/learnerships')
def debug_learnerships():
    """Helper route to view loaded learnership data."""
    learnerships, categories = load_learnerships()
    return jsonify({
        "learnerships_count": len(learnerships),
        "categories_count": len(categories),
        "learnerships": learnerships,
        "categories": categories
    })


# Route to serve icons from the static/icons folder
@app.route('/static/icons/<path:filename>')
def serve_icon(filename):
    """Serves icon files from the static/icons directory."""
    try:
        icon_path = os.path.join(app.static_folder, 'icons')
        logging.debug(f"Attempting to serve icon: {filename} from {icon_path}")

        # Ensure the requested filename is within the icons directory (handled by send_from_directory security)
        # Check if the specific file exists, otherwise serve default
        full_file_path = os.path.join(icon_path, filename)
        if not os.path.exists(full_file_path) or not os.path.isfile(full_file_path):
            logging.warning(f"Icon not found: {filename}. Serving default.png.")
            filename = 'default.png'
            # Ensure default.png exists in the icons directory
            if not os.path.exists(os.path.join(icon_path, filename)):
                 logging.error(f"Default icon not found at {os.path.join(icon_path, filename)}.")
                 # Fallback if default icon is also missing
                 return '', 404


        return send_from_directory(icon_path, filename)

    except Exception as e:
        logging.error(f"Error serving icon {filename}: {e}")
        return '', 500 # Internal server error


def create_default_icon():
    """Creates a simple default icon if it doesn't exist."""
    icon_dir = os.path.join('static', 'icons')
    default_icon_path = os.path.join(icon_dir, 'default.png')

    if os.path.exists(default_icon_path):
        logging.info("Default icon already exists.")
        return

    logging.info("Creating default icon...")
    try:
        from PIL import Image, ImageDraw

        # Create a 32x32 pixel icon
        image = Image.new('RGBA', (32, 32), color=(200, 200, 200, 255)) # Light gray background
        draw = ImageDraw.Draw(image)

        # Draw a simple shape (e.g., a circle)
        draw.ellipse([4, 4, 28, 28], fill=(100, 100, 100, 255), outline=(50, 50, 50, 255))

        # Ensure the static/icons directory exists
        os.makedirs(icon_dir, exist_ok=True)

        # Save the icon
        image.save(default_icon_path)
        logging.info(f"Default icon created successfully at {default_icon_path}.")
    except ImportError:
        logging.warning("Pillow (PIL) library not found. Cannot create default icon. Install with 'pip install Pillow'.")
    except Exception as e:
        logging.error(f"Error creating default icon: {e}")


# Ensure the default icon is created when the script runs
create_default_icon()


if __name__ == "__main__":
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        logging.info("Database tables checked/created.")

    # Ensure static/icons directory exists at runtime
    os.makedirs('static/icons', exist_ok=True)
    logging.info("Static/icons directory ensured.")
  

    # Run the Flask development server
    
    # In production, use a production-ready server like Gunicorn/Waitress
    if os.environ.get('FLASK_ENV') == 'production':
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
    else:
        app.run()