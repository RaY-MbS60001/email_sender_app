#!/usr/bin/env python3
"""
Flask e-mail learnership portal – production-ready version
"""
import os
import re
import json
import base64
import logging
import secrets
import threading
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from sqlalchemy import desc

# ───────────────────────────────
# Logging
# ───────────────────────────────
def setup_logging() -> None:
    """Configure console + rotating-file logging."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    )

    # Add a rotating file handler
    try:
        file_handler = RotatingFileHandler(
            "app.log", maxBytes=5 * 1024 * 1024, backupCount=3
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s  %(levelname)-8s  %(name)s — %(message)s")
        )
        file_handler.setLevel(log_level)
        logging.getLogger().addHandler(file_handler)
    except Exception as e:  # noqa: BLE001
        logging.getLogger(__name__).warning("File logging not available: %s", e)


setup_logging()
logger = logging.getLogger(__name__)

# ───────────────────────────────
# Flask config
# ───────────────────────────────
app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static",
)

# Session / DB
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32),  # fall-back for local dev
)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///email_sender.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(days=31)

db = SQLAlchemy(app)

# Uploads
UPLOAD_FOLDER = "uploaded_cvs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ───────────────────────────────
# Google OAuth settings
# ───────────────────────────────
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
]

# Render and other reverse proxies set this header;
# conversion is handled later
TRUSTED_HTTPS_HEADER = "X-Forwarded-Proto"

def get_redirect_uri() -> str:
    """Return correct redirect URI for current environment."""
    return os.environ.get(
        "OAUTH_REDIRECT_URI",
        "http://localhost:5000/oauth2callback",
    )


def load_client_secrets() -> str:
    """
    Ensure credentials.json exists.
    Option-1: supply JSON via env variable GOOGLE_CLIENT_SECRETS.
    Option-2: mount / commit credentials.json next to source.
    """
    if os.path.exists("credentials.json"):
        return "credentials.json"

    secrets_env = os.environ.get("GOOGLE_CLIENT_SECRETS")
    if secrets_env:
        try:
            data = json.loads(secrets_env)
            with open("credentials.json", "w", encoding="utf-8") as fp:
                json.dump(data, fp)
            logger.info("client_secrets created from environment variable")
            return "credentials.json"
        except Exception as exc:  # noqa: BLE001
            logger.error("Invalid GOOGLE_CLIENT_SECRETS: %s", exc)
            raise

    raise FileNotFoundError("Google OAuth credentials not provided.")


CLIENT_SECRETS_FILE = load_client_secrets()

# Allow HTTP callback ONLY for local development
if os.environ.get("FLASK_ENV") != "production":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# ───────────────────────────────
# Admin settings
# ───────────────────────────────
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "adminpass123")
LEARNERSHIPS_JSON_PATH = "learnerships.json"

# ───────────────────────────────
# Database models
# ───────────────────────────────
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255))
    token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text)
    token_uri = db.Column(db.Text)
    client_id = db.Column(db.Text)
    client_secret = db.Column(db.Text)
    scopes = db.Column(db.Text)
    batches = db.relationship("Batch", backref="client")


class Batch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    cv_filename = db.Column(db.String(255))
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime)
    emails = db.relationship("BatchEmail", backref="batch", cascade="all, delete-orphan")


class BatchEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey("batch.id"), nullable=False)
    recipient_email = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default="pending")
    error = db.Column(db.Text)

# ───────────────────────────────
# Helper utilities
# ───────────────────────────────
email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def is_valid_email(address: str) -> bool:
    return bool(email_regex.match(address.strip()))


def load_learnerships():
    try:
        json_path = os.path.join(os.path.dirname(__file__), LEARNERSHIPS_JSON_PATH)
        if not os.path.exists(json_path):
            logger.error("Learnership file missing: %s", json_path)
            return [], []

        with open(json_path, encoding="utf-8") as fp:
            data = json.load(fp)

        return (
            data.get("learnerships", []) if isinstance(data, dict) else [],
            data.get("categories", []) if isinstance(data, dict) else [],
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load learnerships: %s", exc, exc_info=True)
        return [], []


# ───────────────────────────────
# Google mail helpers
# ───────────────────────────────
def create_message_with_attachment(
    to_email: str,
    subject: str,
    body: str,
    attachment_path: str | None = None,
) -> dict:
    msg = MIMEMultipart()
    msg["to"] = to_email
    msg["subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if attachment_path and os.path.exists(attachment_path):
        filename = os.path.basename(attachment_path)
        with open(attachment_path, "rb") as fp:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(fp.read())

        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
        msg.attach(part)

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return {"raw": raw}


def send_email_gmail_api(creds, to_email, subject, body, attachment_path=None):
    try:
        service = googleapiclient.discovery.build("gmail", "v1", credentials=creds)
        message = create_message_with_attachment(
            to_email, subject, body, attachment_path
        )
        sent = (
            service.users().messages().send(userId="me", body=message).execute()
        )  # noqa: S607
        logger.info("Mail sent to %s. Gmail id=%s", to_email, sent["id"])
        return True, None
    except Exception as exc:  # noqa: BLE001
        logger.error("Gmail send failed for %s: %s", to_email, exc)
        return False, str(exc)


# ───────────────────────────────
# Decorators
# ───────────────────────────────
def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


# ───────────────────────────────
# Background task
# ───────────────────────────────
def send_batch_emails_async(batch_id):
    with app.app_context():
        batch = Batch.query.get(batch_id)
        if not batch or batch.status != "approved":
            logger.warning("Batch %s not approved or missing", batch_id)
            return

        # Avoid accidental double send
        if batch.status == "sending":
            return

        batch.status = "sending"
        db.session.commit()

        client = batch.client
        if not client:
            batch.status = "failed"
            db.session.commit()
            return

        try:
            creds = google.oauth2.credentials.Credentials(
                token=client.token,
                refresh_token=client.refresh_token,
                token_uri=client.token_uri,
                client_id=client.client_id,
                client_secret=client.client_secret,
                scopes=client.scopes.split(),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Credential build failed: %s", exc)
            batch.status = "failed"
            db.session.commit()
            return

        cv = (
            os.path.join(app.config["UPLOAD_FOLDER"], batch.cv_filename)
            if batch.cv_filename
            else None
        )
        if cv and not os.path.isfile(cv):
            logger.warning("Attachment missing: %s", cv)
            cv = None

        ok, bad = 0, 0
        for be in batch.emails:
            if be.status in ("sent", "failed"):
                continue
            success, err = send_email_gmail_api(
                creds, be.recipient_email, batch.subject, batch.body, cv
            )
            if success:
                be.status = "sent"
                ok += 1
            else:
                be.status = "failed"
                be.error = err
                bad += 1
            db.session.commit()

        batch.status = "completed"
        batch.sent_at = datetime.utcnow()
        db.session.commit()
        logger.info("Batch %s finished: %s sent, %s failed", batch_id, ok, bad)


# ───────────────────────────────
# Routes – static pages
# ───────────────────────────────
@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/help")
def help_page():
    return render_template("help.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# ───────────────────────────────
# Routes – auth & home
# ───────────────────────────────
@app.route("/")
def index():
    if "client_id" in session:
        return redirect(url_for("submit_batch"))
    return render_template("index.html")


@app.route("/client/login")
def client_login():
    if "client_id" in session:
        flash("Already logged in.", "info")
        return redirect(url_for("submit_batch"))

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES
    )
    flow.redirect_uri = get_redirect_uri()

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    if session.get("state") != request.args.get("state"):
        flash("Invalid state parameter.", "danger")
        return redirect(url_for("client_login"))
    session.pop("state", None)

    # Build flow again using same state
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=request.args.get("state")
    )
    flow.redirect_uri = get_redirect_uri()

    # Render/other proxies forward original scheme
    auth_resp = request.url
    if request.headers.get(TRUSTED_HTTPS_HEADER) == "https":
        auth_resp = auth_resp.replace("http://", "https://", 1)

    try:
        flow.fetch_token(authorization_response=auth_resp)
    except Exception as exc:  # noqa: BLE001
        logger.error("Token fetch failed: %s", exc, exc_info=True)
        flash("Authentication failed.", "danger")
        return redirect(url_for("client_login"))

    creds = flow.credentials
    oauth2 = googleapiclient.discovery.build("oauth2", "v2", credentials=creds)
    info = oauth2.userinfo().get().execute()  # noqa: S607

    google_id = info["id"]
    email = info["email"]
    name = info.get("name", "User")

    client = Client.query.filter_by(google_id=google_id).first()
    token_data = dict(
        token=creds.token,
        refresh_token=creds.refresh_token or (client.refresh_token if client else None),
        token_uri=creds.token_uri,
        client_id=creds.client_id,
        client_secret=creds.client_secret,
        scopes=" ".join(creds.scopes),
    )

    if client:
        for k, v in token_data.items():
            if k == "refresh_token" and v is None:
                continue
            setattr(client, k, v)
        client.email = email
        client.name = name
    else:
        client = Client(google_id=google_id, email=email, name=name, **token_data)
        db.session.add(client)

    db.session.commit()
    session["client_id"] = client.id
    session.permanent = True
    flash(f"Welcome {name}!", "success")
    return redirect(url_for("submit_batch"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ───────────────────────────────
# Routes – admin
# ───────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        if request.form.get("admin_password") == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            flash("Admin logged in.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Incorrect password.", "danger")
    return render_template("admin_login.html")


@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    batches = Batch.query.order_by(Batch.created_at.desc()).all()
    return render_template("admin_dashboard.html", batches=batches)


@app.route("/admin/batch/<int:batch_id>", methods=["GET", "POST"])
@admin_required
def admin_batch_detail(batch_id):
    batch = Batch.query.get_or_404(batch_id)

    if request.method == "POST":
        action = request.form.get("action")
        if batch.status == "pending":
            if action == "approve":
                batch.status = "approved"
                db.session.commit()
                threading.Thread(
                    target=send_batch_emails_async, args=(batch.id,), daemon=True
                ).start()
                flash("Batch approved – sending started.", "success")
            elif action == "reject":
                batch.status = "rejected"
                db.session.commit()
                flash("Batch rejected.", "warning")
        else:
            flash("Action not allowed for current status.", "info")

        return redirect(url_for("admin_batch_detail", batch_id=batch.id))

    return render_template("admin_batch_detail.html", batch=batch)


# ───────────────────────────────
# Routes – client submission
# ───────────────────────────────
@app.route("/submit", methods=["GET", "POST"])
def submit_batch():
    if "client_id" not in session:
        flash("Please login.", "warning")
        return redirect(url_for("index"))

    learnerships, categories = load_learnerships()
    if not learnerships:
        learnerships = [
            dict(
                id=0,
                company="Placeholder Co.",
                program="Placeholder Program",
                email="placeholder@example.com",
                icon="default.png",
                category="Uncategorised",
            )
        ]
        categories = ["Uncategorised"]

    client = Client.query.get(session["client_id"])
    if not client:
        session.clear()
        flash("User not found; please login again.", "danger")
        return redirect(url_for("index"))

    latest_batch = (
        Batch.query.filter_by(client_id=client.id)
        .order_by(desc(Batch.created_at))
        .first()
    )

    sending_summary = None
    if latest_batch and latest_batch.status in (
        "approved",
        "sending",
        "completed",
        "failed",
    ):
        total = BatchEmail.query.filter_by(batch_id=latest_batch.id).count()
        sent = BatchEmail.query.filter_by(batch_id=latest_batch.id, status="sent").count()
        failed = BatchEmail.query.filter_by(
            batch_id=latest_batch.id, status="failed"
        ).count()
        sending_summary = dict(
            total=total,
            sent=sent,
            failed=failed,
            pending=total - sent - failed,
            status=latest_batch.status,
            created_at=latest_batch.created_at,
            sent_at=latest_batch.sent_at,
        )

    # POST – create new batch
    if request.method == "POST":
        if latest_batch and latest_batch.status in ("pending", "approved", "sending"):
            flash("Existing batch still processing.", "warning")
            return redirect(url_for("submit_batch"))

        chosen = request.form.getlist("learnerships[]")
        cv_file = request.files.get("cv_file")
        subject = request.form.get("subject")
        body = request.form.get("body")

        if not chosen or not cv_file or cv_file.filename == "" or not subject or not body:
            flash("All fields required.", "danger")
            return redirect(url_for("submit_batch"))

        if (
            "." not in cv_file.filename
            or cv_file.filename.rsplit(".", 1)[1].lower() not in {"pdf", "doc", "docx"}
        ):
            flash("Invalid CV file type.", "danger")
            return redirect(url_for("submit_batch"))

        filename = secure_filename(cv_file.filename)
        unique = f"{client.id}_{int(datetime.utcnow().timestamp())}_{filename}"
        cv_path = os.path.join(app.config["UPLOAD_FOLDER"], unique)
        cv_file.save(cv_path)

        batch = Batch(
            client=client, subject=subject, body=body, cv_filename=unique
        )
        db.session.add(batch)
        db.session.flush()

        valid_addresses = 0
        for lid in chosen:
            try:
                lid_int = int(lid)
            except ValueError:
                continue
            ls = next((l for l in learnerships if l["id"] == lid_int), None)
            if ls and is_valid_email(ls.get("email", "")):
                db.session.add(
                    BatchEmail(batch_id=batch.id, recipient_email=ls["email"])
                )
                valid_addresses += 1

        if valid_addresses == 0:
            db.session.rollback()
            os.remove(cv_path)
            flash("No valid e-mail addresses selected.", "danger")
            return redirect(url_for("submit_batch"))

        db.session.commit()
        flash("Batch submitted – awaiting admin approval.", "success")
        return redirect(url_for("submit_batch"))

    return render_template(
        "submit.html",
        learnerships=learnerships,
        categories=categories,
        batch_status=latest_batch.status if latest_batch else None,
        sending_summary=sending_summary,
    )


# ───────────────────────────────
# Misc / static helpers
# ───────────────────────────────
@app.route("/debug/learnerships")
def debug_learnerships():
    l, c = load_learnerships()
    return jsonify(learnerships=l, categories=c, counts=dict(learnerships=len(l), categories=len(c)))


@app.route("/static/icons/<path:filename>")
def serve_icon(filename):
    icon_dir = os.path.join(app.static_folder, "icons")
    full = os.path.join(icon_dir, filename)
    if not os.path.isfile(full):
        filename = "default.png"
    return send_from_directory(icon_dir, filename)


def create_default_icon():
    """Generate a simple default.png if missing."""
    path = os.path.join("static", "icons", "default.png")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        return
    try:
        from PIL import Image, ImageDraw  # type: ignore
        img = Image.new("RGBA", (64, 64), (200, 200, 200, 255))
        d = ImageDraw.Draw(img)
        d.ellipse((8, 8, 56, 56), fill=(120, 120, 120, 255))
        img.save(path)
        logger.info("Default icon generated.")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not create default icon: %s", exc)


create_default_icon()

# ───────────────────────────────
# Global error handler
# ───────────────────────────────
@app.errorhandler(Exception)
def handle_error(err):
    logger.error("Unhandled exception: %s", err, exc_info=True)
    return render_template("error.html", error=str(err)), 500


# ───────────────────────────────
# Run app
# ───────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    os.makedirs(os.path.join("static", "icons"), exist_ok=True)

    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(host=host, port=port, debug=debug)