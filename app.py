
import os
import smtplib
import mimetypes
import socket
from pathlib import Path
from email.message import EmailMessage
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-development-only-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///securemail.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ATTACHMENT_FOLDER = Path(app.instance_path) / "mail_attachments"
ATTACHMENT_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg"}
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    attachments = db.relationship("Attachment", backref="email", lazy=True)

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(120), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)

class NetworkLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(120), nullable=False)
    receiver = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    protocol = db.Column(db.String(20), default="SMTP")
    port = db.Column(db.Integer, default=1025)
    status = db.Column(db.String(30), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def record_network_log(sender, receiver, subject, status, details):
    try:
        log = NetworkLog(
            sender=sender,
            receiver=receiver,
            subject=subject[:200],
            protocol="SMTP",
            port=1025,
            status=status,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Could not save network log")

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or len(password) < 8:
            flash("Enter valid details and a password of at least 8 characters.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "error")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password!", "error")

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    inbox_count = Email.query.filter_by(receiver_id=current_user.id).count()
    sent_count = Email.query.filter_by(sender_id=current_user.id).count()
    recent_emails = Email.query.filter_by(
        receiver_id=current_user.id
    ).order_by(Email.sent_at.desc()).limit(5).all()

    return render_template(
        "dashboard.html",
        user=current_user,
        inbox_count=inbox_count,
        sent_count=sent_count,
        recent_emails=recent_emails
    )

@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    if request.method == "POST":
        receiver_email = request.form.get("receiver", "").strip().lower()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        uploaded_file = request.files.get("attachment")

        receiver = User.query.filter_by(email=receiver_email).first()

        if not receiver:
            flash("Recipient not found! Register the recipient first.", "error")
            return redirect(url_for("compose"))

        if not subject or not body:
            flash("Subject and message cannot be empty.", "error")
            return redirect(url_for("compose"))

        if len(subject) > 200:
            flash("Subject is too long.", "error")
            return redirect(url_for("compose"))

        message = EmailMessage()
        message["From"] = current_user.email
        message["To"] = receiver.email
        message["Subject"] = subject
        message.set_content(body)

        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)

            if not filename or "." not in filename:
                flash("Invalid attachment filename.", "error")
                return redirect(url_for("compose"))

            extension = filename.rsplit(".", 1)[1].lower()

            if extension not in ALLOWED_EXTENSIONS:
                flash("Only PDF, TXT, PNG, JPG and JPEG files are allowed.", "error")
                return redirect(url_for("compose"))

            file_data = uploaded_file.read(MAX_ATTACHMENT_SIZE + 1)

            if len(file_data) > MAX_ATTACHMENT_SIZE:
                flash("Attachment must be 10 MB or smaller.", "error")
                return redirect(url_for("compose"))

            content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            main_type, sub_type = content_type.split("/", 1)

            message.add_attachment(
                file_data,
                maintype=main_type,
                subtype=sub_type,
                filename=filename
            )

        try:
            with smtplib.SMTP("127.0.0.1", 1025, timeout=15) as smtp:
                smtp.send_message(message)

            record_network_log(
                current_user.email,
                receiver.email,
                subject,
                "SUCCESS",
                "SMTP session: EHLO, MAIL FROM, RCPT TO, DATA, QUIT. "
                "Server accepted the message."
            )

            flash("Email transmitted successfully through SMTP!", "success")
            return redirect(url_for("sent"))

        except (smtplib.SMTPException, OSError) as error:
            record_network_log(
                current_user.email,
                receiver.email,
                subject,
                "FAILED",
                f"SMTP delivery attempt failed: {type(error).__name__}"
            )
            app.logger.error("SMTP error: %s", error)
            flash("SMTP delivery failed. Check the SMTP server.", "error")
            return redirect(url_for("compose"))

    return render_template("compose.html", user=current_user)

@app.route("/inbox")
@login_required
def inbox():
    emails = Email.query.filter_by(
        receiver_id=current_user.id
    ).order_by(Email.sent_at.desc()).all()
    return render_template("inbox.html", user=current_user, emails=emails)

@app.route("/sent")
@login_required
def sent():
    emails = Email.query.filter_by(
        sender_id=current_user.id
    ).order_by(Email.sent_at.desc()).all()
    return render_template("sent.html", user=current_user, emails=emails)

@app.route("/attachments")
@login_required
def attachments():
    files = (
        Attachment.query.join(Email)
        .filter(
            (Email.sender_id == current_user.id) |
            (Email.receiver_id == current_user.id)
        )
        .order_by(Attachment.id.desc())
        .all()
    )
    return render_template("attachments.html", user=current_user, files=files)

@app.route("/download/<int:attachment_id>")
@login_required
def download_attachment(attachment_id):
    attachment = db.get_or_404(Attachment, attachment_id)
    email = attachment.email

    if current_user.id not in (email.sender_id, email.receiver_id):
        abort(403)

    file_path = ATTACHMENT_FOLDER / attachment.stored_name

    if not file_path.is_file():
        abort(404)

    return send_file(
        file_path,
        as_attachment=True,
        download_name=attachment.filename,
        mimetype=attachment.content_type
    )

@app.route("/network")
@login_required
def network():
    logs = NetworkLog.query.filter(
        (NetworkLog.sender == current_user.email) |
        (NetworkLog.receiver == current_user.email)
    ).order_by(NetworkLog.timestamp.desc()).limit(100).all()

    success_count = sum(1 for log in logs if log.status == "SUCCESS")
    failed_count = sum(1 for log in logs if log.status == "FAILED")

    try:
        with socket.create_connection(("127.0.0.1", 1025), timeout=1):
            smtp_online = True
    except OSError:
        smtp_online = False

    return render_template(
        "network.html",
        user=current_user,
        logs=logs,
        success_count=success_count,
        failed_count=failed_count,
        smtp_online=smtp_online
    )

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
