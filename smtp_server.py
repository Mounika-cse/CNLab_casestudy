
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from aiosmtpd.controller import Controller
from app import app, db, User, Email, Attachment, ATTACHMENT_FOLDER, ALLOWED_EXTENSIONS, MAX_ATTACHMENT_SIZE
from werkzeug.utils import secure_filename

class SecureMailHandler:
    async def handle_DATA(self, server, session, envelope):
        saved_paths = []

        try:
            message = BytesParser(policy=policy.default).parsebytes(
                envelope.content
            )

            sender = envelope.mail_from.strip().lower()
            recipients = [
                address.strip().lower()
                for address in envelope.rcpt_tos
            ]

            subject = str(message.get("Subject", ""))

            if len(subject) > 200:
                return "552 Subject is too long"

            body_part = message.get_body(preferencelist=("plain",))
            body = body_part.get_content() if body_part else ""

            if not isinstance(body, str):
                body = str(body)

            attachment_data = []

            for part in message.iter_attachments():
                original_name = part.get_filename()

                if not original_name:
                    return "550 Attachment filename is missing"

                filename = secure_filename(original_name)

                if not filename or "." not in filename:
                    return "550 Invalid attachment filename"

                extension = filename.rsplit(".", 1)[1].lower()

                if extension not in ALLOWED_EXTENSIONS:
                    return "550 Attachment type not allowed"

                data = part.get_payload(decode=True)

                if data is None:
                    return "550 Invalid attachment data"

                if len(data) > MAX_ATTACHMENT_SIZE:
                    return "552 Attachment exceeds size limit"

                attachment_data.append((
                    filename,
                    part.get_content_type(),
                    data
                ))

            with app.app_context():
                sender_user = User.query.filter_by(email=sender).first()

                if not sender_user:
                    return "550 Sender is not registered"

                receiver_users = []

                for address in recipients:
                    receiver = User.query.filter_by(email=address).first()

                    if not receiver:
                        return "550 Recipient is not registered"

                    receiver_users.append(receiver)

                for receiver in receiver_users:
                    email_record = Email(
                        sender_id=sender_user.id,
                        receiver_id=receiver.id,
                        subject=subject,
                        body=body,
                        sent_at=datetime.now(timezone.utc)
                    )

                    db.session.add(email_record)
                    db.session.flush()

                    for filename, content_type, data in attachment_data:
                        stored_name = uuid.uuid4().hex + "_" + filename
                        file_path = ATTACHMENT_FOLDER / stored_name

                        with open(file_path, "wb") as output:
                            output.write(data)

                        saved_paths.append(file_path)

                        attachment = Attachment(
                            email_id=email_record.id,
                            filename=filename,
                            stored_name=stored_name,
                            content_type=content_type,
                            file_size=len(data)
                        )
                        db.session.add(attachment)

                db.session.commit()

            print(f"SMTP: {sender} -> {', '.join(recipients)}")
            print(f"Subject: {subject}")
            print(f"Attachments: {len(attachment_data)}")
            print("Message delivered successfully.\n")

            return "250 Message accepted for delivery"

        except Exception as error:
            with app.app_context():
                db.session.rollback()

            for path in saved_paths:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass

            print("SMTP delivery error:", error)
            return "451 Temporary delivery failure"

if __name__ == "__main__":
    controller = Controller(
        SecureMailHandler(),
        hostname="127.0.0.1",
        port=1025
    )

    controller.start()
    print("SecureMail SMTP Server running on 127.0.0.1:1025")
    print("MIME attachment support enabled")
    print("Press Ctrl+C to stop.")

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        controller.stop()
        print("SMTP Server stopped.")
