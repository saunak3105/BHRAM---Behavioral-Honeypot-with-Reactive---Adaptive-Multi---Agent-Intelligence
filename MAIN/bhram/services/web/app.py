"""
BHRAM Technologies — Fake Company Web Application
Flask application serving as an attacker-facing deception surface.

DECEPTION ARTIFACTS:
  - Employee portal (/employee)
  - Internal document portal (/internal, /documents)
  - Support portal (/support)
  - Fictional employee directory
  - Fake technology stack disclosures
  - Fictional internal hostnames in page metadata

SECURITY:
  - All company data is entirely fictional.
  - No real credentials are used or stored.
  - Login forms are honeypots — all submissions are logged.
  - No real authentication logic is implemented.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session

logger = logging.getLogger("bhram.web")

# Part 2: Telemetry integration
# Import is guarded so the web app starts even if bhram package is not installed.
try:
    from bhram.telemetry.collectors.web import WebTelemetryMiddleware
    from bhram.telemetry.storage.pipeline import ForensicStorage
    _forensic = ForensicStorage(base_dir=os.environ.get("BHRAM_DATA_DIR", "data"))

    def _emit_event(event):
        """Write canonical event to forensic flat-file storage."""
        try:
            _forensic.write(event)
        except Exception as exc:
            logger.warning("Telemetry emit error: %s", exc)

    _TELEMETRY_ENABLED = True
except ImportError:
    logger.info("bhram.telemetry not available — web telemetry middleware disabled")
    _TELEMETRY_ENABLED = False


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "devsecret_not_for_production")
    app.config["APPLICATION_ROOT"] = "/"
    app.config["COMPANY_NAME"] = "BHRAM Technologies"

    # ── Context processors ─────────────────────────────────────────────────────
    @app.context_processor
    def inject_globals():
        return {
            "company_name": "BHRAM Technologies",
            "year": datetime.now().year,
            "tagline": "Securing Tomorrow, Today",
            # Fictional internal hostnames — deception artifacts
            "intranet_host": "intranet.bhram-technologies.internal",
            "vpn_host": "vpn.bhram-technologies.internal",
            "mail_host": "mail.bhram-technologies.internal",
            "git_host": "gitlab.bhram-technologies.internal",
        }

    # ── Public routes ──────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/careers")
    def careers():
        return render_template("careers.html")

    @app.route("/contact")
    def contact():
        return render_template("contact.html")

    @app.route("/contact", methods=["POST"])
    def contact_post():
        # Honeypot: log the submission (in Part 2 this feeds telemetry)
        name = request.form.get("name", "")[:128]
        email = request.form.get("email", "")[:256]
        message = request.form.get("message", "")[:2048]
        app.logger.info("Honeypot contact form submitted: %s <%s> - message length: %d", name, email, len(message))
        flash("Thank you for contacting us. A representative will respond within 2 business days.", "success")
        return redirect(url_for("contact"))

    # ── Employee portal ────────────────────────────────────────────────────────

    @app.route("/employee")
    def employee():
        """Employee portal — deception artifact."""
        return render_template("employee.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Login honeypot — all credential attempts are captured."""
        if request.method == "POST":
            username = request.form.get("username", "")[:64]
            # Log the attempt — password is intentionally NOT stored in plain text
            app.logger.info("Honeypot login attempt: username=%s, ip=%s", username, request.remote_addr)
            # Deliberately always fail — no real auth
            flash("Invalid username or password. Please try again.", "danger")
            return render_template("login.html", failed=True)
        return render_template("login.html", failed=False)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # ── Support portal ─────────────────────────────────────────────────────────

    @app.route("/support")
    def support():
        """IT Support portal — deception artifact."""
        return render_template("support.html")

    @app.route("/support", methods=["POST"])
    def support_post():
        flash("Support ticket #" + str(hash(request.form.get("issue", "")))[1:7] + " created successfully.", "success")
        return redirect(url_for("support"))

    # ── Internal/Document portals ──────────────────────────────────────────────

    @app.route("/internal")
    def internal():
        """Internal intranet portal — deception artifact."""
        return render_template("internal.html")

    @app.route("/documents")
    def documents():
        """Document portal — deception artifact with fake file listings."""
        return render_template("documents.html")

    # ── Error handlers ─────────────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("error.html", code=500, message="Internal server error."), 500

    return app


# ── Direct run ────────────────────────────────────────────────────────────────
app = create_app()

# Part 2: Wrap the WSGI app with BHRAM telemetry middleware.
# Every HTTP request is normalized into a CanonicalEvent and written to forensic storage.
if _TELEMETRY_ENABLED:
    app.wsgi_app = WebTelemetryMiddleware(app.wsgi_app, emit_fn=_emit_event)
    logger.info("BHRAM web telemetry middleware ACTIVE")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
