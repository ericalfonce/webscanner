from flask import Flask, render_template, request
from scanner.scanner_engine import run_scan
from flask import session
from models import db
from auth import auth_bp
import uuid
from flask import redirect


app = Flask(__name__)

# Product / Marketing page (MetaMask-style)
@app.route("/")
def product():
    return render_template("product.html")

# Scanner landing + execution
@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        target = request.form.get("url")
        results = run_scan(target)
        return render_template(
            "results.html",
            target=target,
            results=results
        )

    return render_template("index.html")

# Optional: keep old landing if needed later
@app.route("/landing")
def landing():
    return render_template("landing.html")
@app.route("/pricing/basic")
def pricing_basic():
    return render_template("basic.html")

@app.route("/pricing/pro")
def pricing_pro():
    return render_template("pro.html")

@app.route("/pricing/enterprise")
def pricing_enterprise():
    return render_template("enterprise.html")
app.secret_key = "super-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database/scans.db"

db.init_app(app)
app.register_blueprint(auth_bp)




@app.route("/contact-expert", methods=["POST"])
def contact_expert():

    name = request.form.get("name")
    email = request.form.get("email")
    org = request.form.get("organization")
    category = request.form.get("category")
    priority = request.form.get("priority")
    message = request.form.get("message")
    target = request.form.get("target")
    score = request.form.get("score")

    # generate enterprise ticket ID
    ticket_id = "CS-" + str(uuid.uuid4())[:8].upper()

    # SLA logic
    if priority == "critical":
        sla = "Security response team will contact you within 1 hour."
    elif priority == "high":
        sla = "Security specialist will contact you within 4 hours."
    elif priority == "medium":
        sla = "Consultation scheduled within 24 hours."
    else:
        sla = "Advisory review within 2 business days."

    # simulate enterprise notification
    print("==== SECURITY SUPPORT REQUEST ====")
    print("Ticket:", ticket_id)
    print("Name:", name)
    print("Email:", email)
    print("Organization:", org)
    print("Category:", category)
    print("Priority:", priority)
    print("Target:", target)
    print("Security score:", score)
    print("Message:", message)
    print("=================================")

    return render_template(
        "support_confirmation.html",
        ticket_id=ticket_id,
        priority=priority,
        target=target,
        score=score,
        sla_message=sla
    )

@app.route("/threats")
def threats():
    return render_template("threats.html")

@app.route("/intelligence")
def intelligence():
    return render_template("intelligence.html")

@app.route("/analytics")
def analytics():
    return render_template("analytics.html")

@app.route("/incidents")
def incidents():
    return render_template("incidents.html")

@app.route("/compliance")
def compliance():
    return render_template("compliance.html")
if __name__ == "__main__":
    app.run(debug=True)
