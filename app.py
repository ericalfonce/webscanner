from flask import Flask, render_template, request
from scanner.scanner_engine import run_scan

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

if __name__ == "__main__":
    app.run(debug=True)
