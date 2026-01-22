from flask import Flask, render_template, request
from scanner.scanner_engine import run_scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("url")
        results = run_scan(target)
        return render_template("results.html", target=target, results=results)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
