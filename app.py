from flask import Flask, request, render_template
from train_model import train_model
from email_parser import parse_email
from werkzeug.utils import secure_filename
import os
import re

# Initialize Flask application
app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = "./uploaded_eml_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Train the model and load it along with the vectorizer
model, vectorizer = train_model()

# List to store flagged emails for the dashboard
flagged_emails = []


def detect_phishing_traits(email):
    """
    Rule-based detection for phishing-related traits.
    :param email: Input email content (as a string).
    :return: List of phishing traits found.
    """
    phishing_traits = []

    # Example rules-based checks:
    # 1. Check for common phishing keywords
    keywords = ["urgent", "free", "winner", "claim", "limited offer", "act now"]
    if any(word in email.lower() for word in keywords):
        phishing_traits.append("Email contains suspicious keywords.")

    # 2. Suspicious link checks
    if re.search(r"http[s]?://[\w./-]+", email):
        phishing_traits.append("Email contains suspicious links.")

    # 3. Attempts to collect personal information
    if re.search(r"password|account|credit card|login", email.lower()):
        phishing_traits.append("Email seeks sensitive personal details.")

    # 4. Grammar and spelling mistakes (simplified rule example)
    if len(re.findall(r"[A-Z]{2,}", email)) > 5:  # Mock detection of many uppercase words
        phishing_traits.append("Email contains excessive capitalization.")

    return phishing_traits


@app.route("/")
def index():
    """
    Render the homepage with a file upload form.
    """
    return render_template("index.html")


@app.route("/detect", methods=["POST"])
def detect():
    """
    Handle multiple uploaded files to detect phishing emails.
    """
    if 'eml_files' not in request.files:
        return "No files uploaded", 400

    # Get the list of uploaded '.eml' files
    files = request.files.getlist('eml_files')
    results = []

    for file in files:
        filename = secure_filename(file.filename)

        # Save the uploaded file
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        # Parse the .eml file
        with open(file_path, "rb") as f:
            email_data = parse_email(f)

        # Extract email content and run vectorization
        email_content = email_data.get("Content", "")
        email_vector = vectorizer.transform([email_content])

        # Predict using the ML model
        prediction = model.predict(email_vector)
        ml_result = "Phishing Email" if prediction[0] == 1 else "Legitimate Email"

        # Perform rule-based phishing traits detection
        phishing_traits = detect_phishing_traits(email_content)

        # Flag the email if phishing is detected
        if ml_result == "Phishing Email" or phishing_traits:
            flagged_emails.append({"email_text": email_content, "traits": phishing_traits})

        # Store results for display
        results.append({
            "filename": filename,
            "email_data": email_data,
            "ml_result": ml_result,
            "phishing_traits": phishing_traits
        })

    # Render the results template with all detection results
    return render_template("results.html", results=results)


@app.route("/dashboard")
def dashboard():
    """
    Displays a dashboard of flagged emails with traits and alerts.
    """
    return render_template("dashboard.html", flagged_emails=flagged_emails)

@app.route("/owasp")
def owasp_guidelines():
    # Render the OWASP guidelines page
    return render_template('owasp.html')  # Flask will look for owasp.html in the templates folder


if __name__ == "__main__":
    """
    Run the Flask application.
    """
    app.run(debug=True)