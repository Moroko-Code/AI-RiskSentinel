from application import app, db
from flask import render_template, request, json, Response, redirect, flash, url_for, session, abort, make_response
from functools import wraps
from application.models import User
from application.forms import LoginForm, RegisterForm, VerifyForm
from flask_bcrypt import Bcrypt
from config import Config
from flask_login import login_user
from application.models import User 
from application.fnGenerateOtpAndSendEmail import send_email_otp
from application.scanner import scan_network
from application.scan_network_entries import get_flattened_vulnerabilities
from weasyprint import HTML

bcrypt = Bcrypt(app)
vulRec = Config.vulnerabilities_collection

# Twilio Client
#twilio_client = Client(Config.TWILIO_ACCOUNT_SID, Config.TWILIO_AUTH_TOKEN)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first.", "warning")
            return redirect(url_for('login'))  # Redirect to login page
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
@app.route("/index")
def index():
    return render_template("master.html", index=True)

@app.route("/logout")
def logout():
    session['user_id'] = False
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/about")
def about():
    return render_template("abouts.html", about=True)

@app.route("/register", methods=['POST', 'GET'])
def register():
    if session.get('username'):
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        last_user = User.objects.order_by('-user_id').first()
        user_id = last_user.user_id + 1 if last_user else 1 
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(user_id=user_id, email=email, phone=phone, password=hashed_password)
        user.save()
        flash("You are successfully registered!", "success")
        return redirect(url_for('login'))
    return render_template("signup.html", title="Signup", form=form, register=True)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if session.get('username'):
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        passwordLogin = request.form.get('password')
        user = User.objects(email=email).first()
        if user and bcrypt.check_password_hash(user.password, passwordLogin):
            session['user_id'] = user.user_id
              # Call sendOtp to send OTP
            send_email_otp(user)
            flash("OTP sent! Please verify.", "info")
            return redirect(url_for('verifyOTP'))
        else:
            flash("Sorry, Invalid Credentials", "danger")
    return render_template("signin.html", title="Login", form=form, login=True)

@app.route("/verifyOTP", methods=['GET', 'POST'])
def verifyOTP():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = VerifyForm()
    user_id = session.get('user_id')  # Get the user_id from the session
    user = User.objects(user_id=user_id).first()  # Fetch the user document using user_id

    if not user:  # Check if the user was found
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    if form.validate_on_submit():
        if form.otp.data == user.otp:
            login_user(user)  # Log the user in using the login_user function
            user.otp = None  # Clear OTP after successful verification
            user.save()
            flash("Login Successful", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP! Please try again.", "danger")

    return render_template('verify.html', form=form)

@app.route("/admin")
@login_required
def dashboard():
    return render_template("adminDashboard.html", dashboard=True)

#list of assets
@app.route("/assets")
def assets():
    return render_template("assets.html", assets=True)
#users
@app.route("/user")
def user():
    users = User.objects.all()
    return render_template("user.html", users=users)

@app.route('/scanner')
def scanner():
    flattened_data = get_flattened_vulnerabilities()
     # Pagination logic
    page = request.args.get('page', 1, type=int)
    per_page = 50
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = flattened_data[start:end]

    total_pages = (len(flattened_data) + per_page - 1)

    # ✅ Pass page and total_pages to the template
    return render_template("assestments.html", title="Scan Results", data=paginated_data, page=page, total_pages=total_pages)

@app.route('/Scanning', methods=['GET', 'POST'])
def Scanning():
    if request.method == 'POST':
        ip_range = request.form.get('ip_range', '').strip()

        if not ip_range:
            flash("Soory !!!! IP address cannot be empty ........", "warning")
            return redirect(url_for('Scanning'))

        # Proceed with scanning
        scan_network(ip_range)
        flattened_data = get_flattened_vulnerabilities()

        # Pagination logic
        page = request.args.get('page', 1, type=int)
        per_page = 2
        start = (page - 1) * per_page
        end = start + per_page
        paginated_data = flattened_data[start:end]
        total_pages = (len(flattened_data) + per_page - 1) // per_page or 1

        return render_template("assestments.html", title="Scan Results", data=paginated_data, page=page, total_pages=total_pages
        )
    return render_template("assestments.html", title="Scan", data=[], page=1, total_pages=1)

@app.route("/reportsPage")
def reportsPage():
    service = vulRec.distinct("services.service")
    states = vulRec.distinct("services.state")
    Risks = vulRec.distinct("services.cves.risk")
    return render_template("reportsPage.html", service=service, states=states, Risks=Risks)

# Route to generate filtered PDF
@app.route("/report/pdf")
def report_pdf():
    risk = request.args.get("risk")
    state = request.args.get("state")
    protocol = request.args.get("protocol")

    results = []

    # Fetch all documents from the database
    all_docs = list(vulRec.find())
    print(f"Found {len(all_docs)} devices in the database.")
    
    # Print each document to check if they are fetched properly
    for doc in all_docs:
        print(f"Processing device: {doc.get('ip')}")
        print(f"Services: {doc.get('services')}")
        if not doc.get('services'):
            print(f"Warning: Device {doc.get('ip')} has no services listed.")

    # Check if the loop over the documents is functioning as expected
    for doc in all_docs:
        print(f"Processing device: {doc.get('ip')}")
        for svc in doc.get("services", []):
            print(f"Service: {svc.get('service')} - Port: {svc.get('port')}")
            for cve in svc.get("cves", []):
                print(f"CVE: {cve.get('id')} - Risk: {cve.get('risk')}")

    for doc in all_docs:
        for svc in doc.get("services", []):
            # Apply filters if provided
            if state and svc.get("state") != state:
                continue
            if protocol and svc.get("service") != protocol:
                continue

            for cve in svc.get("cves", []):
                if risk and cve.get("risk") != risk:
                    continue

                # Append the data to the results list
                results.append({
                    "ip": doc.get("ip"),
                    "os": doc.get("os"),
                    "scanned_at": doc.get("scanned_at"),
                    "port": svc.get("port"),
                    "protocol": svc.get("service"),
                    "state": svc.get("state"),
                    "cve_id": cve.get("id"),
                    "description": cve.get("description"),
                    "score": cve.get("score"),
                    "risk": cve.get("risk")
                })

    print(f"Total records to be rendered: {len(results)}")
    
    # Render HTML and create the PDF
    html = render_template("vulReport_pdf.html", records=results)
    pdf = HTML(string=html).write_pdf()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=Vulnerability_report.pdf"
    
    return response




                          


