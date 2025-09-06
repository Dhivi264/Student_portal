import os
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

# For scheduled attendance updates
from apscheduler.schedulers.background import BackgroundScheduler

# -----------------
# Config
# -----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = "change_this_secret_in_production"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(BASE_DIR, "database.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4MB max upload

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------
# Models
# -----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'student'

    def check_password(self, pw):
        return bcrypt.check_password_hash(self.password_hash, pw)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_username = db.Column(db.String(120), unique=True, nullable=False)  # links to User.username
    name = db.Column(db.String(200))
    address = db.Column(db.String(400))
    phone = db.Column(db.String(40))
    email = db.Column(db.String(200))
    cgpa = db.Column(db.Float)
    attendance = db.Column(db.Float, default=0.0)  # percent 0-100
    arrears = db.Column(db.String(20))  # 'Yes'/'No'
    is_scholarship = db.Column(db.Boolean, default=False)
    scholarship_name = db.Column(db.String(200), nullable=True)
    image_filename = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# -----------------
# Login manager
# -----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -----------------
# Initialize DB & default admins
# -----------------
with app.app_context():
    db.create_all()
    # create default admins if missing
    if not User.query.filter_by(username="advisor").first():
        pw = bcrypt.generate_password_hash("advisor123").decode("utf-8")
        db.session.add(User(username="advisor", password_hash=pw, role="admin"))
    if not User.query.filter_by(username="me").first():
        pw = bcrypt.generate_password_hash("myadmin123").decode("utf-8")
        db.session.add(User(username="me", password_hash=pw, role="admin"))
    db.session.commit()


# -----------------
# Helper: save upload file
# -----------------
def save_image(file_storage):
    if not file_storage or file_storage.filename == "":
        return None
    filename = secure_filename(file_storage.filename)
    # make filename unique: timestamp + filename
    name = f"{int(datetime.utcnow().timestamp())}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], name)
    file_storage.save(path)
    return name  # store relative filename


# -----------------
# Attendance auto-update job
# -----------------
def auto_update_attendance():
    # This example increments attendance by 0.1% up to 100 for all students once daily.
    with app.app_context():
        students = Student.query.all()
        for s in students:
            if s.attendance is None:
                s.attendance = 0.0
            # increment by small amount daily (adjust as needed)
            s.attendance = min(100.0, round(s.attendance + 0.1, 2))
        db.session.commit()
        app.logger.info("Attendance auto-updated for %d students", len(students))

# Start scheduler
scheduler = BackgroundScheduler()
# run once a day; for testing you can change seconds param (e.g., seconds=30)
scheduler.add_job(func=auto_update_attendance, trigger="interval", days=1, id="attendance_job", replace_existing=True)
scheduler.start()


# -----------------
# Routes
# -----------------
@app.route("/static/uploads/<filename>")
def uploaded_file(filename):
    # serve uploaded files (Flask will serve static folder too)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("role")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, role=role).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful", "success")
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("student_dashboard"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))


# -----------------
# Admin area
# -----------------
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html")


@app.route("/admin/add_student", methods=["GET", "POST"])
@login_required
def add_student():
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        student_username = request.form.get("student_username", "").strip()
        student_password = request.form.get("student_password", "")
        name = request.form.get("name", "").strip()
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        cgpa = float(request.form.get("cgpa") or 0)
        attendance = float(request.form.get("attendance") or 0)
        arrears = request.form.get("arrears") or "No"
        is_scholarship = True if request.form.get("is_scholarship") == "on" else False
        scholarship_name = request.form.get("scholarship_name") or None
        img = request.files.get("image")

        # validation
        if User.query.filter_by(username=student_username).first():
            flash("Student username already exists", "danger")
            return redirect(url_for("add_student"))

        # create user
        pw_hash = bcrypt.generate_password_hash(student_password).decode("utf-8")
        user = User(username=student_username, password_hash=pw_hash, role="student")
        db.session.add(user)
        db.session.commit()

        image_name = save_image(img)
        stud = Student(
            student_username=student_username,
            name=name,
            address=address,
            phone=phone,
            email=email,
            cgpa=cgpa,
            attendance=attendance,
            arrears=arrears,
            is_scholarship=is_scholarship,
            scholarship_name=scholarship_name,
            image_filename=image_name,
            user_id=user.id
        )
        db.session.add(stud)
        db.session.commit()
        flash("Student created successfully", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_student.html")


@app.route("/admin/search", methods=["POST"])
@login_required
def admin_search():
    if current_user.role != "admin":
        return redirect(url_for("login"))
    q = request.form.get("query", "").strip()
    students = []
    if q:
        students = Student.query.filter(Student.name.ilike(f"%{q}%")).all()
    return render_template("search_results.html", students=students, q=q)


@app.route("/admin/edit/<int:student_id>", methods=["GET", "POST"])
@login_required
def edit_student(student_id):
    if current_user.role != "admin":
        return redirect(url_for("login"))
    s = Student.query.get_or_404(student_id)
    if request.method == "POST":
        s.name = request.form.get("name")
        s.address = request.form.get("address")
        s.phone = request.form.get("phone")
        s.email = request.form.get("email")
        s.cgpa = float(request.form.get("cgpa") or 0)
        s.attendance = float(request.form.get("attendance") or 0)
        s.arrears = request.form.get("arrears") or "No"
        s.is_scholarship = True if request.form.get("is_scholarship") == "on" else False
        s.scholarship_name = request.form.get("scholarship_name") or None

        img = request.files.get("image")
        if img and img.filename:
            # save new image and set
            image_name = save_image(img)
            s.image_filename = image_name

        db.session.commit()
        flash("Student updated", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_student.html", student=s)


@app.route("/admin/delete/<int:student_id>", methods=["POST"])
@login_required
def delete_student(student_id):
    if current_user.role != "admin":
        return redirect(url_for("login"))
    s = Student.query.get_or_404(student_id)
    user = User.query.filter_by(username=s.student_username).first()
    db.session.delete(s)
    if user:
        db.session.delete(user)
    db.session.commit()
    flash("Student deleted", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reset_password/<int:user_id>", methods=["GET", "POST"])
@login_required
def reset_password(user_id):
    if current_user.role != "admin":
        return redirect(url_for("login"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        new_pw = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not new_pw or new_pw != confirm:
            flash("Passwords do not match or empty", "danger")
            return redirect(url_for("reset_password", user_id=user_id))
        user.password_hash = bcrypt.generate_password_hash(new_pw).decode("utf-8")
        db.session.commit()
        flash("Password reset", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("reset_password.html", user=user)


@app.route("/admin/update_attendance_now", methods=["POST"])
@login_required
def update_attendance_now():
    # admin-triggered update: increments attendance by specified delta for all or single student
    if current_user.role != "admin":
        return redirect(url_for("login"))
    delta = float(request.form.get("delta") or 0)
    target = request.form.get("target")  # "all" or student_id
    if target == "all":
        students = Student.query.all()
        for s in students:
            s.attendance = min(100.0, s.attendance + delta)
        db.session.commit()
        flash("Attendance updated for all students", "success")
    else:
        try:
            sid = int(target)
            s = Student.query.get(sid)
            if s:
                s.attendance = min(100.0, s.attendance + delta)
                db.session.commit()
                flash("Attendance updated for student", "success")
        except:
            flash("Invalid target", "danger")
    return redirect(url_for("admin_dashboard"))


# -----------------
# Student area
# -----------------
@app.route("/student")
@login_required
def student_dashboard():
    if current_user.role != "student":
        flash("Access denied", "danger")
        return redirect(url_for("login"))
    # find student record by username
    student = Student.query.filter_by(student_username=current_user.username).first()
    return render_template("student_dashboard.html", student=student)


# -----------------
# Change own password route
# -----------------
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password_self():
    user = current_user
    if request.method == "POST":
        old = request.form.get("old_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not user.check_password(old):
            flash("Old password incorrect", "danger")
            return redirect(url_for("change_password_self"))
        if new != confirm or new == "":
            flash("New passwords do not match or empty", "danger")
            return redirect(url_for("change_password_self"))
        user.password_hash = bcrypt.generate_password_hash(new).decode("utf-8")
        db.session.commit()
        flash("Password changed. Please log in again.", "success")
        logout_user()
        return redirect(url_for("login"))
    return render_template("change_password.html")


# -----------------
# App teardown
# -----------------
@app.teardown_appcontext
def shutdown_scheduler(exception=None):
    # do not shut scheduler on every request; scheduler runs until process exit
    pass


# -----------------
# Run
# -----------------
if __name__ == "__main__":
    try:
        # start flask dev server
        app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
