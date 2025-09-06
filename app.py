import os
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler

# =====================
# Config
# =====================
app = Flask(__name__)
app.secret_key = "supersecretkey"   # ⚠️ change in production
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# =====================
# Models
# =====================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # "admin" or "student"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_username = db.Column(db.String(80), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    name = db.Column(db.String(120))
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    cgpa = db.Column(db.Float)
    attendance = db.Column(db.Float)
    arrears = db.Column(db.String(10), default="No")
    is_scholarship = db.Column(db.Boolean, default=False)
    scholarship_name = db.Column(db.String(120))
    image_filename = db.Column(db.String(120))

# =====================
# Login manager
# =====================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =====================
# Helper: save upload file
# =====================
def save_image(file):
    if file and file.filename:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        return filename
    return None

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# =====================
# Attendance auto-update job
# =====================
def auto_update_attendance():
    with app.app_context():
        students = Student.query.all()
        for s in students:
            if s.attendance is not None:
                s.attendance = max(0, min(100, s.attendance - 0.1))  # drop by 0.1%
        db.session.commit()

scheduler = BackgroundScheduler()
scheduler.add_job(auto_update_attendance, "interval", hours=24)  # run daily
scheduler.start()

# =====================
# Routes
# =====================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form["role"]
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username, role=role).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful", "success")
            return redirect(url_for("admin_dashboard" if role == "admin" else "student_dashboard"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "success")
    return redirect(url_for("login"))

# ---------------------
# Admin area
# ---------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html")

@app.route("/admin/add", methods=["GET", "POST"])
@login_required
def add_student():
    if current_user.role != "admin":
        return redirect(url_for("login"))
    if request.method == "POST":
        # create user for student
        student_user = User(username=request.form["student_username"], role="student")
        student_user.set_password(request.form["student_password"])
        db.session.add(student_user)
        db.session.commit()

        # save image
        image = request.files.get("image")
        filename = save_image(image) if image else None

        student = Student(
            student_username=request.form["student_username"],
            user_id=student_user.id,
            name=request.form.get("name"),
            address=request.form.get("address"),
            phone=request.form.get("phone"),
            email=request.form.get("email"),
            cgpa=request.form.get("cgpa"),
            attendance=request.form.get("attendance"),
            arrears=request.form.get("arrears"),
            is_scholarship="is_scholarship" in request.form,
            scholarship_name=request.form.get("scholarship_name"),
            image_filename=filename
        )
        db.session.add(student)
        db.session.commit()
        flash("Student added successfully", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_student.html")

@app.route("/admin/edit/<int:student_id>", methods=["GET", "POST"])
@login_required
def edit_student(student_id):
    if current_user.role != "admin":
        return redirect(url_for("login"))
    student = Student.query.get_or_404(student_id)
    if request.method == "POST":
        student.name = request.form.get("name")
        student.address = request.form.get("address")
        student.phone = request.form.get("phone")
        student.email = request.form.get("email")
        student.cgpa = request.form.get("cgpa")
        student.attendance = request.form.get("attendance")
        student.arrears = request.form.get("arrears")
        student.is_scholarship = "is_scholarship" in request.form
        student.scholarship_name = request.form.get("scholarship_name")
        image = request.files.get("image")
        if image:
            student.image_filename = save_image(image)
        db.session.commit()
        flash("Student updated successfully", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_student.html", student=student)

@app.route("/admin/delete/<int:student_id>", methods=["POST"])
@login_required
def delete_student(student_id):
    if current_user.role != "admin":
        return redirect(url_for("login"))
    student = Student.query.get_or_404(student_id)
    user = User.query.get(student.user_id)
    db.session.delete(student)
    if user:
        db.session.delete(user)
    db.session.commit()
    flash("Student deleted", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/search")
@login_required
def admin_search():
    if current_user.role != "admin":
        return redirect(url_for("login"))
    q = request.args.get("q")
    students = []
    if q:
        students = Student.query.filter(
            (Student.name.contains(q)) |
            (Student.student_username.contains(q)) |
            (Student.email.contains(q))
        ).all()
    return render_template("search_results.html", q=q, students=students)

@app.route("/admin/reset/<int:user_id>", methods=["GET", "POST"])
@login_required
def reset_password(user_id):
    if current_user.role != "admin":
        return redirect(url_for("login"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm = request.form["confirm_password"]
        if new_password == confirm:
            user.set_password(new_password)
            db.session.commit()
            flash("Password reset successfully", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Passwords do not match", "danger")
    return render_template("reset_password.html", user=user)

# ---------------------
# Student area
# ---------------------
@app.route("/student")
@login_required
def student_dashboard():
    if current_user.role != "student":
        return redirect(url_for("login"))
    student = Student.query.filter_by(user_id=current_user.id).first()
    return render_template("student_dashboard.html", student=student)

# ---------------------
# Change own password route
# ---------------------
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password_self():
    if request.method == "POST":
        old_pw = request.form["old_password"]
        new_pw = request.form["new_password"]
        confirm_pw = request.form["confirm_password"]
        if not current_user.check_password(old_pw):
            flash("Old password incorrect", "danger")
        elif new_pw != confirm_pw:
            flash("New passwords do not match", "danger")
        else:
            current_user.set_password(new_pw)
            db.session.commit()
            flash("Password updated", "success")
            return redirect(url_for("admin_dashboard" if current_user.role == "admin" else "student_dashboard"))
    return render_template("change_password.html")

# =====================
# App teardown
# =====================
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# =====================
# Run (Flask 3.x safe DB init)
# =====================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role="admin").first():
            admin = User(username="admin", role="admin")
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
