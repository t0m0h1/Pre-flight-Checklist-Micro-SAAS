import os
from io import BytesIO
from datetime import datetime
from flask import (Flask, render_template, redirect, url_for, request,
                   flash, send_file, abort)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField, BooleanField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from PIL import Image

# Config
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "devsecret")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# DB setup
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'db.sqlite3')}")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
Session = sessionmaker(bind=engine)
session = Session()
Base = declarative_base()

# Models
class User(UserMixin, Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(200), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    name = Column(String(200), nullable=True)
    logo_filename = Column(String(300), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    checklists = relationship("Checklist", back_populates="user", cascade="all, delete-orphan")

class Checklist(Base):
    __tablename__ = "checklists"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    public = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="checklists")
    items = relationship("ChecklistItem", back_populates="checklist", cascade="all, delete-orphan", order_by="ChecklistItem.position")

class ChecklistItem(Base):
    __tablename__ = "checklist_items"
    id = Column(Integer, primary_key=True)
    checklist_id = Column(Integer, ForeignKey("checklists.id"))
    text = Column(Text, nullable=False)
    position = Column(Integer, default=0)
    checklist = relationship("Checklist", back_populates="items")

Base.metadata.create_all(engine)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return session.query(User).get(int(user_id))

# Forms
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Length(6, 200)])
    name = StringField("Name", validators=[Length(0, 200)])
    password = PasswordField("Password", validators=[InputRequired(), Length(6, 100)])
    confirm = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo("password")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Length(6,200)])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")

class ChecklistForm(FlaskForm):
    title = StringField("Title", validators=[InputRequired(), Length(1,200)])
    description = TextAreaField("Description")
    public = BooleanField("Make public")
    submit = SubmitField("Save")

class ItemForm(FlaskForm):
    text = StringField("Item text", validators=[InputRequired(), Length(1,500)])
    submit = SubmitField("Add item")

class LogoForm(FlaskForm):
    logo = FileField("Upload logo (png/jpg/svg)")
    submit = SubmitField("Upload")

# Routes
@app.route(\"/\")
def index():
    public = session.query(Checklist).filter_by(public=True).order_by(Checklist.created_at.desc()).limit(8).all()
    return render_template(\"index.html\", public=public)

@app.route(\"/register\", methods=[\"GET\",\"POST\"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing = session.query(User).filter_by(email=form.email.data.lower()).first()
        if existing:
            flash(\"Account exists. Please login.\", \"warning\")
            return redirect(url_for(\"login\"))
        hashed = generate_password_hash(form.password.data)
        u = User(email=form.email.data.lower(), password=hashed, name=form.name.data)
        session.add(u)
        session.commit()
        login_user(u)
        flash(\"Welcome! Your account was created.\", \"success\")
        return redirect(url_for(\"dashboard\"))
    return render_template(\"register.html\", form=form)

@app.route(\"/login\", methods=[\"GET\",\"POST\"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = session.query(User).filter_by(email=form.email.data.lower()).first()
        if u and check_password_hash(u.password, form.password.data):
            login_user(u)
            flash(\"Logged in.\", \"success\")
            return redirect(url_for(\"dashboard\"))
        flash(\"Invalid credentials.\", \"danger\")
    return render_template(\"login.html\", form=form)

@app.route(\"/logout\")
@login_required
def logout():
    logout_user()
    flash(\"Logged out.\", \"info\")
    return redirect(url_for(\"index\"))

@app.route(\"/dashboard\")
@login_required
def dashboard():
    checklists = current_user.checklists
    return render_template(\"dashboard.html\", checklists=checklists)

@app.route(\"/checklist/new\", methods=[\"GET\",\"POST\"])
@login_required
def new_checklist():
    form = ChecklistForm()
    if form.validate_on_submit():
        cl = Checklist(user=current_user._get_current_object(), title=form.title.data, description=form.description.data, public=form.public.data)
        session.add(cl); session.commit()
        flash(\"Checklist created.\", \"success\")
        return redirect(url_for(\"edit_checklist\", checklist_id=cl.id))
    return render_template(\"edit_checklist.html\", form=form, items=[])

@app.route(\"/checklist/<int:checklist_id>/edit\", methods=[\"GET\",\"POST\"])
@login_required
def edit_checklist(checklist_id):
    cl = session.query(Checklist).get(checklist_id)
    if not cl or cl.user_id != current_user.id:
        abort(404)
    form = ChecklistForm(obj=cl)
    item_form = ItemForm()
    if form.validate_on_submit():
        cl.title = form.title.data
        cl.description = form.description.data
        cl.public = form.public.data
        session.commit()
        flash(\"Saved.\", \"success\")
        return redirect(url_for(\"dashboard\"))
    return render_template(\"edit_checklist.html\", form=form, checklist=cl, items=cl.items, item_form=item_form)

@app.route(\"/checklist/<int:checklist_id>/item/add\", methods=[\"POST\"])
@login_required
def add_item(checklist_id):
    cl = session.query(Checklist).get(checklist_id)
    if not cl or cl.user_id != current_user.id:
        abort(404)
    form = ItemForm()
    if form.validate_on_submit():
        pos = max([i.position for i in cl.items], default=0) + 1
        it = ChecklistItem(checklist=cl, text=form.text.data, position=pos)
        session.add(it); session.commit()
    return redirect(url_for(\"edit_checklist\", checklist_id=checklist_id))

@app.route(\"/checklist/<int:checklist_id>/item/<int:item_id>/delete\", methods=[\"POST\"])
@login_required
def delete_item(checklist_id, item_id):
    cl = session.query(Checklist).get(checklist_id)
    it = session.query(ChecklistItem).get(item_id)
    if not cl or not it or cl.user_id != current_user.id or it.checklist_id != cl.id:
        abort(404)
    session.delete(it); session.commit()
    flash(\"Item deleted.\", \"info\")
    return redirect(url_for(\"edit_checklist\", checklist_id=checklist_id))

@app.route(\"/account\", methods=[\"GET\",\"POST\"])
@login_required
def account():
    form = LogoForm()
    if form.validate_on_submit():
        f = request.files.get(\"logo\")
        if f:
            filename = secure_filename(f.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], f\"user_{current_user.id}_{filename}\")
            f.save(save_path)
            current_user.logo_filename = os.path.basename(save_path)
            session.commit()
            flash(\"Logo uploaded.\", \"success\")
            return redirect(url_for(\"account\"))
    return render_template(\"account.html\", form=form)

@app.route(\"/uploads/<filename>\")
def uploaded_file(filename):
    p = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(p):
        abort(404)
    return send_file(p)

# PDF generation
def generate_pdf(checklist: Checklist, user: User):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    margin = 20*mm
    y = height - margin

    # Draw logo if exists
    if user.logo_filename:
        logo_path = os.path.join(app.config['UPLOAD_FOLDER'], user.logo_filename)
        if os.path.exists(logo_path):
            try:
                im = Image.open(logo_path)
                im.thumbnail((160, 80))
                tmp = BytesIO()
                im.save(tmp, format='PNG')
                tmp.seek(0)
                c.drawImage(tmp, margin, y - 40, preserveAspectRatio=True, mask='auto')
            except Exception:
                pass

    # Title
    c.setFont(\"Helvetica-Bold\", 16)
    c.drawString(margin + 180, y - 10, checklist.title)
    y -= 40

    # Description
    if checklist.description:
        c.setFont(\"Helvetica\", 10)
        text = c.beginText(margin, y)
        for line in checklist.description.splitlines():
            text.textLine(line)
            y -= 12
        c.drawText(text)
        y -= 10

    # Items
    c.setFont(\"Helvetica\", 11)
    for idx, item in enumerate(checklist.items, start=1):
        if y < margin + 40:
            c.showPage()
            y = height - margin
            c.setFont(\"Helvetica\", 11)
        c.drawString(margin, y, f\"{idx}. {item.text}\")
        y -= 16

    # Footer
    c.setFont(\"Helvetica-Oblique\", 8)
    footer = f\"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} • Powered by ChecklistSaaS\"
    c.drawRightString(width - margin, margin / 2, footer)

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer

@app.route(\"/checklist/<int:checklist_id>/download\")
@login_required
def download_checklist(checklist_id):
    cl = session.query(Checklist).get(checklist_id)
    if not cl:
        abort(404)
    if cl.user_id != current_user.id and not cl.public:
        flash(\"This checklist is private.\", \"danger\")
        return redirect(url_for(\"dashboard\"))
    pdf = generate_pdf(cl, current_user)
    filename = f\"{secure_filename(cl.title)}.pdf\"
    return send_file(pdf, download_name=filename, as_attachment=True, mimetype=\"application/pdf\")


@app.route(\"/view/<int:checklist_id\")
def temp_route():
    return \"temp\"

# Minimal public view
@app.route(\"/view/<int:checklist_id>\")
def view_public(checklist_id):
    cl = session.query(Checklist).get(checklist_id)
    if not cl or not cl.public:
        abort(404)
    return render_template(\"public_view.html\", checklist=cl)

# Minimal deletion
@app.route(\"/checklist/<int:checklist_id>/delete\", methods=[\"POST\"])
@login_required
def delete_checklist(checklist_id):
    cl = session.query(Checklist).get(checklist_id)
    if not cl or cl.user_id != current_user.id:
        abort(404)
    session.delete(cl); session.commit()
    flash(\"Checklist removed.\", \"info\")
    return redirect(url_for(\"dashboard\"))

if __name__ == \"__main__\":
    app.run(debug=True)
