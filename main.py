import os
from random import choice
from urllib.parse import urlparse, urljoin

from flask import Flask, abort, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

csrf = CSRFProtect()

db = SQLAlchemy()
login_manager = LoginManager()

CHOICES = ("rock", "paper", "scissors")
WIN_MAP = {"rock": "scissors", "paper": "rock", "scissors": "paper"}

DEFAULT_BALANCE = 10_000

email_validator = Email(message="invalid email")

class LoginForm(FlaskForm):
    username = StringField("Username or email", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField("Log in")

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=16)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    verify_password = PasswordField(
        "Verify Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")]
    )
    submit = SubmitField("Register")

class ResetAccountForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField("Confirm")

class UpdatePasswordForm(FlaskForm):
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=6, max=128)]) 
    verify_new_password = PasswordField("Verify new password", validators=[DataRequired(), Length(min=6, max=128)])
    current_password = PasswordField("Current password", validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField("Update")

def outcome(player, cpu):
    if player == cpu:
        return "draw"
    return "win" if WIN_MAP[player] == cpu else "loss"

def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-prod")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///app.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    # app.config.setdefault("SESSION_COOKIE_SECURE", True)  # enable under HTTPS

    csrf.init_app(app)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"

    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(16), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        is_admin = db.Column(db.Boolean, nullable=False, default=False)

        def set_password(self, password):
            self.password_hash = generate_password_hash(password, method="pbkdf2:sha256")

        def check_password(self, password):
            return check_password_hash(self.password_hash, password)

    class Stats(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
        balance = db.Column(db.Integer, nullable=False, default=0)
        bets = db.Column(db.Integer, nullable=False, default=0)
        wins = db.Column(db.Integer, nullable=False, default=0)
        draws = db.Column(db.Integer, nullable=False, default=0)
        losses = db.Column(db.Integer, nullable=False, default=0)
        wagered = db.Column(db.Integer, nullable=False, default=0)
        profit = db.Column(db.Integer, nullable=False, default=0)

        user = db.relationship("User", backref=db.backref("stats", uselist=False))

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def is_safe_url(target):
        ref = urlparse(request.host_url)
        test = urlparse(urljoin(request.host_url, target))
        return test.scheme in ("http", "https") and ref.netloc == test.netloc

    @app.after_request
    def set_csrf_cookie(resp):
        resp.set_cookie("csrf_token", generate_csrf(), httponly=False, samesite="Lax")
        return resp

    @app.route("/api/admin/users/<int:user_id>", methods=["PATCH"])
    @admin_required
    def admin_update_user(user_id):
        data = request.get_json(silent=True) or {}
        u = db.session.get(User, user_id)
        if not u:
            return jsonify(error="not found"), 404
        if "is_admin" in data:
            if u.id == current_user.id and data["is_admin"] is False:
                return jsonify(error="cannot demote self"), 400
            u.is_admin = bool(data["is_admin"])
        if "username" in data:
            new = (data["username"] or "").strip()
            if not new or len(new) > 16:
                return jsonify(error="invalid username"), 400
            if User.query.filter(User.username == new, User.id != u.id).first():
                return jsonify(error="username taken"), 400
            u.username = new
        if "email" in data:
            new_email = (data["email"] or "").strip().lower()
            if not new_email:
                return jsonify(error="invalid email"), 400
            try:
                email_validator(None, type("F", (), {"data": new_email})())
            except ValidationError:
                return jsonify(error="invalid email"), 400
            if User.query.filter(User.email == new_email, User.id != u.id).first():
                return jsonify(error="email taken"), 400
            u.email = new_email
        if "balance" in data:
            s = u.stats or Stats(user=u)
            try:
                setattr(s, "balance", int(data["balance"]))
            except (TypeError, ValueError):
                return jsonify(error=f"invalid balance"), 400
            db.session.add(s)

        db.session.commit()
        return jsonify(message="updated",
                       user={"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin}), 200

    @app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
    @admin_required
    def admin_delete_user(user_id):
        if user_id == current_user.id:
            return jsonify(error="cannot delete self"), 400
        u = db.session.get(User, user_id)
        if not u:
            return jsonify(error="not found"), 404
        if u.stats:
            db.session.delete(u.stats)
        db.session.delete(u)
        db.session.commit()
        return jsonify(message="deleted", id=user_id), 200

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            if current_user.stats is None:
                s = Stats(user=current_user, balance=DEFAULT_BALANCE)
                db.session.add(s)
                db.session.commit()
            return render_template("index.html",
                                   username=current_user.username,
                                   balance=current_user.stats.balance,
                                   bets=current_user.stats.bets,
                                   wins=current_user.stats.wins,
                                   draws=current_user.stats.draws,
                                   losses=current_user.stats.losses,
                                   wagered=current_user.stats.wagered,
                                   profit=current_user.stats.profit,
                                   is_admin=current_user.is_admin)
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            username = form.username.data.strip()
            email = form.email.data.strip().lower()

            if User.query.filter_by(username=username).first():
                form.username.errors.append("Username already registered")
            elif User.query.filter_by(email=email).first():
                form.email.errors.append("Email already registered")
            else:
                u = User(username=username, email=email)
                u.set_password(form.password.data)
                db.session.add(u)
                db.session.flush()
                db.session.add(Stats(user=u, balance=DEFAULT_BALANCE))
                db.session.commit()
                login_user(u)
                return redirect(url_for("index"))

        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            u = User.query.filter(or_(User.username == form.username.data.strip(),
                                      User.email == form.username.data.strip().lower())).first()
            if u and u.check_password(form.password.data):
                login_user(u)
                nxt = request.args.get("next")
                return redirect(nxt) if nxt and is_safe_url(nxt) else redirect(url_for("index"))
            flash("Invalid credentials")
        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out")
        return redirect(url_for("login"))

    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html",
                               is_admin=current_user.is_admin,
                               username=current_user.username,
                               default_balance=DEFAULT_BALANCE,
                               balance=current_user.stats.balance,
                               bets=current_user.stats.bets,
                               wins=current_user.stats.wins,
                               draws=current_user.stats.draws,
                               losses=current_user.stats.losses,
                               wagered=current_user.stats.wagered,
                               profit=current_user.stats.profit,
                               password_form=UpdatePasswordForm(),
                               reset_form=ResetAccountForm())

    @app.post("/api/users/reset")
    @login_required
    def reset_account():
        form = ResetAccountForm()
        if not form.validate_on_submit():
            return jsonify(error="invalid form"), 400

        # Identity check
        if form.username.data.strip() != current_user.username:
            return jsonify(error="username mismatch"), 400
        if not current_user.check_password(form.password.data):
            return jsonify(error="incorrect password"), 400

        # Reset stats
        s = current_user.stats
        if s is None:
            s = Stats(user=current_user, balance=DEFAULT_BALANCE)
            db.session.add(s)
        else:
            s.balance = DEFAULT_BALANCE
            s.bets = 0
            s.wins = 0
            s.draws = 0
            s.losses = 0
            s.wagered = 0
            s.profit = 0

        db.session.commit()
        return jsonify(message="reset", balance=s.balance, bets=s.bets, wins=s.wins,
                       draws=s.draws, losses=s.losses, wagered=s.wagered, profit=s.profit), 200

    @app.post("/api/users/update-password")
    @login_required
    def update_password():
        form = UpdatePasswordForm()
        if not form.validate_on_submit():
            return jsonify(error="invalid form"), 400

        if form.new_password.data != form.verify_new_password.data:
            return jsonify(error="new passwords don't match"), 400

        if not current_user.check_password(form.current_password.data):
            return jsonify(error="incorrect password"), 400

        current_user.set_password(form.new_password.data)
        
        db.session.commit()
        return jsonify(message="success"), 200


    @app.post("/api/gamble")
    @login_required
    def api_gamble():
        payload = request.get_json(silent=True) or {}
        choice_in = (payload.get("choice") or "").lower()
        wager = payload.get("wager")

        if choice_in not in CHOICES:
            return jsonify(error="invalid choice"), 400

        try:
            wager = int(wager)
        except (TypeError, ValueError):
            return jsonify(error="invalid wager"), 400

        if wager < 0:
            return jsonify(error="wager must not be negative"), 400

        stats = current_user.stats
        if stats is None:
            stats = Stats(user=current_user, balance=DEFAULT_BALANCE)
            db.session.add(stats)
            db.session.flush()

        if wager > stats.balance:
            return jsonify(error="insufficient balance"), 400

        cpu = choice(CHOICES)
        result = outcome(choice_in, cpu)

        stats.wagered += wager
        stats.bets += 1
        if result == "win":
            stats.wins += 1
            stats.profit += wager
            stats.balance += wager
        elif result == "draw":
            stats.draws += 1
        elif result == "loss":
            stats.losses += 1
            stats.profit -= wager
            stats.balance -= wager

        db.session.commit()

        print(stats.draws)

        return jsonify(
            user_choice=choice_in,
            cpu_choice=cpu,
            result=result,
            balance=stats.balance,
            bets=stats.bets,
            wins=stats.wins,
            draws=stats.draws,
            losses=stats.losses,
            wagered=stats.wagered,
            profit=stats.profit,
        ), 200

    @app.route("/admin")
    @admin_required
    def admin_panel():
        users = User.query.outerjoin(Stats, Stats.user_id == User.id).add_entity(Stats).all()
        rows = []
        for u, s in users:
            rows.append({
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "is_admin": u.is_admin,
                "balance": s.balance if s else 0,
                "bets": s.bets if s else 0,
                "wins": s.wins if s else 0,
                "draws": s.draws if s else 0,
                "losses": s.losses if s else 0,
                "wagered": s.wagered if s else 0,
                "profit": s.profit if s else 0,
                })
        return render_template("admin.html",
                               username=current_user.username,
                               rows=rows,
                               is_admin=current_user.is_admin)

    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            admin_username = os.getenv("ADMIN_USERNAME")
            if admin_username == "":
                print("ADMIN_USERNAME not set")
                exit()
            admin_email = os.getenv("ADMIN_EMAIL")
            if admin_username == "":
                print("ADMIN_EMAIL not set")
                exit()
            admin_password = os.getenv("ADMIN_PASSWORD")
            if admin_username == "":
                print("ADMIN_PASSWORD not set")
                exit()
            u = User(username=admin_username, email=admin_email, is_admin=True)
            u.set_password(admin_password)
            db.session.add(u)
            db.session.flush()
            db.session.add(Stats(user=u, balance=DEFAULT_BALANCE))
            db.session.commit()

    return app


app = create_app()
