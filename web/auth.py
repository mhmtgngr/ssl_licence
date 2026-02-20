"""Authentication and authorization module."""

import functools
import os

from urllib.parse import urlparse

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, session, g, jsonify,
)

from web.services import get_user_store, get_audit_log
from tracker.user import User, UserRole

bp = Blueprint("auth", __name__)


# ── Configuration ────────────────────────────────────────────────────


def get_auth_config() -> dict:
    """Return auth configuration from env vars."""
    return {
        "apisix_enabled": os.environ.get("APISIX_AUTH_ENABLED", "false").lower() == "true",
        "apisix_user_header": os.environ.get("APISIX_USER_HEADER", "X-User-Id"),
        "apisix_role_header": os.environ.get("APISIX_ROLE_HEADER", "X-User-Role"),
        "apisix_display_name_header": os.environ.get("APISIX_DISPLAY_NAME_HEADER", "X-User-Display-Name"),
    }


# ── Identity Resolution (before_request hook) ────────────────────────


def load_current_user():
    """Resolve current user from APISIX headers or session.

    Sets g.current_user to a User object or None.
    """
    if request.endpoint and request.endpoint == "static":
        return

    g.current_user = None

    config = get_auth_config()

    # 1. Try APISIX pass-through headers (OIDC)
    if config["apisix_enabled"]:
        apisix_user = request.headers.get(config["apisix_user_header"])
        if apisix_user:
            apisix_display = request.headers.get(config["apisix_display_name_header"], apisix_user)
            store = get_user_store()
            user = store.get_by_username(apisix_user)
            if user:
                if user.disabled:
                    return
                # Update display name and last_login from OIDC token
                from datetime import datetime, timezone
                store.update(user.user_id,
                             display_name=apisix_display or user.display_name,
                             last_login=datetime.now(timezone.utc))
                g.current_user = user
            else:
                # Auto-create OIDC user on first login (default: viewer)
                new_user = User(
                    username=apisix_user,
                    role=UserRole.VIEWER,
                    display_name=apisix_display,
                    auth_source="oidc",
                )
                store.add(new_user)
                get_audit_log().log("user_auto_created", apisix_user,
                                    f"OIDC first login, role: viewer", user="system")
                g.current_user = new_user
            return

    # 2. Try Flask session (local login)
    user_id = session.get("user_id")
    if user_id:
        store = get_user_store()
        user = store.get_by_id(user_id)
        if user and not user.disabled:
            g.current_user = user


# ── Decorators ───────────────────────────────────────────────────────


def login_required(f):
    """Decorator: require an authenticated user."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if g.get("current_user") is None:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles: str):
    """Decorator: require one of the specified roles.

    Usage:
        @role_required("admin")
        @role_required("admin", "editor")
    """
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = g.current_user
            if user.role.value not in roles:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"error": "Insufficient permissions"}), 403
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("dashboard.index"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ── Helper: get current username for audit logging ───────────────────


def current_username() -> str:
    """Return the current user's username, or 'system' if not in request context."""
    try:
        user = g.get("current_user")
        if user:
            return user.username
    except RuntimeError:
        pass
    return "system"


# ── Redirect safety ──────────────────────────────────────────────────


def _is_safe_redirect(target: str) -> bool:
    """Return True only if *target* redirects to the same host (or is path-only)."""
    parsed = urlparse(target)
    return parsed.scheme in ("", "http", "https") and not parsed.netloc


# ── Login / Logout Routes ────────────────────────────────────────────


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Local login form and handler."""
    if g.get("current_user"):
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("auth/login.html")

        store = get_user_store()
        user = store.authenticate(username, password)

        if user:
            session.clear()
            session["user_id"] = user.user_id
            session["username"] = user.username
            session.permanent = True
            get_audit_log().log("user_login", user.username, f"Role: {user.role.value}", user=user.username)
            next_url = request.args.get("next", "")
            if not next_url or not _is_safe_redirect(next_url):
                next_url = url_for("dashboard.index")
            return redirect(next_url)
        else:
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html")

    return render_template("auth/login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    """Log out the current user."""
    username = g.current_user.username if g.get("current_user") else "unknown"
    get_audit_log().log("user_logout", username, user=username)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ── User Management Routes (Admin only) ─────────────────────────────


@bp.route("/users")
@role_required("admin")
def list_users():
    """Admin: list all local users."""
    store = get_user_store()
    users = store.list_all()
    return render_template("auth/users.html", users=users)


@bp.route("/users/add", methods=["GET", "POST"])
@role_required("admin")
def add_user():
    """Admin: add a new local user."""
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        display_name = request.form.get("display_name", "").strip()
        role = request.form.get("role", "viewer")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("auth/user_form.html", action="add")

        store = get_user_store()
        if store.get_by_username(username):
            flash(f"User '{username}' already exists.", "warning")
            return render_template("auth/user_form.html", action="add")

        try:
            user_role = UserRole(role)
        except ValueError:
            user_role = UserRole.VIEWER

        user = User(username=username, role=user_role, display_name=display_name or username)
        user.set_password(password)
        store.add(user)

        get_audit_log().log("user_add", username, f"Role: {user_role.value}", user=current_username())
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("auth.list_users"))

    return render_template("auth/user_form.html", action="add")


@bp.route("/users/<user_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def edit_user(user_id):
    """Admin: edit user role/display name/password."""
    store = get_user_store()
    user = store.get_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("auth.list_users"))

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        role = request.form.get("role", user.role.value)
        password = request.form.get("password", "")
        disabled = request.form.get("disabled") == "on"

        try:
            user_role = UserRole(role)
        except ValueError:
            user_role = user.role

        updates = {
            "display_name": display_name or user.display_name,
            "role": user_role,
            "disabled": disabled,
        }
        if password:
            from werkzeug.security import generate_password_hash
            updates["password_hash"] = generate_password_hash(password)

        store.update(user_id, **updates)
        get_audit_log().log("user_edit", user.username, f"Role: {user_role.value}, Disabled: {disabled}", user=current_username())
        flash(f"User '{user.username}' updated.", "success")
        return redirect(url_for("auth.list_users"))

    return render_template("auth/user_form.html", action="edit", edit_user=user)


@bp.route("/users/<user_id>/delete", methods=["POST"])
@role_required("admin")
def delete_user(user_id):
    """Admin: delete a user."""
    store = get_user_store()
    user = store.get_by_id(user_id)

    if user and g.current_user and user.user_id == g.current_user.user_id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("auth.list_users"))

    username = user.username if user else user_id
    if store.remove(user_id):
        get_audit_log().log("user_delete", username, user=current_username())
        flash(f"User '{username}' deleted.", "success")
    else:
        flash("User not found.", "danger")
    return redirect(url_for("auth.list_users"))
