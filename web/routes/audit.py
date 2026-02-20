"""Audit log route — view all tracked actions."""

from flask import Blueprint, render_template, request

from web.auth import login_required
from web.services import get_audit_log
from tracker.audit import AuditAction

bp = Blueprint("audit", __name__)


@bp.route("/")
@login_required
def list_entries():
    audit = get_audit_log()

    action_filter = request.args.get("action", "")
    user_filter = request.args.get("user", "").strip()
    q = request.args.get("q", "").strip()

    if action_filter:
        try:
            entries = audit.filter(action=AuditAction(action_filter), limit=500)
        except ValueError:
            entries = audit.list_all()
    elif q:
        entries = audit.filter(target=q, limit=500)
    else:
        entries = audit.list_all()

    if user_filter:
        entries = [e for e in entries if e.user and user_filter.lower() in e.user.lower()]

    from web.sort_utils import sort_items
    sort_f = request.args.get("sort") or "timestamp"
    sort_o = request.args.get("order") or "desc"
    entries, sort_field, sort_order = sort_items(
        entries,
        sort_f,
        sort_o,
        {
            "timestamp": lambda e: e.timestamp,
            "user": lambda e: (e.user or "").lower(),
            "action": lambda e: e.action.value,
            "target": lambda e: e.target.lower(),
        },
    )

    return render_template(
        "audit/list.html",
        entries=entries,
        action_filter=action_filter,
        user_filter=user_filter,
        q=q,
        sort_field=sort_field,
        sort_order=sort_order,
    )
