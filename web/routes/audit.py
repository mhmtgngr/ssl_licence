"""Audit log route — view all tracked actions."""

from flask import Blueprint, render_template, request

from web.services import get_audit_log
from tracker.audit import AuditAction

bp = Blueprint("audit", __name__)


@bp.route("/")
def list_entries():
    audit = get_audit_log()

    action_filter = request.args.get("action", "")
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

    from web.sort_utils import sort_items
    sort_f = request.args.get("sort") or "timestamp"
    sort_o = request.args.get("order") or "desc"
    entries, sort_field, sort_order = sort_items(
        entries,
        sort_f,
        sort_o,
        {
            "timestamp": lambda e: e.timestamp,
            "action": lambda e: e.action.value,
            "target": lambda e: e.target.lower(),
        },
    )

    return render_template(
        "audit/list.html",
        entries=entries,
        action_filter=action_filter,
        q=q,
        sort_field=sort_field,
        sort_order=sort_order,
    )
