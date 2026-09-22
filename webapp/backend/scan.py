"""
Scan blueprint: submit scans, stream progress via SSE, list history, view reports.
Background scans run in daemon threads. SSE streams live log output to browser.
"""
import json
import sys
import os
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, request, jsonify, Response, stream_with_context, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from .models import db, User, Scan, Report
from .security import require_json, bot_guard, sanitize_input, escape_html, get_real_ip

scan_bp = Blueprint("scan", __name__, url_prefix="/api/scan")

# Per-scan SSE message queues: scan_id -> Queue
_scan_queues: dict[int, queue.Queue] = {}
_scan_queues_lock = threading.Lock()


def _get_or_create_queue(scan_id: int) -> queue.Queue:
    with _scan_queues_lock:
        if scan_id not in _scan_queues:
            _scan_queues[scan_id] = queue.Queue(maxsize=500)
        return _scan_queues[scan_id]


def _push_log(scan_id: int, message: str, level: str = "info"):
    q = _get_or_create_queue(scan_id)
    try:
        q.put_nowait({"type": "log", "level": level, "message": message})
    except queue.Full:
        pass  # Drop if buffer full — never block the scan thread


def _push_done(scan_id: int, status: str, error: str = None):
    q = _get_or_create_queue(scan_id)
    try:
        q.put_nowait({"type": "done", "status": status, "error": error})
    except queue.Full:
        pass


# ─── Field validation helpers ─────────────────────────────────────────────────

_MODULE_FIELD_TYPES = {
    "domain": "domain",
    "username": "username",
    "breach": "email",
    "search": "query",
    "entity": "query",
    "dork": "query",
    "metadata": "query",  # URL or file path — lenient
    "full": "domain",
}


def _json_error(message: str, code: int):
    return jsonify({"error": escape_html(message)}), code


# ─── Submit Scan ──────────────────────────────────────────────────────────────

@scan_bp.route("/run", methods=["POST"])
@jwt_required()
@bot_guard
@require_json
def run_scan():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return _json_error("Unauthorized", 401)

    data = request.get_json(silent=True) or {}
    module = data.get("module", "").strip().lower()
    target = data.get("target", "").strip()

    # ── Validate module ───────────────────────────────────────────────────────
    if module not in Scan.VALID_MODULES:
        return _json_error(f"Invalid module. Choose one of: {', '.join(sorted(Scan.VALID_MODULES))}", 400)

    # ── Validate + sanitize target ────────────────────────────────────────────
    field_type = _MODULE_FIELD_TYPES[module]
    is_valid, result = sanitize_input(target, field_type)
    if not is_valid:
        return _json_error(f"Invalid target: {result}", 400)
    target = result

    # ── Optional full-scan fields ─────────────────────────────────────────────
    extra_username = extra_email = extra_entity_name = None
    if module == "full":
        if u := data.get("username", "").strip():
            ok, r = sanitize_input(u, "username")
            if not ok:
                return _json_error(f"Invalid username: {r}", 400)
            extra_username = r
        if e := data.get("email", "").strip():
            ok, r = sanitize_input(e, "email")
            if not ok:
                return _json_error(f"Invalid email: {r}", 400)
            extra_email = r
        if en := data.get("entity_name", "").strip():
            ok, r = sanitize_input(en, "query")
            if not ok:
                return _json_error(f"Invalid entity name: {r}", 400)
            extra_entity_name = r

    # ── Concurrent scan limit ─────────────────────────────────────────────────
    max_concurrent = current_app.config.get("MAX_CONCURRENT_SCANS_PER_USER", 2)
    running_count = Scan.query.filter_by(
        user_id=user_id, status=Scan.STATUS_RUNNING
    ).count()
    if running_count >= max_concurrent:
        return _json_error(
            f"You already have {running_count} scan(s) running. "
            f"Please wait for them to finish (max {max_concurrent} concurrent).",
            429,
        )

    # ── Create scan record ────────────────────────────────────────────────────
    scan = Scan(
        user_id=user_id,
        module=module,
        target=target,
        extra_username=extra_username,
        extra_email=extra_email,
        extra_entity_name=extra_entity_name,
        status=Scan.STATUS_PENDING,
    )
    db.session.add(scan)
    db.session.commit()

    # ── Launch background thread ───────────────────────────────────────────────
    app = current_app._get_current_object()
    thread = threading.Thread(
        target=_run_scan_background,
        args=(app, scan.id),
        daemon=True,
        name=f"scan-{scan.id}",
    )
    thread.start()

    current_app.logger.info(
        f"Scan {scan.id} started: module={module} target={target!r} user={user_id} ip={get_real_ip()}"
    )

    return jsonify({"scan_id": scan.id, "status": "pending"}), 202


# ─── Background Scan Execution ────────────────────────────────────────────────

def _run_scan_background(app, scan_id: int):
    """Runs in a background daemon thread. Uses app context for DB access."""
    with app.app_context():
        # Add the project src/ to path so we can import osint_agent modules
        src_path = str(Path(__file__).parents[3] / "src")
        if src_path not in sys.path:
            sys.path.insert(0, src_path)

        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status = Scan.STATUS_RUNNING
        db.session.commit()

        try:
            findings = _execute_module(scan, scan_id)
            # Build markdown report
            from osint_agent.modules import report as report_module
            import tempfile, os
            with tempfile.TemporaryDirectory() as tmp:
                basename = f"scan_{scan_id}"
                md_path = report_module.save_markdown(findings, tmp, basename)
                with open(md_path, "r", encoding="utf-8") as f:
                    markdown = f.read()

            rep = Report(scan_id=scan_id)
            rep.set_findings(findings)
            rep.markdown_data = markdown
            db.session.add(rep)
            scan.status = Scan.STATUS_DONE
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()

            _push_log(scan_id, "✅ Scan completed successfully.", "success")
            _push_done(scan_id, "done")

        except Exception as exc:
            db.session.rollback()
            error_msg = str(exc)[:500]
            scan.status = Scan.STATUS_ERROR
            scan.error_message = error_msg
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()
            app.logger.exception(f"Scan {scan_id} failed: {exc}")
            _push_log(scan_id, f"❌ Error: {error_msg}", "error")
            _push_done(scan_id, "error", error_msg)

        finally:
            # Clean up queue after delay
            time.sleep(30)
            with _scan_queues_lock:
                _scan_queues.pop(scan_id, None)


def _execute_module(scan: Scan, scan_id: int) -> dict:
    """
    Execute the appropriate OSINT module.
    Patches print() to also push to the SSE queue for live progress.
    """
    import builtins
    original_print = builtins.print

    def patched_print(*args, **kwargs):
        msg = " ".join(str(a) for a in args)
        _push_log(scan_id, msg, "info")
        original_print(*args, **kwargs)

    builtins.print = patched_print
    try:
        from osint_agent.modules import (
            domain_recon, username_search, breach_check,
            web_search, entity_search, doc_metadata,
        )
        module = scan.module
        target = scan.target
        findings = {"target": target}

        if module == "domain":
            findings["domain"] = domain_recon.run(target)
        elif module == "username":
            findings["username"] = username_search.run(target)
        elif module == "breach":
            findings["breach"] = breach_check.run(target)
        elif module in ("search", "dork"):
            findings["search"] = web_search.run(target)
        elif module == "entity":
            findings["entity"] = entity_search.run(target)
        elif module == "metadata":
            findings["metadata"] = doc_metadata.run(target)
        elif module == "full":
            findings["domain"] = domain_recon.run(target)
            if scan.extra_username:
                findings["username"] = username_search.run(scan.extra_username)
            if scan.extra_email:
                findings["breach"] = breach_check.run(scan.extra_email)
            findings["search"] = web_search.run(target)
            if scan.extra_entity_name:
                findings["entity"] = entity_search.run(scan.extra_entity_name)

        return findings
    finally:
        builtins.print = original_print


# ─── SSE Progress Stream ──────────────────────────────────────────────────────

@scan_bp.route("/status/<int:scan_id>", methods=["GET"])
@jwt_required()
def scan_status_stream(scan_id: int):
    user_id = int(get_jwt_identity())
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id, is_deleted=False).first()
    if not scan:
        return _json_error("Scan not found", 404)

    def generate():
        q = _get_or_create_queue(scan_id)
        # If scan is already done, immediately send final status
        if scan.status in (Scan.STATUS_DONE, Scan.STATUS_ERROR):
            event = {"type": "done", "status": scan.status, "error": scan.error_message}
            yield f"data: {json.dumps(event)}\n\n"
            return

        timeout_seconds = 600  # Max 10 min stream
        start = time.time()
        while time.time() - start < timeout_seconds:
            try:
                msg = q.get(timeout=1.0)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") == "done":
                    break
            except queue.Empty:
                # Send keepalive ping
                yield f": ping\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Connection": "keep-alive",
        },
    )


# ─── List Scans ───────────────────────────────────────────────────────────────

@scan_bp.route("/list", methods=["GET"])
@jwt_required()
def list_scans():
    user_id = int(get_jwt_identity())
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(50, max(1, request.args.get("per_page", 20, type=int)))

    pagination = (
        Scan.query
        .filter_by(user_id=user_id, is_deleted=False)
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )

    return jsonify({
        "scans": [s.to_dict() for s in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": per_page,
    }), 200


# ─── Get Report ───────────────────────────────────────────────────────────────

@scan_bp.route("/report/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_report(scan_id: int):
    user_id = int(get_jwt_identity())
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id, is_deleted=False).first()
    if not scan:
        return _json_error("Scan not found", 404)
    if scan.status != Scan.STATUS_DONE:
        return _json_error(f"Scan is not complete (status: {scan.status})", 400)
    if not scan.report:
        return _json_error("Report not found", 404)

    return jsonify(scan.to_dict(include_report=True)), 200


# ─── Delete Scan ──────────────────────────────────────────────────────────────

@scan_bp.route("/<int:scan_id>", methods=["DELETE"])
@jwt_required()
def delete_scan(scan_id: int):
    user_id = int(get_jwt_identity())
    scan = Scan.query.filter_by(id=scan_id, user_id=user_id, is_deleted=False).first()
    if not scan:
        return _json_error("Scan not found", 404)
    if scan.status == Scan.STATUS_RUNNING:
        return _json_error("Cannot delete a running scan", 400)
    scan.is_deleted = True
    db.session.commit()
    return jsonify({"message": "Scan deleted"}), 200
