from flask_login import current_user, login_required
from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.lib.base.provider import Provider
import json

bp = Blueprint('sessions', __name__)

# Add a sessions index route for listing all sessions
@bp.route('/sessions', methods=['GET'])
@login_required
def index():
    provider = Provider()
    sessions = provider.sessions()

    user_id = 0 if current_user.admin else current_user.id
    all_sessions = sessions.get_all(user_id=user_id)

    return render_template(
        'sessions/index.html',
        sessions=all_sessions
    )

# Existing routes
def dont_update_session(func):
    func._dont_update_session = True
    return func

@bp.route('/create', methods=['POST'])
@login_required
def create():
    provider = Provider()
    sessions = provider.sessions()

    description = request.form['description'].strip()
    if len(description) == 0:
        flash('Please enter a session description', 'error')
        return redirect(url_for('home.index'))

    session = sessions.create(current_user.id, description, current_user.username)
    if session is None:
        flash('Could not create session', 'error')
        return redirect(url_for('home.index'))

    return redirect(url_for('sessions.setup_hashes', session_id=session.id))

# ... keep all your existing parameterized routes here (setup_hashes, setup_hashcat, view, action, files, settings, etc.)
# Nothing else changes — just the new index() route at the top.
