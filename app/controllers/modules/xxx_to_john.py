from flask import render_template, request
from flask_login import login_required
from app.controllers.modules import bp
from app.lib.modules.xxx_to_john.manager import XXXtoJohnManager

# GET route: show the upload form
@bp.route("/xxx-to-john", methods=["GET"])
@login_required
def xxx_to_john_index():
    return render_template("modules/xxx_to_john/index.html", hash="", detected_type="")

# POST route: handle file upload
@bp.route("/xxx-to-john/upload", methods=["POST"])
@login_required
def xxx_to_john_upload():
    file = request.files.get("document")
    if file:
        manager = XXXtoJohnManager()
        output = manager.extract(file)
        return render_template(
            "modules/xxx_to_john/index.html",
            hash=output,
            detected_type="auto"
        )
    # If no file was provided, just reload the form
    return render_template("modules/xxx_to_john/index.html", hash="", detected_type="")
