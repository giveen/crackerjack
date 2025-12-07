from flask import Blueprint

bp = Blueprint('modules', __name__, url_prefix='/modules')

from . import office
from . import keepass
from . import xxx_to_john
