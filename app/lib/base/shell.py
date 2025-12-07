# shell.py

import subprocess
import datetime
import shlex
import sys
import os
import logging
import tempfile
from sqlalchemy import and_, desc

from app.lib.models.system import ShellLogModel
from app.lib.models.user import UserModel
from app import db

# Configure logging for this module
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True
)
logger = logging.getLogger(__name__)
logger.debug("shell.py module loaded")


class ShellManager:
    def __init__(self, user_id=0):
        self.user_id = user_id

    def execute(self, command, user_id=None, log_to_db=True):
        user_id = self.user_id if user_id is None else user_id
        if log_to_db:
            log = self.__log_start(' '.join(command), user_id)

        try:
            logger.debug("Executing command: %s", command)
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            output = result.stdout.decode().strip()
            error = result.stderr.decode().strip()

            if error:
                logger.debug("stderr: %s", error)
                output = output + ("\n[stderr]\n" + error)

        except Exception as e:
            logger.exception("Error running command")
            output = f"Error: {e}"

        if log_to_db:
            log = self.__log_finish(log, output)

        return output

    def build_command_from_dict(self, command):
        sanitised = []
        for key, value in command.items():
            item = shlex.quote(key)
            if isinstance(value, str) and len(value) > 0:
                item = item + ' ' + shlex.quote(value)
            else:
                item = item + ' ' + str(value)
            sanitised.append(item.strip())
        return sanitised

    def __log_start(self, command, user_id):
        record = ShellLogModel(
            user_id=user_id,
            command=command,
            executed_at=datetime.datetime.now()
        )
        db.session.add(record)
        db.session.commit()
        db.session.refresh(record)
        logger.debug("Log start: %s", command)
        return record

    def __log_finish(self, record, output):
        record.output = output
        record.finished_at = datetime.datetime.now()
        db.session.commit()
        db.session.refresh(record)
        logger.debug("Log finish: %s", output[:200])  # truncate for readability
        return record

    def get_logs(self, user_id=-1, page=0, per_page=0):
        conditions = and_(1 == 1)
        if user_id >= 0:
            conditions = and_(ShellLogModel.user_id == user_id)

        query = ShellLogModel.query \
            .outerjoin(UserModel, ShellLogModel.user_id == UserModel.id) \
            .add_columns(
                ShellLogModel.id,
                ShellLogModel.user_id,
                ShellLogModel.command,
                ShellLogModel.output,
                ShellLogModel.executed_at,
                ShellLogModel.finished_at,
                UserModel.username
            ) \
            .filter(conditions) \
            .order_by(desc(ShellLogModel.id))

        if page == 0 and per_page == 0:
            return query.all()
        else:
            # Flask-SQLAlchemy 3.x style pagination
            return db.paginate(query, page=page, per_page=per_page, error_out=False)


if __name__ == "__main__":
    # Quick debug harness
    sm = ShellManager(user_id=0)
    test_cmd = ["/bin/echo", "Hello from ShellManager"]
    print("Output:", sm.execute(test_cmd, log_to_db=False))
