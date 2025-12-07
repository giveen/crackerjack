import os
import tempfile
import subprocess
from werkzeug.utils import secure_filename

JOHN_SCRIPT_MAP = {
    ".zip": "zip2john.py",
    ".rar": "rar2john.py",
    ".pdf": "pdf2john.py",
    ".doc": "office2john.py",
    ".docx": "office2john.py",
    ".xls": "office2john.py",
    ".xlsx": "office2john.py",
    ".ppt": "office2john.py",
    ".pptx": "office2john.py",
    ".key": "ssh2john.py",
    ".pem": "ssh2john.py",
    ".pfx": "pfx2john.py",
    ".7z": "7z2john.py",
    ".kdbx": "keepass2john.py",
    ".kdb": "keepass2john.py",
    ".wallet": "bitcoin2john.py",
}

JOHN_RUN_DIR = "/path/to/john/run"  # adjust to your jumbo run dir

class XXXtoJohnManager:
    def __init__(self, run_dir=JOHN_RUN_DIR):
        self.run_dir = run_dir

    def extract(self, file):
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        script = JOHN_SCRIPT_MAP.get(ext)
        if not script:
            return f"Unsupported file type: {ext}"

        temp_dir = tempfile.TemporaryDirectory()
        save_as = os.path.join(temp_dir.name, filename)
        file.save(save_as)

        output = self.__run_script(script, save_as)
        temp_dir.cleanup()
        return output

    def __run_script(self, script, file_path):
        script_path = os.path.join(self.run_dir, script)
        try:
            result = subprocess.run(
                ["python3", script_path, file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            output = result.stdout.decode().strip()
            if result.stderr:
                output += "\n[stderr]\n" + result.stderr.decode().strip()
            return output
        except Exception as e:
            return f"Error running {script}: {e}"
