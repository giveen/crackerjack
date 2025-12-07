import os
import tempfile
import subprocess
from werkzeug.utils import secure_filename

# Map file extensions to the correct XXX2john Python script
JOHN_SCRIPT_MAP = {
    ".ansible": "ansible2john.py",
    ".ab": "androidbackup2john.py",   # Android backup
    ".apex": "apex2john.py",
    ".notes": "applenotes2john.py",
    ".aruba": "aruba2john.py",
    ".axx": "axcrypt2john.py",
    ".bcr": "bestcrypt2john.py",
    ".wallet": "bitcoin2john.py",
    ".bek": "bitlocker2john.py",
    ".json": "bitwarden2john.py",     # Bitwarden export
    ".ldb": "blockchain2john.py",
    ".cardano": "cardano2john.py",
    ".ccache": "ccache2john.py",
    ".dcr": "diskcryptor2john.py",
    ".dmg": "dmg2john.py",
    ".ecryptfs": "ecryptfs2john.py",
    ".ejabberd": "ejabberd2john.py",
    ".electrum": "electrum2john.py",
    ".kwallet": "kwallet2john.py",
    ".csv": "lastpass2john.py",       # LastPass export
    ".doc": "office2john.py",
    ".docx": "office2john.py",
    ".xls": "office2john.py",
    ".xlsx": "office2john.py",
    ".ppt": "office2john.py",
    ".pptx": "office2john.py",
    ".pdf": "pdf2john.py",
    ".pfx": "pfx2john.py",
    ".pse": "pse2john.py",
    ".key": "ssh2john.py",
    ".pem": "ssh2john.py",
    ".tc": "truecrypt2john.py",
}

JOHN_RUN_DIR = "/home/jeremy/crackerjack/app/lib/modules/xxx_to_john"  # where you downloaded the scripts

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
