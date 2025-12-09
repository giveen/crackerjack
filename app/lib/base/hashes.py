import os
import shutil
import subprocess
from flask import current_app
from app.lib.base.hashid import HashIdentifier


class HashesManager:
    def __init__(self, filesystem, uploaded_hashes_path):
        self.filesystem = filesystem
        self.uploaded_hashes_path = uploaded_hashes_path

    def get_uploaded_hashes(self):
        return self.filesystem.get_files(self.uploaded_hashes_path)

    def is_valid_uploaded_hashfile(self, uploaded_hashfile):
        files = self.get_uploaded_hashes()
        return uploaded_hashfile in files

    def get_uploaded_hashes_path(self, uploaded_hashfile):
        if not self.is_valid_uploaded_hashfile(uploaded_hashfile):
            return ''

        files = self.get_uploaded_hashes()
        uploaded_hashfile = files[uploaded_hashfile]
        return uploaded_hashfile['path']

    def get_name_from_path(self, path):
        return path.replace(self.uploaded_hashes_path, '').lstrip(os.sep)

    def copy_file(self, src, dst):
        try:
            shutil.copyfile(src, dst)
        except OSError:
            return False

        return True

    def identify_hash_type(self, hash_string):
        """Identify hash type using hashcat --identify --machine-readable with dynamic binary path."""
        try:
            hashcat_path = current_app.config['HASHCAT_BINARY']
            current_app.logger.debug(f"Using hashcat binary: {hashcat_path}")
            
            # Ensure hash_string is properly encoded
            if isinstance(hash_string, str):
                hash_string = hash_string.encode('utf-8')
            
            current_app.logger.debug(f"Running hashcat --identify --machine-readable with hash: {hash_string.decode('utf-8', errors='ignore')[:50]}...")
            
            result = subprocess.run(
                [hashcat_path, '--identify', '--machine-readable'],
                input=hash_string,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            current_app.logger.debug(f"hashcat --identify exit code: {result.returncode}")
            current_app.logger.debug(f"hashcat --identify stdout: {result.stdout}")
            current_app.logger.debug(f"hashcat --identify stderr: {result.stderr}")
            
            if result.returncode == 0:
                mode = result.stdout.strip()
                if mode:
                    current_app.logger.debug(f"Identified hash mode: {mode}")
                    return self.identify_mode(mode)
                else:
                    current_app.logger.debug("No mode returned from hashcat --identify")
            else:
                current_app.logger.error(f"hashcat --identify failed with return code {result.returncode}")
                current_app.logger.error(f"Error output: {result.stderr}")
                
        except Exception as e:
            current_app.logger.error(f"Hash identification failed: {e}")
            current_app.logger.error(f"Exception type: {type(e).__name__}")
            
        return None

    def identify_mode(self, mode):
        """Lookup mode in HashIdentifier."""
        try:
            current_app.logger.debug(f"Looking up hash mode: {mode}")
            identifier = HashIdentifier()
            results = identifier.identify(mode)
            current_app.logger.debug(f"HashIdentifier results: {results}")
            
            if results:
                # Return the first result
                return results[0]['name']
            else:
                current_app.logger.debug(f"No hash type found for mode: {mode}")
                
        except Exception as e:
            current_app.logger.error(f"Error in identify_mode: {e}")
            
        return None
