import subprocess
import shlex
import os

OPENSSL_BIN = os.path.expanduser("~/PQCnovo/openssl-3.5/bin/openssl")


class OpenSSLCLI:
    def __init__(self, openssl_cmd=None):
        os.environ["OPENSSL_MODULES"] = os.path.expanduser("~/PQCnovo/oqs-provider/build/lib")
        if openssl_cmd is None:
            openssl_cmd = OPENSSL_BIN   # usar o caminho correto do OpenSSL 3.5
        self.openssl_cmd = openssl_cmd
        self.version = self._get_version()

    def _get_version(self):
        try:
            out = subprocess.check_output([self.openssl_cmd, "version", "-v"], stderr=subprocess.STDOUT)
            return out.decode("utf-8").strip()
        except Exception:
            return None

    def has_pkeyutl_encap(self):
        # Try running 'openssl pkeyutl -help' and search for 'encap' or try a dry-run with -encap and capture return code
        try:
            out = subprocess.check_output([self.openssl_cmd, "pkeyutl", "-help"], stderr=subprocess.STDOUT)
            s = out.decode("utf-8", errors="ignore")
            return "encap" in s or "-encap" in s
        except Exception:
            # Best-effort: return False if we can't detect
            return False

    def run(self, cmd_args, check=True):
        """
        cmd_args: list of arguments (first must be 'openssl' or not; we'll call with self.openssl_cmd)
        returns stdout bytes
        """
        argv = [self.openssl_cmd] + cmd_args
        try:
            out = subprocess.check_output(argv, stderr=subprocess.STDOUT)
            return out
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"OpenSSL error: {e.output.decode('utf-8', errors='ignore')}")

    def run_shell(self, cmdline):
        # Convenience if needed
        parts = shlex.split(cmdline)
        return self.run(parts[1:])
