import subprocess
import shlex
import os

OPENSSL_BIN = os.path.expanduser("~/PQCnovo/openssl-3.5/bin/openssl")


class OpenSSLCLI:
    def __init__(self, openssl_cmd=None):
        # Caminho do oqsprovider
        oqs_lib_path = os.path.expanduser("~/PQCnovo/oqs-provider/build/lib")

        # 🧠 Configuração robusta do ambiente
        self.env = os.environ.copy()
        self.env["OPENSSL_MODULES"] = oqs_lib_path
        self.env["PATH"] = os.path.expanduser("~/PQCnovo/openssl-3.5/bin") + ":" + self.env.get("PATH", "")

        if openssl_cmd is None:
            openssl_cmd = OPENSSL_BIN   # usar o caminho correto do OpenSSL 3.5
        self.openssl_cmd = openssl_cmd
        self.version = self._get_version()

    def has_algorithm(self, name: str) -> bool:
        """Verifica se o algoritmo de chave pública existe no provider"""
        try:
            out = self.run(["list", "-public-key-algorithms", "-provider", "oqsprovider"])
            algos = out.decode("utf-8", errors="ignore").splitlines()
            # Procura de forma parcial, ignorando maiúsculas/minúsculas
            return any(name.lower() in algo.lower() for algo in algos)
        except Exception:
            return False


    def _get_version(self):
        try:
            out = subprocess.check_output(
                [self.openssl_cmd, "version", "-v"],
                stderr=subprocess.STDOUT,
                env=self.env  # 👈 garante que use o ambiente configurado
            )
            return out.decode("utf-8").strip()
        except Exception:
            return None

    def has_pkeyutl_encap(self):
        try:
            out = subprocess.check_output(
                [self.openssl_cmd, "pkeyutl", "-help"],
                stderr=subprocess.STDOUT,
                env=self.env  # 👈 mesmo aqui
            )
            s = out.decode("utf-8", errors="ignore")
            return "encap" in s or "-encap" in s
        except Exception:
            return False

    def run(self, cmd_args, check=True):
        """
        cmd_args: list of arguments (first must be 'openssl' or not; we'll call with self.openssl_cmd)
        returns stdout bytes
        """
        argv = [self.openssl_cmd] + cmd_args + [
            "-provider", "oqsprovider",
            "-provider-path", os.path.expanduser("~/PQCnovo/oqs-provider/build/lib")
        ]

        try:
            out = subprocess.check_output(
                argv,
                stderr=subprocess.STDOUT,
                env=self.env  # 👈 herdando variáveis do ambiente
            )
            return out
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"OpenSSL error: {e.output.decode('utf-8', errors='ignore')}")

    def run_shell(self, cmdline):
        parts = shlex.split(cmdline)
        return self.run(parts[1:])
