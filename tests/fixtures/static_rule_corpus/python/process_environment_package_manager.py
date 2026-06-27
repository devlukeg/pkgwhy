import os
import subprocess


def install_fixture():
    token = os.environ.get("PKGWHY_FIXTURE_TOKEN")
    subprocess.run(["python", "-m", "pip", "install", "demo-package"])
    return token
