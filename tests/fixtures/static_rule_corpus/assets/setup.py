import subprocess
import urllib.request

if False:
    subprocess.run(["python", "-m", "pip", "install", "demo-package"])
    urllib.request.urlopen("https://example.invalid/build")
    exec("value = 1")
