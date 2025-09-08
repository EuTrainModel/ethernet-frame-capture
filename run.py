#!/usr/bin/env python3
import os, sys, platform, subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
IS_WIN = platform.system() == "Windows"
VENV_PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe") if IS_WIN \
          else os.path.join(ROOT, ".venv", "bin", "python")

def main():
    args = sys.argv[1:]
    cmd = [VENV_PY, "ethernet_cap.py"] + args

    # Auto-elevate on Unix if not root (Scapy needs raw socket/BPF)
    if not IS_WIN:
        try:
            is_root = (os.geteuid() == 0)
        except AttributeError:
            is_root = False
        if not is_root:
            sudo_cmd = ["sudo"] + cmd
            print("+ " + " ".join(sudo_cmd))
            # Replace current process so the child is truly elevated
            os.execvp("sudo", sudo_cmd)

    # Windows or already root: just run
    print("+ " + " ".join(cmd))
    rc = subprocess.call(cmd)
    sys.exit(rc)

if __name__ == "__main__":
    main()
