#!/usr/bin/env python3
import os, sys, platform, subprocess

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(ROOT, ".venv")

def venv_python():
    if platform.system() == "Windows":
        return os.path.join(VENV, "Scripts", "python.exe")
        # Note: on Windows the activation hint will differ (we still show the macOS line if you want exact match,
        # but see the post-setup hints at the bottom where we branch per-OS).
    else:
        return os.path.join(VENV, "bin", "python")

def sh_echo(cmd):
    # mimic bash set -x style: "+ <cmd>"
    print("+ " + " ".join(cmd))

def run(cmd, **kw):
    sh_echo(cmd)
    subprocess.check_call(cmd, **kw)

def main():
    # 📦 line exactly like your screenshot
    print("📦  Setting up project virtual environment...")

    # create venv if missing
    if not os.path.isdir(VENV):
        run([sys.executable, "-m", "venv", VENV])

    py = venv_python()

    # pip upgrade
    print("Upgrading pip in venv…")
    run([py, "-m", "pip", "install", "--upgrade", "pip"])

    # deps
    req = os.path.join(ROOT, "requirements.txt")
    if os.path.isfile(req):
        print("Installing dependencies from requirements.txt…")
        run([py, "-m", "pip", "install", "-r", req])
    else:
        print("Installing default dependencies…")
        run([py, "-m", "pip", "install", "scapy", "colorama"])

    # ensure captures/ with .gitkeep (so empty dir is tracked)
    capdir = os.path.join(ROOT, "captures")
    os.makedirs(capdir, exist_ok=True)
    keep = os.path.join(capdir, ".gitkeep")
    if not os.path.exists(keep):
        open(keep, "w").close()

    # ✅ + two 👉 lines exactly like your macOS setup.sh
    print("\n✅  Setup complete!")
    if platform.system() == "Windows":
        # still give Windows-appropriate hints, but keep style consistent
        print("👉  Next time, activate with: .\\.venv\\Scripts\\Activate.ps1   (PowerShell)")
        print("👉  Or just use: python run.py to launch directly")
    else:
        print("👉  Next time, activate with: source .venv/bin/activate")
        print("👉  Or just use: run.py to launch directly")

if __name__ == "__main__":
    main()
