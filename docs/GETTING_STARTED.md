# Getting started

For a first installation with Docker, follow the
[README walkthrough](../README.md#install-and-open). It explains downloading
the ZIP, extracting it, opening a command window, starting the application,
and creating a report. No Git or programming knowledge is required.

This page covers the Python alternative, updating, and offline use. Use
**one** installation route; you do not need both Docker and Python.

## Native installation with Python

This route runs the same local browser application without Docker. It needs
Python 3.10 or newer, an internet connection for installation and the first
ATT&CK download, and a current web browser. Python 3.14 is a tested choice.
Git and Node.js are not needed for a downloaded ZIP.

### 1. Install Python

Choose your operating system. Skip installation if your version check already
shows Python 3.10 or newer.

**Windows**

1. Open [Python's official Windows instructions](https://docs.python.org/3.14/using/windows.html).
   Install the **Python Install Manager** using the linked Python.org or
   Microsoft Store download. Open the downloaded installer and choose **Install**.
2. Close any old command windows. Open **PowerShell** from Start.
3. For a new Install Manager installation, paste this to install Python 3.14:

```powershell
py install 3.14
```

4. Check the installed runtime:

```powershell
py -3 --version
```

Success is a line such as `Python 3.14.x`, not an interactive `>>>` prompt.
If `py` is not recognized, reopen PowerShell and follow
[Python's command troubleshooting](https://docs.python.org/3.14/using/windows.html#troubleshooting).
The `py install` command is for the new Install Manager; an existing older
Python launcher can still run `py -3 --version` and the application.

**Mac**

1. Open [Python's Mac downloads](https://www.python.org/downloads/macos/).
   Choose a stable Python 3.14 release and its **macOS 64-bit universal2 installer**.
2. Open the downloaded `.pkg` file and follow the installer.
3. Open **Applications → Python 3.14** and double-click **Install Certificates.command**.
   This prepares Python to download over HTTPS.
4. Open a new **Terminal** window and check:

```bash
python3 --version
```

Success is `Python 3.14.x` (an existing Python 3.10 or newer also works).

**Ubuntu or Debian Linux**

Open Terminal. Check Python first:

```bash
python3 --version
```

If Python is missing or its virtual-environment support is missing, install
the distribution's packages:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip
```

`sudo` may ask for your computer password. Nothing appears while you type it;
press **Enter** when finished. Check `python3 --version` again; it must be
3.10 or newer. On another Linux distribution, use its Python installation
instructions or ask your administrator for Python and virtual-environment support.

### 2. Download and open the application folder

Follow [README steps 2 and 3](../README.md#2-download-and-extract-adversaryflow):
download the ZIP, extract it, and open a command window in the folder that
contains **run.ps1**, **run.sh**, and **README.md**. Do not run inside the ZIP.
These same folder-opening instructions work for the Python route.

### 3. Install and start

Paste the block for your system into that folder's command window.

**Windows PowerShell**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1
```

This runs the downloaded launcher in a separate PowerShell process. The
execution-policy setting applies to that process; it does not permanently
change your computer's policy. Use the launcher from this project's ZIP.
If a work computer's policy still blocks it, ask IT to approve the installation.

**Mac or Linux**

```bash
chmod +x run.sh install.sh
./run.sh
```

The first launch creates the application's private Python environment,
installs its dependencies, and runs a self-test. Leave the window open.
You should see:

```text
AdversaryFlow installed and verified. Start it with ...
[AdversaryFlow] starting; the browser will open when ATT&CK data is ready
AdversaryFlow 0.5.3: http://127.0.0.1:5000
```

The first line's launcher name depends on your system. Future versions print
their own version number. The browser can open while ATT&CK data is preparing;
wait for the actor choices to become available. Local native installs do not
require the Docker API token. If the browser does not open, enter the printed
URL manually.

Now follow [Create your first plan](../README.md#create-your-first-plan).
Save a JSON backup before stopping. To stop, click the command window and
press **Ctrl+C**. To restart, reopen a command window in the same application
folder and rerun the same startup block; it reuses the installed environment.

### Check a native installation

Stop the native service before checking its port. In the application folder,
run the commands for your system:

**Windows PowerShell**

```powershell
.\.venv\Scripts\adversaryflow.exe --version
.\.venv\Scripts\adversaryflow.exe doctor
```

**Mac or Linux**

```bash
.venv/bin/adversaryflow --version
.venv/bin/adversaryflow doctor
```

Look for `"ok": true` and `"required_failed": 0`. Each item in `checks`
has a label, `PASS` or `FAIL`, and a suggested fix. A Docker check can fail
without preventing this Python route from working: it is advisory.
See [Troubleshooting](TROUBLESHOOTING.md) if a required check fails.

## Updating

Save a JSON backup, stop the application, then choose the row matching how
you installed it. New browser plans can use schema 2.0 or 3.0; older schema
1.0 files are not supported. Read [CHANGELOG](../CHANGELOG.md) for changes.

| Installation | Update steps |
| --- | --- |
| **ZIP + Docker** | Download and extract the new ZIP. Open a command window in the new application folder. Run `docker compose up --build`. Keep Docker's existing saved volume; do not use `docker compose down --volumes` to update. |
| **ZIP + Python** | Download and extract the new ZIP. Open a command window in the new folder and follow the native startup steps above. The new folder gets its own Python environment; the normal per-user ATT&CK cache and engagement database are retained. Resume your JSON backup. |
| **Git + Docker** | In the existing checkout, run `git pull`, then `docker compose up --build`. |
| **Git + Python** | In the checkout, run `git pull`, then rerun the installer below. The startup launcher alone does not reinstall an existing environment. |
| **Release wheel** | Follow the [wheel install/update reference](INSTALL.md#isolated-install-from-a-wheel). Install the downloaded file; do not use `pipx install adversaryflow`. |

**Reinstall after a Git update, Windows PowerShell:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1
```

**Reinstall after a Git update, Mac or Linux:**

```bash
./install.sh
./run.sh
```

The normal cache/database locations remain the same during an update. If you
configured a custom cache or database path, reuse that configuration. A newer
ATT&CK data version may require rebuilding the plan; keep and restore your
JSON backup rather than marking new steps as already run.

## Offline use

First start online and let the needed ATT&CK domains finish downloading.
Installation and downloads cannot complete offline on an empty computer.
Then stop the application and use the matching command below. Offline mode
uses the saved ATT&CK data; it does not download new data.

**Docker, Windows PowerShell:**

```powershell
$env:ADVERSARYFLOW_OFFLINE = "true"
docker compose up
```

**Docker, Mac or Linux:**

```bash
ADVERSARYFLOW_OFFLINE=true docker compose up
```

**Python, Windows PowerShell:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 --offline
```

**Python, Mac or Linux:**

```bash
./run.sh --offline
```

To return online, stop the application. For the Windows Docker command, run
`Remove-Item Env:ADVERSARYFLOW_OFFLINE` in that same PowerShell window, then
`docker compose up`. For the other commands, restart without the offline
setting/flag. Resume saved work as described in the [README](../README.md#save-and-resume-your-work).

## Need help?

Use the [beginner troubleshooting steps](TROUBLESHOOTING.md#start-here), then
[Ask for help](TROUBLESHOOTING.md#ask-for-help). Advanced configuration and
manual installation live in [Installation reference](INSTALL.md); service
backups and deliberate remote access live in [Operations](OPERATIONS.md).
