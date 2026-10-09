# AdversaryFlow

**AdversaryFlow is a local, browser-based security exercise planner that turns
MITRE ATT&CK threat-group and campaign techniques into guided lab plans, with
evidence notes, detection tracking, and exportable reports.**

Choose a threat group or campaign from MITRE ATT&CK, a public reference of
attacker techniques. AdversaryFlow puts its activities in order and provides
lab exercises, evidence notes, and reports. You do not need to write code to
create a plan.

The planner runs on your computer and opens in your web browser. **Creating a
plan or report does not run an attack.** Running an exported exercise is a
separate activity for someone who understands it and has an authorized,
disposable test environment. See [Acceptable use](ACCEPTABLE_USE.md).

**Start here:** [Install and open](#install-and-open) ·
[Create your first plan](#create-your-first-plan) ·
[Save and resume](#save-and-resume-your-work) ·
[Stop and restart](#stop-and-restart) ·
[Something went wrong](#something-went-wrong)

## Install and open

Use the Docker route below on Windows or macOS. Docker runs the application's
required software for you; **you do not need Git, Python, Node.js, an API key,
or a GitHub account for this route**. You need an internet connection for the
initial installation and ATT&CK download. Allow several minutes or longer on
a slow connection; the first start does more work than later starts.

On Linux, or if Docker cannot be installed on your computer, use the
[native installation guide](docs/GETTING_STARTED.md#native-installation-with-python)
instead. It uses Python and the same browser interface.

### 1. Install and start Docker

| Your computer | What to do |
| --- | --- |
| **Windows** | Follow [Docker's Windows installer](https://docs.docker.com/desktop/setup/install/windows-install/). Keep its recommended WSL 2 option, follow any requested Windows setup/restart, then open **Docker Desktop** from Start. |
| **Mac** | Open [Docker's Mac installer](https://docs.docker.com/desktop/setup/install/mac-install/). **Apple menu → About This Mac** shows whether you have an Apple chip or Intel processor; choose the matching download. Open the downloaded file, drag Docker to Applications, then open **Docker** from Applications. |
| **Linux with Docker already installed** | Start Docker and check that `docker compose version` works. If it does not, use the native guide above or [Docker's Linux installation instructions](https://docs.docker.com/desktop/setup/install/linux/). |

Wait until Docker Desktop says its engine is running. Leave it open. If your
work computer requires permission to install software, ask your IT team to
complete this step.

### 2. Download and extract AdversaryFlow

1. Click **[Download AdversaryFlow ZIP](https://github.com/rikterskale/AdversaryFlow/archive/refs/heads/main.zip)**.
   Alternatively, on the [project page](https://github.com/rikterskale/AdversaryFlow),
   choose the green **Code** button, then **Download ZIP**.
2. Find the file in your **Downloads** folder. On Windows, right-click it and
   choose **Extract All**, then **Extract**. On Mac, double-click it. On Linux,
   use your file manager's **Extract** action.
3. Open the extracted folder. You need the folder containing **README.md**,
   **Dockerfile**, **docker-compose.yml**, and **run.ps1**. Its name is usually
   **AdversaryFlow-main**. If you see another folder with that name, open it.
4. Keep that folder somewhere you can find again, such as Documents. Run the
   tool from the extracted folder, not from inside the ZIP.

### 3. Open a command window in that folder

A command window lets you paste the startup instruction. Choose your system:

- **Windows:** in File Explorer, open the folder from step 2, click the
  address bar at the top, type `powershell`, and press **Enter**. A PowerShell
  window opens in that folder. Administrator mode is not needed to start the planner.
- **Mac:** open **Terminal** using Spotlight (**Command+Space**, type
  `Terminal`, press **Enter**). Type `cd` followed by a space, drag the
  extracted folder from Finder into Terminal, then press **Enter**.
- **Linux:** right-click inside the extracted folder and choose **Open in
  Terminal**. If that option is absent, open Terminal, type `cd` followed by
  a space, drag the folder into the window, then press **Enter**.

Copy only the instructions inside a code box, not the box's label. Paste
with **Ctrl+V** in PowerShell, **Command+V** on Mac, or **Ctrl+Shift+V** in a
Linux terminal. Press **Enter** after pasting.

Check Docker first:

```text
docker version
docker compose version
```

Success shows Docker **Client** and **Server** version information and a
**Docker Compose version v2...** line. If you see an error instead, use
[Something went wrong](#something-went-wrong) below.

### 4. Start the planner

In that same window, paste:

```text
docker compose up --build
```

Leave the window open. Download and build messages are normal. The first
start also downloads the Enterprise ATT&CK data, which is tens of megabytes.
Look for **AdversaryFlow container configured successfully** and these lines:

```text
URL:       http://127.0.0.1:5000
API token: a-long-random-value (generated for this container start)
Next step: open the URL and enter this token when prompted.
```

`a-long-random-value` above is an example. Use the actual value in **your**
window, stopping before the parenthesized note. This token is a temporary
access code generated by the tool; you do not need to register for one. Keep
it private. In Windows PowerShell, select
the token with the mouse and press **Enter** to copy it. On Mac, select it
and press **Command+C**. On Linux, select it and press **Ctrl+Shift+C**.

Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your usual browser.
This address means "this computer"; it is not a public website. Paste the
token into **API token** and choose **Connect securely** if prompted. Wait
for preparation to finish and **Begin emulation plan** to become available.
If preparation fails, follow [Something went wrong](#something-went-wrong).

**Installation worked when you can open the planner and choose a threat group.**

## Create your first plan

Your first session creates a report without running any exercise:

1. Select **Begin emulation plan**.
2. Keep the default **Enterprise** data and choose a threat group or campaign.
   You can type a name in the search box. Select **Continue to scope**.
3. Choose the platform you want the plan to describe: Windows, Linux, or
   macOS. Leave **Allow network-active
   commands**, **Allow administrator commands**, and **Allow high-risk
   commands** off. Select **Build plan**.
4. Read a technique card and its explanation. Leave command outcomes at
   **Not run** and detection results at **Not assessed**. Those fields record
   real observations; creating a plan does not make an exercise pass.
5. Select **Finish & export**, then **Save JSON plan**. A `.json` file saves
   the plan and any notes so you can resume later.
6. Select **Generate report**. After the preview appears, choose **PDF** for
   a printable report, or **HTML** for a report you can open in a browser.
7. Find the files in your browser's Downloads list or your Downloads folder.
   Open the PDF or HTML report to check it. Keep the JSON file as your backup;
   you do not need to open or edit its contents.

Success is a saved JSON plan and a readable report, with `0` outcomes recorded.
**Copy command** only copies text; an execution-kit download only saves files.
Run exercises only after reviewing their requirements and arranging a separate,
authorized lab. The [execution-kit guide](docs/EXPORTS.md#operator-execution-kit)
explains the operator-controlled runner.

## Save and resume your work

- **Return to the welcome tools:** choose **Home** (the house icon in the
  header) to browse saved engagements or compare intelligence while keeping
  your current plan. Choose **Resume <actor> plan** to return to it.
- **Keep a backup:** use **Finish & export → Save JSON plan** before stopping,
  changing browsers, or clearing browser data. JSON files can contain private
  notes and command text; store and share them appropriately.
- **Continue in the same browser:** reopen the same address and choose
  **Resume <actor> plan** on the welcome screen. Normal browser storage saves
  progress automatically; private browsing or blocked storage may prevent it.
- **Restore a backup:** on the welcome screen, choose **Resume JSON plan** and
  select your downloaded `.json` file. Both schema 2.0 and 3.0 plans are
  supported. Double-clicking the file does not resume the application.
  Restored command text is flagged for review before use; this is expected.
- **Save on this computer's service:** **Save engagement** creates a separate
  saved revision. It is local storage, not an online backup. Keep your JSON
  copy too. If the ATT&CK version or platform changes, use **Saved evidence
  from other platforms or data versions** to recover the earlier snapshot.

Workspace safety: existing work is confirmed before replacement, and persistent
storage failures stay visible until a successful save. **Download workspace
recovery copy** preserves scope, workflow, archives and unfinished evidence even
when a plan cannot export. Welcome also provides **Browse saved engagements**
for server revisions. See [command coverage and proof verification](docs/COMMAND_COVERAGE.md)
for executor availability, variant selection and audit limitations. See [export and recovery contracts](docs/EXPORTS.md) for
UTF-8 limits, reference validation, catalog reload, executed/skipped counts and
offline Unicode PDF support.

You can review and report a scoped plan even when no commands are runnable.
The report documents the coverage gaps; command copying and execution-kit
downloads remain unavailable until the scope includes runnable commands.
Saved plans and JSON recovery remain accessible while the service prepares.

## Stop and restart

**Stop:** save a JSON backup, click the command window running AdversaryFlow,
then press **Ctrl+C**. Wait for the shutdown messages. Closing only the
browser tab leaves the service running.

**Start again:** open Docker Desktop, reopen a command window in the extracted
folder as in step 3, then run:

```text
docker compose up
```

If you set another port with a `.env` file, it is reused automatically.
Reopen the printed browser address and use the token printed for this start.
The token can change after restarting. Existing ATT&CK downloads and
server-saved engagements remain in Docker's saved data volume. Avoid deleting
that volume or resetting Docker Desktop when troubleshooting.

**Update a ZIP installation:** save your JSON backup, stop the old service,
download and extract the new ZIP, then repeat the startup steps using
`docker compose up --build` in the new folder. Keep Docker's saved volume.
For Git, Python, or wheel installations, use the [update instructions](docs/GETTING_STARTED.md#updating).

## Something went wrong

Keep the command window open and read the last error. Start with the matching
row below. These steps do not require deleting your saved work.

| What you see | What to do next |
| --- | --- |
| `docker` is not recognized or `command not found` | Install Docker using step 1. Close and reopen the command window using step 3, then try the version checks again. |
| `Cannot connect to the Docker daemon`, engine stopped, or a Docker connection error | Open Docker Desktop, wait for the engine to run, then retry `docker compose up`. If Docker asks for a WSL update or restart, complete its linked instructions first. |
| `no configuration file provided` or `docker-compose.yml` cannot be found | You are in the wrong folder or still inside the ZIP. Repeat steps 2 and 3 using the folder that contains **docker-compose.yml**. |
| `port is already allocated`, `address already in use`, or `WinError 10048` | Stop this startup with **Ctrl+C**, then follow [Use another port](docs/TROUBLESHOOTING.md#use-another-port). Open the new printed address. |
| Browser says the site cannot be reached | Confirm the command window is still running and Docker is open. Use the **URL** printed by the service, including its port number. Reopen the address after startup finishes. |
| The API token is rejected | Use the token from the current startup, with no label, quotes, or spaces. Recover it with `docker compose logs adversaryflow` in another command window opened in the same folder. |
| Preparation fails, or downloads report a proxy/certificate/network error | Check your internet connection. Open the status button in the app's header, then **System health → Host self-test**. On a managed network, ask IT to permit the official download and dependency hosts listed in the [troubleshooting guide](docs/TROUBLESHOOTING.md#downloads-or-preparation-fail). |
| A plan has no runnable steps | Try another actor or the correct destination platform. Keep the three Allow options off for your first session. Some techniques have no exercise for the selected platform. |
| Notes disappeared or the browser cannot save progress | Return to the original browser and address, or restore your JSON file with **Resume JSON plan**. Changing the port, using private mode, or clearing browser data creates a different or empty browser workspace. |
| A report or download fails | Use **Save JSON plan** first, check the inline error and **System health**, restore the service/token, then choose **Retry report generation** or retry the download. |

For a deeper check, open a **second** command window in the same application
folder while the container is running:

```text
docker compose exec adversaryflow adversaryflow doctor
```

Look for `"ok": true`. A failing required check includes a suggested fix.
If you still need help, follow [Ask for help](docs/TROUBLESHOOTING.md#ask-for-help).
Include your operating system, browser, what you tried, and the exact error.
Remove API tokens and private notes from screenshots or logs before sharing.

## More you can do

- Track what ran separately from what your monitoring detected, with notes,
  timestamps, and evidence references.
- Import a CSV, ATT&CK Navigator layer, or STIX bundle; review candidate
  mappings and attach accepted procedures to a plan. See
  [Structured intelligence import](docs/INTELLIGENCE_IMPORT.md).
- Download an offline execution kit, an Atomic Red Team draft, a Markdown
  report, or a commented runbook. See [Export formats](docs/EXPORTS.md).
- Include ICS (industrial systems) and Mobile mappings. Their exercises are
  desktop lab proxies, not tests for industrial devices, Android, or iOS.
- Use cached ATT&CK data offline after one successful online start. See
  [Offline use](docs/GETTING_STARTED.md#offline-use).

## Technical reference

The application is a React/TypeScript interface served by a local Flask API.
It reads the official [MITRE ATT&CK data](https://github.com/mitre-attack/attack-stix-data),
resolves each domain's actor mappings, and orders techniques using its published
tactic matrix. The service validates plan schemas, rebinds execution-kit
commands to its catalog, and never runs catalog commands itself.

| Guide | Read it when you need to... |
| --- | --- |
| [Getting started](docs/GETTING_STARTED.md) | Use Python instead of Docker, update, or work offline |
| [Installation reference](docs/INSTALL.md) | Configure ports, cache paths, Docker, or wheel installs |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Diagnose setup, downloads, reports, and browser recovery |
| [Operations](docs/OPERATIONS.md) | Back up service data or configure deliberate remote access |
| [Architecture](docs/ARCHITECTURE.md) | Understand components and data flow |
| [OpenAPI contract](docs/openapi.yaml) | Integrate with the API |
| [Contributing](CONTRIBUTING.md) | Develop, test, or extend the command catalog |

JSON exports use [schema 2.0](schemas/adversaryflow-plan.schema.json), or
[schema 3.0](schemas/adversaryflow-plan-v3.schema.json) when reviewed procedures
or receipts are included. A bounded-exercise receipt reports what its runner
observed; independent endpoint or monitoring evidence is needed to verify it.

Licensed under [Apache-2.0](LICENSE). See [Support](SUPPORT.md),
[Governance](GOVERNANCE.md), and [Security](SECURITY.md).
