"""Shell-completion script generation for the ``adversaryflow`` CLI.

Completion is static (no runtime introspection of a live target), so the scripts
only ever suggest subcommand names and the small, fixed set of choice values that
are safe to advertise. Generating a script never contacts a network or a target.
"""

from __future__ import annotations

SUPPORTED_SHELLS = ("bash", "zsh", "fish", "powershell")

# Top-level subcommands offered for completion.
TOP_COMMANDS = (
    "validate", "plan", "intel-sync", "draft", "demo", "doctor", "quickstart", "support-bundle",
    "capabilities", "adapter", "guide", "provider", "campaign", "telemetry",
    "detection", "coverage", "manager", "completion", "explain",
)

# Second-level subcommands keyed by their parent, for shells that can offer them.
NESTED_COMMANDS = {
    "adapter": ("status",),
    "provider": ("status", "validate", "configure", "diagnose", "profile", "policy", "test"),
    "campaign": ("list", "inspect", "reject", "cancel", "reset", "assess", "retest"),
    "telemetry": ("normalize", "preflight", "export"),
    "detection": ("export",),
    "completion": SUPPORTED_SHELLS,
}


def _bash_script() -> str:
    tops = " ".join(TOP_COMMANDS)
    nested = "\n".join(
        f'        {parent}) COMPREPLY=( $(compgen -W "{" ".join(children)}" -- "$cur") ); return;;'
        for parent, children in NESTED_COMMANDS.items()
    )
    return f"""# adversaryflow bash completion
# Load with: source <(adversaryflow completion bash)
_adversaryflow_complete() {{
    local cur prev words cword
    _init_completion 2>/dev/null || {{ cur="${{COMP_WORDS[COMP_CWORD]}}"; prev="${{COMP_WORDS[COMP_CWORD-1]}}"; }}
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "{tops}" -- "$cur") )
        return
    fi
    case "${{COMP_WORDS[1]}}" in
{nested}
    esac
    COMPREPLY=( $(compgen -W "--json --quiet --verbose --human --no-color --help" -- "$cur") )
}}
complete -F _adversaryflow_complete adversaryflow
"""


def _zsh_script() -> str:
    tops = " ".join(TOP_COMMANDS)
    nested = "\n".join(
        f'    {parent}) subcmds=({" ".join(children)});;'
        for parent, children in NESTED_COMMANDS.items()
    )
    return f"""#compdef adversaryflow
# adversaryflow zsh completion
# Load with: adversaryflow completion zsh > "${{fpath[1]}}/_adversaryflow"
_adversaryflow() {{
    local -a subcmds
    if (( CURRENT == 2 )); then
        compadd {tops}
        return
    fi
    case "${{words[2]}}" in
{nested}
    esac
    (( ${{#subcmds}} )) && compadd $subcmds
    compadd -- --json --quiet --verbose --human --no-color --help
}}
_adversaryflow "$@"
"""


def _fish_script() -> str:
    lines = ["# adversaryflow fish completion",
             "# Load with: adversaryflow completion fish | source",
             "complete -c adversaryflow -f"]
    top_list = " ".join(TOP_COMMANDS)
    lines.append(f'complete -c adversaryflow -n "__fish_use_subcommand" -a "{top_list}"')
    for parent, children in NESTED_COMMANDS.items():
        lines.append(f'complete -c adversaryflow -n "__fish_seen_subcommand_from {parent}" -a "{" ".join(children)}"')
    for flag, desc in (("--json", "Force JSON output"), ("--quiet", "Terse status line"),
                       ("--verbose", "Extra detail"), ("--human", "Force human output"),
                       ("--no-color", "Disable colour")):
        lines.append(f'complete -c adversaryflow -l {flag.lstrip("-")} -d "{desc}"')
    return "\n".join(lines) + "\n"


def _powershell_script() -> str:
    tops = ", ".join(f"'{command}'" for command in TOP_COMMANDS)
    nested_cases = "\n".join(
        f"            '{parent}' {{ @({', '.join(repr(child) for child in children)}) }}"
        for parent, children in NESTED_COMMANDS.items()
    )
    return f"""# adversaryflow PowerShell completion
# Load with: adversaryflow completion powershell | Out-String | Invoke-Expression
Register-ArgumentCompleter -Native -CommandName adversaryflow -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $tokens = $commandAst.CommandElements | ForEach-Object {{ $_.ToString() }}
    $top = @({tops})
    if ($tokens.Count -le 2) {{
        $candidates = $top
    }} else {{
        $candidates = switch ($tokens[1]) {{
{nested_cases}
            default {{ @('--json', '--quiet', '--verbose', '--human', '--no-color') }}
        }}
    }}
    $candidates | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}
"""


_GENERATORS = {
    "bash": _bash_script,
    "zsh": _zsh_script,
    "fish": _fish_script,
    "powershell": _powershell_script,
}


def completion_script(shell: str) -> str:
    """Return the completion script for ``shell`` (one of :data:`SUPPORTED_SHELLS`)."""
    try:
        return _GENERATORS[shell]()
    except KeyError as exc:
        raise ValueError(f"Unsupported shell '{shell}'. Choose one of: {', '.join(SUPPORTED_SHELLS)}") from exc
