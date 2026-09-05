# Acceptable use

AdversaryFlow is a **development-lab planner**. It generates ATT&CK-aligned
plans and operator-gated runners. The web service does not execute catalog
commands.

## Authorized use

Use AdversaryFlow only:

- on systems and data you own or are explicitly authorized to test;
- in a disposable development or detection-validation lab;
- after reviewing each command's fidelity, risk, prerequisites, and cleanup.

## Not authorized

Do not use AdversaryFlow, its catalog, or its runners to:

- target production systems, third-party networks, or people;
- dump credential stores, create accounts, install services, or lock sessions
  as a real attack;
- treat a self-reported exercise receipt as independent proof of detection.

## Dual-use

Catalog commands and generated runners can change local state. Operators are
responsible for scope, authorization, and cleanup. High-risk commands require
acknowledgement before copy. Execution kits are rebound to the live catalog so
a submitted plan cannot smuggle an arbitrary payload under this project's name.

Report suspected product vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).
