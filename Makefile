# Convenience wrapper for Unix `make` users.
# All logic lives in the cross-platform runner `tasks.py`, so Windows users
# can run the same commands with:  python tasks.py <target>
#
# Choose the interpreter: `make PYTHON=python3.12 setup`
PYTHON ?= python3

.PHONY: setup install test lint format check demo clean

setup:
	$(PYTHON) tasks.py setup

# Backwards-compatible alias for `setup`.
install: setup

test:
	$(PYTHON) tasks.py test

lint:
	$(PYTHON) tasks.py lint

format:
	$(PYTHON) tasks.py format

check:
	$(PYTHON) tasks.py check

demo:
	$(PYTHON) tasks.py demo

clean:
	$(PYTHON) tasks.py clean
