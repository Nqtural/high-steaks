#!/bin/env sh
if command -v python >/dev/null 2>&1; then
	python -m venv .
	bin/pip install -r requirements.txt
else
	echo "Could not find \`python\`. Is it installed?"
fi
