# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build
VENVDIR := .venv
PYTHON := python3

# only fish and bash/zsh supported
VENV_CMD := if [ "x${FISH_VERSION}" != "x" ]; then . $(VENVDIR)/bin/activate.fish; else . $(VENVDIR)/bin/activate; fi
RUN_VENV := if [ -d $(VENVDIR) ]; then $(VENV_CMD); fi

$(VENVDIR):
	$(PYTHON) -m virtualenv $(VENVDIR)
	$(VENV_CMD) && pip install -r requirements.txt

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	@echo
	@echo 'Non-Sphinx targets'
	@echo '  .venv       create python3 virtualenv with Sphinx requirements'

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	$(RUN_VENV); \
	$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
