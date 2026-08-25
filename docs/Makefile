# Minimal makefile for Sphinx documentation
#

SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = pyobs
SOURCEDIR     = source
BUILDDIR      = ../.doc-build

help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

html:
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

livehtml:
	sphinx-autobuild -b html --watch ../pyobs_auth $(ALLSPHINXOPTS) "$(SOURCEDIR)/" "$(BUILDDIR)/html/"

%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
