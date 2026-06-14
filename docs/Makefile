apidoc:
	sphinx-apidoc -o source/api/ ../kha256/

html: apidoc
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."
