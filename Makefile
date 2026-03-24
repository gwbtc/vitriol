.PHONY: build clean

VENDOR_BASE_DEV := \
	lib/dbug.hoon \
	lib/default-agent.hoon \
	lib/server.hoon \
	lib/skeleton.hoon \
	lib/verb.hoon \
	mar/bill.hoon \
	mar/hoon.hoon \
	mar/kelvin.hoon \
	mar/mime.hoon \
	mar/noun.hoon \
	sur/verb.hoon

build:
	@rm -rf dist
	@mkdir -p dist
	@echo "Building vitriol desk..."
	@cp -r desk/* dist/
	@for f in $(VENDOR_BASE_DEV); do \
		mkdir -p dist/$$(dirname $$f); \
		cp vendor/base-dev/$$f dist/$$f; \
	done
	@echo "Build completed successfully."
	@if [ -n "$(DEST)" ]; then \
		echo "Copying to $(DEST)..."; \
		cp -r dist/* $(DEST); \
		echo "Done."; \
	fi

clean:
	rm -rf dist
