.PHONY: build

.PHONY: check
check:
	@if [[ -z "${ANGR_ROOT}" ]]; then echo "Set ANGR_ROOT to the path to your angr-dev directory"; exit 1; fi
	python code-finder.py ${ANGR_ROOT} content/blog/*

.PHONY: build
build: check
	hugo

.PHONY: update
.ONESHELL:
update: build
	cd public
	git add .
	git commit -m "rebuilding site $(shell date)"
	git push

.PHONY: local
local:
	hugo server
