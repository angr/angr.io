VIRTUALENVWRAPPER_SCRIPT=$(shell which virtualenvwrapper.sh)
PYTHON3_LOCATION=/bin/python3

.PHONY: local
default: local

public:
	git clone git@github.com:angr/angr.github.io.git public

.PHONY: install
.ONESHELL:
install:
	source ${VIRTUALENVWRAPPER_SCRIPT}
	mkvirtualenv -p ${PYTHON3_LOCATION} hugo
	pip install -r requirements.txt

.PHONY: uninstall
.ONESHELL:
uninstall:
	source ${VIRTUALENVWRAPPER_SCRIPT}
	rmvirtualenv hugo

.PHONY: check
.ONESHELL:
check: install
	@if [[ -z "${ANGR_ROOT}" ]]; then echo "Set ANGR_ROOT to the path to your angr-dev directory"; exit 1; fi
	source ${VIRTUALENVWRAPPER_SCRIPT}
	workon hugo
	python code-finder.py ${ANGR_ROOT} content/blog/*

.PHONY: build
build: check public

	hugo

.PHONY: deploy
.ONESHELL:
deploy: build
	cd public
	git add .
	git commit -m "Rebuilding hugo site"
	git push

.PHONY: local
local:
	hugo server

.PHONY: clean
clean:
	rm -rf public
