SHELL:=$(shell which bash)

.PHONY: local
default: local

public:
	git clone git@github.com:angr/angr.github.io.git public

.PHONY: build
build: public
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
