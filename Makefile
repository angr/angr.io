SHELL:=$(shell which bash)

.PHONY: local
default: local

.PHONY: build
build:
	hugo

.PHONY: local
local:
	hugo server

.PHONY: clean
clean:
	rm -rf public
