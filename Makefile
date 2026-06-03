SHELL := /bin/bash

.PHONY: test validate build clean

test:
	opa test policies

validate:
	opa check policies

build:
	mkdir -p dist
	opa build -b policies -o dist/bundle.tar.gz

clean:
	rm -rf dist
