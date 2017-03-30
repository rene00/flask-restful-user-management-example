#!/usr/bin/make

VENV ?= $(PWD)/venv
PYTHON = $(VENV)/bin/python3
PIP = $(VENV)/bin/pip
FLASK = $(VENV)/bin/flask
FLASK_DEBUG ?= 1
FLASK_HOST ?= 127.0.0.1
FLASK_PORT ?= 5002

default: build

build:
	py3-virtualenv $(VENV)
	$(PIP) install -r requirements.txt

run:
	FLASK_DEBUG=$(FLASK_DEBUG) FLASK_APP=app.py \
	    $(FLASK) run --host=$(FLASK_HOST) --port=$(FLASK_PORT)

rebuild_db:
	$(PYTHON) manage.py dropdata
	$(PYTHON) manage.py db upgrade
	$(PYTHON) manage.py initdata

clean:
	rm -rf $(VENV)
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
