CLANG ?= clang
PYTHON ?= python3

all: build check

build:
	$(PYTHON) build.py --clang $(CLANG)

check:
	$(PYTHON) check.py

test:
	$(PYTHON) -m unittest discover -s . -p "test_*.py"

clean:
	rm -f fixture.bpf.o

.PHONY: all build check test clean

