PYTHON ?= python
export PYTHONPATH := src

.PHONY: test demo serve validate clean

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m drillverify demo --fixtures fixtures --out outputs

validate:
	$(PYTHON) -m drillverify validate --fixtures fixtures

serve:
	$(PYTHON) -m drillverify serve --db outputs/ledger.sqlite3 --host 127.0.0.1 --port 5000

clean:
	rm -rf outputs .pytest_cache
