.PHONY: test install build clean

install:
	python -m pip install -e .

test:
	PYTHONPATH=src python -m unittest discover -s tests -v

build:
	python -m pip wheel . -w dist

clean:
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .coverage htmlcov
