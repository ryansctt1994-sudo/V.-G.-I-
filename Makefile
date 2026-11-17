.PHONY: demo test install

install:
	pip install -e .

demo:
	python -m apps.cli.demo

test:
	python -m unittest discover -s tests -v
