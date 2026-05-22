.PHONY: up down build migrate loadalgos test shell logs

up:
	docker compose up -d --build

down:
	docker compose down

build:
	docker compose build

migrate:
	docker compose exec web python manage.py migrate

loadalgos:
	docker compose exec web sh -c 'for f in algorithms/*/fixtures.json; do python manage.py loaddata "$$f"; done'

test:
	.venv/bin/pytest -v
	node --test static/**/tests/*.test.js

shell:
	docker compose exec web python manage.py shell

logs:
	docker compose logs -f web
