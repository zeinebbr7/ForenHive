.PHONY: up down restart logs status rebuild-galah ps

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

status:
	docker compose ps

rebuild-galah:
	docker compose build galah && docker compose up -d --force-recreate galah

ps:
	docker compose ps -a
