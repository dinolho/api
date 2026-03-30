.PHONY: install up down restart logs backend frontend 

make:
	@echo "Usage: make [target]"
	@echo "Targets: install, up, down, restart"

install:
	@echo "Installing dependencies..."
	@cd backend && ./install.sh
	@cd frontend && pnpm install

	@if [ ! -f backend/.env ]; then \
		echo "Creating default .env file..."; \
		touch backend/.env; \
		echo "ENVIRONMENT=localhost" >> backend/.env; \
		echo "JWT_SECRET=$(shell uuidgen)" >> backend/.env; \
		echo "JWT_EXPIRY_H=168" >> backend/.env; \
		echo "APP_SECRET=$(shell uuidgen)" >> backend/.env; \
		echo "ENCRYPTION_KEY=$(shell uuidgen)" >> backend/.env; \
	fi

	@if [ ! -f .env ]; then \
		ln -s backend.env .env; \
	fi 

	@echo "Starting..."
	@if [ -f .git/info/exclude ]; then \
		echo "/frontend/" > .git/info/exclude; \
	fi
	@make up

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose down && docker compose up -d

