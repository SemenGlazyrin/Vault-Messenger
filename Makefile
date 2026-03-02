.PHONY: help up down build logs test lint format proto clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Запустить сервисы
	docker compose up -d

down: ## Остановить сервисы
	docker compose down

build: ## Пересобрать образы
	docker compose build

logs: ## Логи всех сервисов
	docker compose logs -f

lint: ## Проверка кода
	ruff check shared/ services/ gateway/
	mypy shared/ services/ gateway/ --ignore-missing-imports

format: ## Форматирование
	ruff format shared/ services/ gateway/
	ruff check --fix shared/ services/ gateway/

test: ## Все тесты
	pytest tests/ services/ -v

proto: ## Генерация Python из .proto
	python -m grpc_tools.protoc \
		-I shared/proto \
		--python_out=shared/proto \
		--grpc_python_out=shared/proto \
		--pyi_out=shared/proto \
		shared/proto/*.proto

clean: ## Очистка
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +