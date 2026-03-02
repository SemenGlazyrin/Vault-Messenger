-- Выполняется один раз при первом запуске PostgreSQL.
-- Создаёт отдельную базу для каждого сервиса — изоляция данных.
-- pgcrypto нужен для gen_random_uuid() в DEFAULT на колонках.

CREATE DATABASE auth;
CREATE DATABASE chat;
CREATE DATABASE file;
CREATE DATABASE audit;

\c auth
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\c chat
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\c file
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\c audit
CREATE EXTENSION IF NOT EXISTS pgcrypto;