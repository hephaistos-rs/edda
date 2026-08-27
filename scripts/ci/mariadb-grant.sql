-- The MySQL/MariaDB test harness (`edda_db::test_pool`) creates a fresh,
-- uniquely-named `edda_test_<...>` database per test — Postgres/MySQL have
-- no in-memory mode, so that is how test isolation is achieved. The `edda`
-- user the container provisions only gets `ALL ON eddadb.*`, which is not
-- enough to `CREATE DATABASE` or to run migrations inside the new one.
-- Grant exactly what the per-test-database pattern needs, nothing wider.
--
-- Applied automatically:
--   * locally  — mounted into /docker-entrypoint-initdb.d/ by compose.db.yml
--   * in CI    — piped in by the `test` job once the service is healthy

GRANT CREATE ON *.* TO 'edda'@'%';
GRANT ALL PRIVILEGES ON `edda_test_%`.* TO 'edda'@'%';
FLUSH PRIVILEGES;
