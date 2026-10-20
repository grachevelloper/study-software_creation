.PHONY: test run smoke compose-check

test:
	go test ./...

run:
	JWT_SECRET=local-run-secret DATABASE_PATH=data/notes.db go run .

smoke:
	go run ./cmd/smoke http://127.0.0.1:8080

compose-check:
	docker compose config --quiet
