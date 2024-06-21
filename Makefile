test:
	go test ./...

watch_test:
	find . | entr -c -r make test

lint:
	golangci-lint run ./...

watch_lint:
	find . | entr -c -r make lint
