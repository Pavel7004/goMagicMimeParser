.PHONY: all
all: lint

lint:
	@echo "---------------------"
	@echo "Sort imports"
	@echo "---------------------"
	goimportssort -v -w -local "github.com/Pavel7004" .	
	@echo ""
	@echo "---------------------"
	@echo "Running linters"
	@echo "---------------------"
	golangci-lint run ./...
