all: build run

build:
	go build -o reconengine ./cmd/main.go

run:
	@echo "Usage: make run DOMAIN=example.com"
	./reconengine -d $(DOMAIN)

clean:
	rm -f reconengine
