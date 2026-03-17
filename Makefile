## Recorded Future Sandbox Analyser — Go Edition
## ─────────────────────────────────────────────

APP     = rf-sandbox
CMD_DIR = ./cmd

# Détection OS
GOOS   ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

.PHONY: all build run demo deps clean help windows linux

all: deps build

## Installer les dépendances
deps:
	go mod tidy
	go mod download

## Build natif
build:
	go build -ldflags="-s -w" -o $(APP) $(CMD_DIR)
	@echo "✓ Binaire : ./$(APP)"

## Mode démonstration (sans API)
demo: build
	./$(APP) -demo

## Build Windows (depuis Linux/Mac)
windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(APP).exe $(CMD_DIR)
	@echo "✓ Binaire Windows : ./$(APP).exe"

## Build Linux
linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(APP)_linux $(CMD_DIR)
	@echo "✓ Binaire Linux : ./$(APP)_linux"

## Nettoyer
clean:
	rm -f $(APP) $(APP).exe $(APP)_linux
	rm -rf output/*.pdf

## Lancer avec un fichier
run-file:
	./$(APP) -file $(FILE)

## Aide
help:
	@./$(APP) -help
