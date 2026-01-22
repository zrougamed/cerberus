# Cerberus UI - Makefile
# Build and run the containerized frontend

IMAGE_NAME ?= cerberus-ui
IMAGE_TAG ?= latest
CONTAINER_NAME ?= cerberus-ui
CERBERUS_BACKEND ?= http://cerberus:8080/api/v1/
PORT ?= 3000

.PHONY: all build run stop clean logs shell push help

# Default target
all: build

# Build the Docker image
build:
	@echo "Building $(IMAGE_NAME):$(IMAGE_TAG)..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Build with no cache
build-no-cache:
	@echo "Building $(IMAGE_NAME):$(IMAGE_TAG) (no cache)..."
	docker build --no-cache -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run the container
run: stop
	@echo "Starting $(CONTAINER_NAME) on port $(PORT)..."
	docker run -d \
		--name $(CONTAINER_NAME) \
		-p $(PORT):80 \
		-e CERBERUS_BACKEND=$(CERBERUS_BACKEND) \
		$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "Cerberus UI running at http://localhost:$(PORT)"

# Run with custom backend URL
run-with-backend:
	@echo "Starting $(CONTAINER_NAME) with backend $(CERBERUS_BACKEND)..."
	docker run -d \
		--name $(CONTAINER_NAME) \
		-p $(PORT):80 \
		-e CERBERUS_BACKEND=$(CERBERUS_BACKEND) \
		$(IMAGE_NAME):$(IMAGE_TAG)

# Stop and remove the container
stop:
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true

# Remove the image
clean: stop
	@echo "Removing image $(IMAGE_NAME):$(IMAGE_TAG)..."
	@docker rmi $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || true

# View container logs
logs:
	docker logs -f $(CONTAINER_NAME)

# Open a shell in the running container
shell:
	docker exec -it $(CONTAINER_NAME) /bin/sh

# Build and run
dev: build run

# Tag and push to registry (set REGISTRY env var)
push:
	@if [ -z "$(REGISTRY)" ]; then \
		echo "Error: REGISTRY not set. Usage: make push REGISTRY=your-registry.com"; \
		exit 1; \
	fi
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# Start with docker-compose (full stack)
compose-up:
	docker-compose up -d

# Stop docker-compose stack
compose-down:
	docker-compose down

# Rebuild and restart with docker-compose
compose-rebuild:
	docker-compose up -d --build

# Show help
help:
	@echo "Cerberus UI - Available targets:"
	@echo ""
	@echo "  make build              Build the Docker image"
	@echo "  make build-no-cache     Build without Docker cache"
	@echo "  make run                Run the container (port $(PORT))"
	@echo "  make stop               Stop and remove the container"
	@echo "  make clean              Remove container and image"
	@echo "  make logs               View container logs"
	@echo "  make shell              Open shell in container"
	@echo "  make dev                Build and run"
	@echo "  make push               Push to registry (set REGISTRY=...)"
	@echo "  make compose-up         Start with docker-compose"
	@echo "  make compose-down       Stop docker-compose stack"
	@echo "  make compose-rebuild    Rebuild and restart compose stack"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  CONTAINER_NAME=$(CONTAINER_NAME)"
	@echo "  CERBERUS_BACKEND=$(CERBERUS_BACKEND)"
	@echo "  PORT=$(PORT)"
	@echo ""
	@echo "Examples:"
	@echo "  make build IMAGE_TAG=v1.0.0"
	@echo "  make run PORT=8080 CERBERUS_BACKEND=http://10.0.0.5:8080/api/v1/"
	@echo "  make push REGISTRY=ghcr.io/myorg"
