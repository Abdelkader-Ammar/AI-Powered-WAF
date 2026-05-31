# One-word entrypoints for the standalone demo. Run from demo/.
COMPOSE := docker compose -f docker-compose.yml
REPO    := $(shell cd .. && pwd)
GOIMG   := golang:1.26-bookworm

.PHONY: up orch proxy down watch attack storyline test logs clean

# Compile the orchestrator binary in a golang container with PERSISTENT Go caches
# (named volumes), so after the first build only changed packages recompile
# (~10s vs ~6min). Avoids in-image `go build`, which this host can't cache
# (no BuildKit/buildx). The build container shares glibc with the runtime image.
proxy:             ## compile demo/bin/waf-proxy (incremental, cached)
	@mkdir -p bin
	docker run --rm \
	  -v "$(REPO)":/src \
	  -v ai-waf-gobuild:/root/.cache/go-build \
	  -v ai-waf-gomod:/go/pkg/mod \
	  -w /src/tier-0 \
	  $(GOIMG) go build -buildvcs=false -o /src/demo/bin/waf-proxy .

up: proxy           ## build + start the whole stack
	$(COMPOSE) up --build -d
	@echo "proxy:     http://localhost:8080"
	@echo "admin API: http://localhost:8081"
	@echo "dashboard: http://localhost:8082"

orch: proxy         ## fast-rebuild + restart just the orchestrator
	$(COMPOSE) up -d --build orchestrator

down:              ## stop and remove everything
	$(COMPOSE) down -v

watch:             ## live read-only correlation console (Ctrl-C to stop)
	$(COMPOSE) logs -f orchestrator | python3 observer/console.py

attack:            ## run one scenario:  make attack S=sqli_coraza
	python3 attacks/sim.py scenario $(S)

storyline:         ## run the scripted live-demo narrative
	python3 attacks/sim.py storyline

test:              ## black-box regression suite (stack must be up)
	cd . && pytest tests/ -v

test-norasp:       ## skip RASP-dependent scenarios
	cd . && pytest tests/ -v -m "not rasp"

logs:
	$(COMPOSE) logs -f

clean: down
	rm -rf report/*.json report/*.png
