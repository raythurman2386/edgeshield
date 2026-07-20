.PHONY: all build test clippy audit clean install uninstall docker docker-multiarch docker-push docker-run

BINARY_NAME = edgeshield
BINARY_PATH = target/release/$(BINARY_NAME)
CONFIG_DIR = /etc/edgeshield
SYSTEMD_DIR = /etc/systemd/system
MAN_DIR = /usr/share/man/man8
IMAGE_NAME ?= edgeshield
IMAGE_TAG  ?= latest
PLATFORMS  ?= linux/amd64,linux/arm64
REGISTRY   ?= ghcr.io/edgeshield

all: build

build:
	cargo build --release

test:
	cargo test --workspace

clippy:
	cargo clippy --all-targets -- -D warnings

audit:
	cargo install cargo-audit --locked --quiet 2>/dev/null || true
	cargo audit

clean:
	cargo clean

install: build
	install -d $(DESTDIR)$(CONFIG_DIR)
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	install -d $(DESTDIR)$(MAN_DIR)
	install -m 755 $(BINARY_PATH) $(DESTDIR)/usr/bin/$(BINARY_NAME)
	install -m 644 dist/edgeshield.service $(DESTDIR)$(SYSTEMD_DIR)/edgeshield.service
	install -m 644 dist/edgeshield.8 $(DESTDIR)$(MAN_DIR)/edgeshield.8
	@echo "Installed. Enable with: systemctl enable edgeshield"
	@echo "Start with: systemctl start edgeshield"

uninstall:
	rm -f $(DESTDIR)/usr/bin/$(BINARY_NAME)
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/edgeshield.service
	rm -f $(DESTDIR)$(MAN_DIR)/edgeshield.8
	systemctl daemon-reload

# --- Docker ---------------------------------------------------------------

# Build the image for the host architecture (fast, no buildx needed).
docker:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Build multi-arch images (amd64 + arm64) using buildx. Requires:
#   docker buildx create --use --name edgeshield-builder
# Outputs are loaded into the local image store; use `docker-push` to
# publish them to a registry.
docker-multiarch:
	docker buildx build \
		--platform $(PLATFORMS) \
		-t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) \
		--load \
		.

# Push multi-arch images to the registry. Requires `docker login` for
# the target registry (e.g. `echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin`).
docker-push:
	docker buildx build \
		--platform $(PLATFORMS) \
		-t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) \
		--push \
		.

# Quick local smoke test: run the container with host networking and
# verify the binary responds. Requires CAP_NET_RAW for real capture.
docker-run:
	docker run --rm --net=host --cap-add=NET_RAW \
		$(IMAGE_NAME):$(IMAGE_TAG) default-config
