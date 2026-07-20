.PHONY: all build test clippy audit clean install uninstall

BINARY_NAME = edgeshield
BINARY_PATH = target/release/$(BINARY_NAME)
CONFIG_DIR = /etc/edgeshield
SYSTEMD_DIR = /etc/systemd/system
MAN_DIR = /usr/share/man/man8

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
