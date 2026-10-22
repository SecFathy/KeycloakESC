SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help up down logs bootstrap check exploit attack-b attack-c attack-d all clean

help:
	@echo "Keycloak composite map-role escalation lab"
	@echo ""
	@echo "  make up         Start Keycloak + auto-bootstrap the vulnerable realm"
	@echo "  make check      Run the non-destructive vuln probe"
	@echo "  make exploit    Self-escalate limited-admin -> realm-admin (Attack A)"
	@echo "  make attack-b   Nested composite onto bob"
	@echo "  make attack-c   Client-role wrapper onto carol"
	@echo "  make attack-d   Map wrapper onto a group with members"
	@echo "  make all        Full chain (check + A + B + C + D)"
	@echo "  make logs       Follow Keycloak logs"
	@echo "  make down       Stop containers"
	@echo "  make clean      Stop and remove volumes"

up:
	$(COMPOSE) up -d
	@echo "[*] Keycloak + bootstrap starting. Follow progress with: make logs"
	@echo "[*] Admin console: http://127.0.0.1:$${KC_PORT:-8080}  (admin/admin)"

logs:
	$(COMPOSE) logs -f keycloak

bootstrap:
	$(COMPOSE) run --rm bootstrap

check:    ; ./poc/kc_composite_maprole_poc.sh check
exploit:  ; ./poc/kc_composite_maprole_poc.sh exploit
attack-b: ; ./poc/kc_composite_maprole_poc.sh attack-b
attack-c: ; ./poc/kc_composite_maprole_poc.sh attack-c
attack-d: ; ./poc/kc_composite_maprole_poc.sh attack-d
all:      ; ./poc/kc_composite_maprole_poc.sh all

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v
