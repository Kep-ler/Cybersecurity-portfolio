package aegis

# =========================================================================
# CONFIGURATION
# =========================================================================

# Ports that must not be exposed to the public Internet.
restricted_ports := {22, 3306, 3389, 5432}


# =========================================================================
# RFC1918 PRIVATE NETWORK HELPERS
# =========================================================================

is_private_rfc1918(cidr) {
    net.cidr_contains("10.0.0.0/8", cidr)
}

is_private_rfc1918(cidr) {
    net.cidr_contains("172.16.0.0/12", cidr)
}

is_private_rfc1918(cidr) {
    net.cidr_contains("192.168.0.0/16", cidr)
}


# =========================================================================
# PUBLIC CIDR HELPERS
# =========================================================================

# IPv4 CIDR is considered public when it is within IPv4 address space
# and is not an RFC1918 private network.
is_public_ipv4_cidr(cidr) {
    net.cidr_contains("0.0.0.0/0", cidr)
    not is_private_rfc1918(cidr)
}

# IPv6 CIDR is considered public when it is within IPv6 address space.
is_public_ipv6_cidr(cidr) {
    net.cidr_contains("::/0", cidr)
}


# =========================================================================
# PUBLIC INGRESS HELPER
# =========================================================================

# Check for a public IPv4 CIDR.
# object.get() safely handles missing or null CIDR fields.
is_public_ingress(ingress) {
    is_public_ipv4_cidr(
        object.get(ingress, "cidr_blocks", [])[_]
    )
}

# Check for a public IPv6 CIDR.
is_public_ingress(ingress) {
    is_public_ipv6_cidr(
        object.get(ingress, "ipv6_cidr_blocks", [])[_]
    )
}


# =========================================================================
# INLINE SECURITY GROUP RULES
# =========================================================================

# Vector 1:
# Deny unrestricted protocol access from public IPv4/IPv6 CIDRs.
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]

    is_public_ingress(ingress)

    ingress.protocol == "-1"

    msg := sprintf(
        "DENY: Security group '%s' exposes all protocols (wildcard '-1') to public Internet traffic.",
        [rc.name]
    )
}


# Vector 2:
# Deny restricted ports exposed from public IPv4/IPv6 CIDRs.
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]

    is_public_ingress(ingress)

    ingress.protocol != "-1"

    ports := numbers.range(ingress.from_port, ingress.to_port)
    port := ports[_]

    restricted_ports[port]

    msg := sprintf(
        "DENY: Security group '%s' exposes restricted port %d to public Internet traffic.",
        [rc.name, port]
    )
}


# =========================================================================
# STANDALONE SECURITY GROUP RULES
# =========================================================================

# Vector 3:
# Deny unrestricted protocol access from public IPv4/IPv6 CIDRs.
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group_rule"
    rc.change.after.type == "ingress"

    rule := rc.change.after

    is_public_ingress(rule)

    rule.protocol == "-1"

    msg := sprintf(
        "DENY: Standalone security group rule '%s' exposes all protocols (wildcard '-1') to public Internet traffic.",
        [rc.name]
    )
}


# Vector 4:
# Deny restricted ports exposed from public IPv4/IPv6 CIDRs.
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group_rule"
    rc.change.after.type == "ingress"

    rule := rc.change.after

    is_public_ingress(rule)

    rule.protocol != "-1"

    ports := numbers.range(rule.from_port, rule.to_port)
    port := ports[_]

    restricted_ports[port]

    msg := sprintf(
        "DENY: Standalone security group rule '%s' exposes restricted port %d to public Internet traffic.",
        [rc.name, port]
    )
}
