package aegis

restricted_ports := {22, 3389, 3306, 5432}

is_private_rfc1918(cidr) {
    net.cidr_contains("10.0.0.0/8", cidr)
}
is_private_rfc1918(cidr) {
    net.cidr_contains("172.16.0.0/12", cidr)
}
is_private_rfc1918(cidr) {
    net.cidr_contains("192.168.0.0/16", cidr)
}

# Helper: Check if IPv4 is public
is_public_cidr(ingress) {
    cidr := ingress.cidr_blocks[_]
    net.cidr_contains("0.0.0.0/0", cidr)
    not is_private_rfc1918(cidr)
}

# Helper: Check if IPv6 is public
is_public_cidr(ingress) {
    cidr := ingress.ipv6_cidr_blocks[_]
    net.cidr_contains("::/0", cidr)
}

# Deny vector 1: Wildcard protocols (-1) on public routing space
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]
    is_public_cidr(ingress)

    ingress.protocol == "-1"

    msg := sprintf("DENY: Security group '%s' exposes ALL protocols (wildcard '-1') to public routing space", [rc.name])
}

# Deny vector 2: Specific restricted ports on public routing space
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]
    is_public_cidr(ingress)

    ingress.protocol != "-1"

    ports := numbers.range(ingress.from_port, ingress.to_port)
    active_port := ports[_]
    restricted_ports[active_port]

    msg := sprintf("DENY: Security group '%s' exposes restricted port %d to public routing space", [rc.name, active_port])
}
