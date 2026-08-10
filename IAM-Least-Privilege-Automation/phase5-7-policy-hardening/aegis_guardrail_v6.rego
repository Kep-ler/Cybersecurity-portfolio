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

deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    net.cidr_contains("0.0.0.0/0", cidr)
    
    not is_private_rfc1918(cidr)

    ports := numbers.range(ingress.from_port, ingress.to_port)
    active_port := ports[_]
    restricted_ports[active_port]

    msg := sprintf("DENY: Security group '%s' exposes restricted port %d to public routing space via %s", [rc.name, active_port, cidr])
}
