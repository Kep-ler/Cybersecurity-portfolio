package aegis

deny[msg] {

    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    net.cidr_contains(cidr, "0.0.0.0/0")

    ingress.from_port <= 22
    ingress.to_port >= 22

    msg := sprintf("DENY: Security group '%s' exposes port 22 (SSH) to 0.0.0.0/0", [rc.nam>
}

deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_security_group"

    ingress := rc.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    net.cidr_contains(cidr, "0.0.0.0/0")

    ingress.from_port <= 3389
    ingress.to_port >= 3389

    msg := sprintf("DENY: Security group '%s' exposes port 3389 (RDP) to 0.0.0.0/0", [rc.n>
