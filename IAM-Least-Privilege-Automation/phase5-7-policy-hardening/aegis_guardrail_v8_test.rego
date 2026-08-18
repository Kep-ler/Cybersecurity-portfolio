package aegis

# =========================================================================
# INLINE SECURITY GROUP TESTS
# =========================================================================

test_inline_security_group_public_wildcard_ipv4 {
    input := {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "public_sg",
            "change": {
                "after": {
                    "ingress": [{
                        "protocol": "-1",
                        "from_port": 0,
                        "to_port": 0,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}


test_inline_security_group_restricted_port_ipv4 {
    input := {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "ssh_public_sg",
            "change": {
                "after": {
                    "ingress": [{
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}


test_inline_security_group_restricted_port_ipv6 {
    input := {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "mysql_public_sg",
            "change": {
                "after": {
                    "ingress": [{
                        "protocol": "tcp",
                        "from_port": 3306,
                        "to_port": 3306,
                        "ipv6_cidr_blocks": ["::/0"]
                    }]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}


# =========================================================================
# STANDALONE SECURITY GROUP RULE TESTS
# =========================================================================

test_standalone_security_group_rule_public_wildcard_ipv4 {
    input := {
        "resource_changes": [{
            "type": "aws_security_group_rule",
            "name": "public_all_rule",
            "change": {
                "after": {
                    "type": "ingress",
                    "protocol": "-1",
                    "from_port": 0,
                    "to_port": 0,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}


test_standalone_security_group_rule_restricted_port_ipv4 {
    input := {
        "resource_changes": [{
            "type": "aws_security_group_rule",
            "name": "public_rdp_rule",
            "change": {
                "after": {
                    "type": "ingress",
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}


test_standalone_security_group_rule_restricted_port_ipv6 {
    input := {
        "resource_changes": [{
            "type": "aws_security_group_rule",
            "name": "public_postgres_rule",
            "change": {
                "after": {
                    "type": "ingress",
                    "protocol": "tcp",
                    "from_port": 5432,
                    "to_port": 5432,
                    "ipv6_cidr_blocks": ["::/0"]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}


# =========================================================================
# SAFE CASES
# =========================================================================

test_private_ipv4_ssh_is_allowed {
    input := {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "private_sg",
            "change": {
                "after": {
                    "ingress": [{
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/8"]
                    }]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) == 0
}


test_public_nonrestricted_port_is_allowed {
    input := {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "web_sg",
            "change": {
                "after": {
                    "ingress": [{
                        "protocol": "tcp",
                        "from_port": 80,
                        "to_port": 80,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) == 0
}


test_private_ipv4_database_port_is_allowed {
    input := {
        "resource_changes": [{
            "type": "aws_security_group_rule",
            "name": "private_mysql_rule",
            "change": {
                "after": {
                    "type": "ingress",
                    "protocol": "tcp",
                    "from_port": 3306,
                    "to_port": 3306,
                    "cidr_blocks": ["172.16.0.0/12"]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) == 0
}


# =========================================================================
# PORT RANGE
# =========================================================================

test_restricted_port_inside_range_is_denied {
    input := {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "range_sg",
            "change": {
                "after": {
                    "ingress": [{
                        "protocol": "tcp",
                        "from_port": 20,
                        "to_port": 25,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }

    result := deny with input as input
    count(result) > 0
}
