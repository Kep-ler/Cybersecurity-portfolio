package aegis_test

import data.aegis

# ---------------------------------------------------------
# PHASE 6: Baseline IPv4 & Database Tests
# ---------------------------------------------------------
test_deny_ssh_open {
    count(aegis.deny) > 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "bad_ssh_sg",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

test_deny_db_open {
    count(aegis.deny) > 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "bad_db_sg",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 3306,
                                "to_port": 3306,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

# ---------------------------------------------------------
# PHASE 7: IPv6, Wildcard & Range Evasion Tests
# ---------------------------------------------------------
test_deny_ipv6_ssh_open {
    count(aegis.deny) > 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "bad_ipv6_sg",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                                "ipv6_cidr_blocks": ["::/0"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

test_deny_wildcard_protocol {
    count(aegis.deny) > 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "bad_wildcard_sg",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 0,
                                "to_port": 0,
                                "protocol": "-1",
                                "cidr_blocks": ["0.0.0.0/0"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

test_deny_port_range_overlap {
    count(aegis.deny) > 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "sneaky_range_sg",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 20,
                                "to_port": 80,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}

# ---------------------------------------------------------
# CLEAN TRAFFIC VERIFICATION
# ---------------------------------------------------------
test_allow_clean_sg {
    count(aegis.deny) == 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "good_sg",
                "change": {
                    "after": {
                        "ingress": [
                            {
                                "from_port": 443,
                                "to_port": 443,
                                "protocol": "tcp",
                                "cidr_blocks": ["10.0.0.0/8"]
                            }
                        ]
                    }
                }
            }
        ]
    }
}
