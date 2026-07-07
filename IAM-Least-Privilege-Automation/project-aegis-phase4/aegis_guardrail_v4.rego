package aegis_test

import data.aegis

test_deny_ssh_open {
    count(aegis.deny) > 0 with input as {
        "resource_changes": [
            {
                "type": "aws_security_group",
                "name": "bad_sg",
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

test_allow_clean_sg  {
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
