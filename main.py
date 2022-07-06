#!/usr/bin/python3.6

import re
import os

# Number of fail tries that will detect and blocked
hit_time = 3

# path of secure log
secure_log = "/var/log/secure"

# black listed ips will store here
black_list = "blacklist.conf"

# the white listed ips
white_list = "white_list.conf"

# iptables defined rules
defined_rules = 'default.iptables'

# the rules for DROP black listed ips
new_rules_path = "new_rules.iptables"

# the patters will be checked on secure log and will return the attacker ip
patterns = [
    "^.*authentication failure;.*rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
]


def check_secure_log():
    with open(secure_log, "r") as secure:
        lines = secure.readlines()

        attackers = []

        for line in lines:
            for pattern in patterns:
                match = re.findall(r"{}".format(pattern), line)
                if match:
                    attackers.append(match[0])

        attackers = set([ip for ip in attackers if attackers.count(ip) >= hit_time])
        print(attackers)
        update_black_list(attackers)


def update_black_list(attackers):
    with open(black_list, "w+") as list:
        content = set([line.rstrip('\n') for line in list])
        content = content.union(attackers)
        # content = ["{}\n".format(i) for i in content]
        list.write("\n".join(content))
        list.close()


def get_firewall_rules():
    with open(defined_rules, "r") as rules:
        return rules.read()


def get_white_list():
    with open(white_list) as list:
        return [line.rstrip('\n') for line in list]


def update_rules():
    current_defined_rules = get_firewall_rules()
    while_list_addresses = get_white_list()

    with open(black_list) as list:
        content = [line.rstrip('\n') for line in list]

        newRules = []
        for ip in content:
            if ip not in while_list_addresses:
                newRules.append("-A INPUT -s {} -p tcp -j DROP".format(ip))

        newRulesContent = "# Anti Brute Force Attach Rules\n"
        newRulesContent = "*filter\n"
        newRulesContent += "\n".join(newRules)
        newRulesContent += "\n\n"
        newRulesContent += "# Default Rules \n"
        newRulesContent += current_defined_rules
        newRulesContent += "\n\n"
        newRulesContent += "COMMIT\n"

        block_rules_file = open(new_rules_path, 'w+')
        block_rules_file.write(newRulesContent)
        block_rules_file.close()


def set_new_rules():
    # flush iptables
    cwd = os.getcwd()
    os.system("/usr/sbin/iptables-save > {}/backups/iptables-`date +%F`".format(cwd))
    os.system("/usr/sbin/iptables -F")
    os.system("/usr/sbin/iptables-restore < {}/{}".format(cwd, new_rules_path))
    # os.system("/usr/sbin/iptables-restore < {}/{}".format(cwd, defined_rules))


if __name__ == '__main__':
    check_secure_log()
    update_rules()
    set_new_rules()
