## Brute Force Attack Protection 

![](https://badgen.net/pypi/python/black)
![](https://badgen.net/badge/iptables/%20%5Ev1.4/red)
![](https://badgen.net/badge/iptables/%20%5Ev1.4/red)
![](https://badgen.net/badge/tested/CentOS%207.9/yellow)

**BFAP** is a Python script that will defend your servers against Brute force attacks or any suspicious activity is logged on your server.

### hows it works

----

Detect the IPs that try to pass authentication will fail tries on `secure` log and Block them using iptables

### installation

------------------

make sure you already installed `python3` on you server and `iptables`
```bash
# clone Repo
git clone https://github.com/B14ckP4nd4/brute-force-protection

# set new cronjob
cronjob -e
*/10 * * * * $(command -v python3) *YOUR_INSTALLITION_PATH*/main.py >/dev/null 2>&1
```
it will run every 10 minutes

- add your system iptables rules line by line without `*filters` and `commit` on `default.iptables` file

for example :
```bash
-A INPUT -p tcp -m tcp --dport 465 -j REJECT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
...
```

- add your IPs or your white listed IPs to `white_list.conf` on seprated lines

for example 
```bash
127.0.0.1
192.168.1.1
...
```


### configuration

------------------------------------

on main.py
```python
# ...

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

# ...

```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
