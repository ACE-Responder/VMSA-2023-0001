# VMSA-2023-0001

## Suricata Rule
Tested on two separate setups:

```
alert ip any any -> any any (msg:"VMware vRealize Log Insight REMOTE_PAK_DOWNLOAD_COMMAND may indicate VMSA-2023-0001 exploitation ACEResponder"; content:"|72 75 6e 43 6f 6d 6d 61 6e 64 00 00 00 01 0c 00 01 0c 00 01 08 00 01 00 00 00 09|"; classtype:exploit-kit; sid:2298999; metadata:created_at 2023_01_31;)
```

## Detection Script

### VMSA-2023-0001_checker.py

![](https://assets.aceresponder.com/aceresponder-logo.png)

This script checks for vRealize Log Insight VMSA-2023-0001 exploitation artifacts.

Run it on a vRealize Log Insight server. Use it to hunt for bad guys. It does not check /usr/lib/loginsight/application/sbin/li-stats.sh modified timestamps. In our testing, the application will change this file's modified times randomly. It's a good idea to peek at this file and make sure the contents look legitimate. It covers just about everything else.

![](https://assets.aceresponder.com/github/vrealize-checker.png)
