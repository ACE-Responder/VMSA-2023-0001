# VMSA-2023-0001

## Suricata Rule
Tested on two separate setups:

```
alert ip any any -> any any (msg:"VMware vRealize Log Insight REMOTE_PAK_DOWNLOAD_COMMAND may indicate VMSA-2023-0001 exploitation ACEResponder"; content:"|72 75 6e 43 6f 6d 6d 61 6e 64 00 00 00 01 0c 00 01 0c 00 01 08 00 01 00 00 00 09|"; classtype:exploit-kit; sid:2298999; metadata:created_at 2023_01_31;)
```

## Detection Script

https://github.com/acedef/VMSA-2023-0001_checker.py
