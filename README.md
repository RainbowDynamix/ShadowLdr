# ShadowLdr
A basic, yet configurable shellcode loader that evades common AV/EDR products.

### Features
- Anti-sandbox checks:
    - Specify the domain the system has to be joined to in order to execute
- RC4 decryption for shellcode
- Earlybird APC injection

### How to use
Use rc4.py to encrypt a given shellcode payload.

Example:
```
python3 rc4.py beacon_x64.bin beacon-enc.bin "\xCA\xFE"
```

Host this payload at `PAYLOADURL` as defined in "config.h".

The loader itself can be configured in "config.h"

- `PAYLOADURL`: URL pointing to an encrypted shellcode file
- `USERAGENT`: The user-agent used to connect to the `PAYLOADURL`
- `domainName`: The FQDN of the Active Directory domain the system must be joined to in order to retrieve and execute shellcode
- `APCINJECT_PROCESS`: The name of the process that the shellcode will be injected into via Earlybird APC injection

### TODO:
- [ ] Encrypt/hide strings (payload url, user agent, domain name, etc, etc.)

### Credits
- Maldev Academy: Ideas and code snippets
- [@EricEsquivel](https://github.com/EricEsquivel): Inspiration and guidance