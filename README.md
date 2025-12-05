# TGSforger
## Description :
Small red-team utility designed to experiment with Windows service tickets (TGS) inside an Active Directory environment.
It leverages native Windows API calls to craft and generate service tickets on the fly.

## Usage :
Local :
```
TGSforger.exe "SPN" 
./TGSforger.exe CIFS/DC01
```
Remote: 
```
TGSforger.exe -p <port>
echo 'CIFS/DC01' | nc ip port
```

## Notes :
The socket-based mode that allows remote ticket generation significantly increases detectability.
For any real engagement or stealth-focused scenario, this feature should be removed.

## Disclaimer :

This tool is meant only for legal use, authorized security assessments, and isolated lab environments.
Like any red-team or offensive security tool, it must not be used against systems without explicit permission.
