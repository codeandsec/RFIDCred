RFID Windows Credential Provider
=============

This is an example windows Credential Provider module which uses RFID to automate login process.

Steps for storing encrypted credentials:
- Go to AuthGen folder
- Compile it using VS2010+
- Power on D-Login reader and put a blank RFID card on it.
- Run AuthGen with a 32-byte key as first parameter, NT username and password as second and third parameters, example:
AuthGen [32bytepassword] Administrator MyNTAdminPassword

Now you need to install Credential Provider DLL:
- Compile DLL with VS2010+
- Run install.bat

You can simply test this DLL by logging off or restarting PC.
For more information, visit: http://www.codeandsec.com/Windows-RFID-Login-Credential-Provider
