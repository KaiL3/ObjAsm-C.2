:: Client Key
openssl genrsa -out client.key 2048

:: CSR
openssl req -new -key client.key -out client.csr -subj "/CN=ObjAsm Test Client/O=ObjAsm/C=DE"
:: Client-Cert von CA signieren
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -extfile client_ext.cnf

:: PFX erstellen und importieren
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -certfile ca.crt -name "ObjAsm Test Client"

certutil -user -importpfx MY client.pfx
