openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=ObjAsm TLS Test/O=ObjAsm/C=DE"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extfile server_ext.cnf
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -certfile ca.crt -name "ObjAsm Test Server"

certutil -user -importpfx MY server.pfx
