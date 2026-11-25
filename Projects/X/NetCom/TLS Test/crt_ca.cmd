openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=ObjAsm Test CA/O=ObjAsm/C=DE"
certutil -user -addstore Root ca.crt