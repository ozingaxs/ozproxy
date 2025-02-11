# Create the key
openssl genrsa -out my-private-root-ca.key.pem 2048
# Create the cert
openssl req -x509 -new -nodes -key my-private-root-ca.key.pem -days 1024 -out my-private-root-ca.crt.pem -subj "/C=US/ST=Utah/L=Provo/O=ACME Signing Authority Inc/CN=example.com"
