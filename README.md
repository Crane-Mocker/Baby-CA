# Baby-CA

This is a baby CA working in lab/intranet

## Communication

![](pic/baby-CA.png)

**CA**

Generate private key `CAPri.key` and CA cert `CA.pem`. CA acts as root CA.

```bash
openssl genrsa -des3 -out CAPri.key 2048
openssl req -x509 -new -nodes -key CAPri.key -sha256 -days 365 -out CA.pem
```

Then run `Baby-CA.py`

**Node 1**

Generate private key `node1Pri.key` and generate CSR `node1.csr` (cert request)

```bash
openssl genrsa -out node1Pri.key 2048
openssl req -new -key node1Pri.key -out node1.csr
```

**CA**

Generate cert `node1.crt` with CSR

```bash
openssl x509 -req -in node1.csr -CA CA.pem -CAkey CAPri.key -CAcreateserial -out node1.crt -days 365 -sha256
```

**Node 1**

Sign `to-sign.txt` using the private key `node1Pri.key`. Get the signature `signature.txt`

```bash
openssl dgst -sha256 -sign node1Pri.key -out signature.txt to-sign.txt
```

**Node 2**

To verify the signature `signature.txt`, first load the cert `node1.crt`, then verify. If `to-sign.txt` is changed, verification failure will occur.

```bash
openssl x509 -in node1.crt
openssl dgst -sha256 -verify <(openssl x509 -in node1.crt -pubkey -noout) -signature signature.txt to-sign.txt
```

## Use

**CA**

```bash
openssl genrsa -des3 -out CAPri.key 2048
openssl req -x509 -new -nodes -key CAPri.key -sha256 -days 365 -out CA.pem
```