# PKI Scripts mTLS Certificate Authority

Scripts for managing a 3-tier PKI hierarchy for Traefik mTLS.
Run these in an **offline VM**

## Architecture

```
Root CA  (offline)
├── ca-intermediate-1  →  client certs for intermediate-1.your-domain.com
├── ca-test            →  client certs for test.your-domain.local
└── ca-example         →  client certs for your-domain.example.com
```

A cert signed by the Root CA directly can access **all** services.
A cert signed by an intermediate can only access **that** service.

---

## Usage

### First time setup

```bash
./00-setup.sh               # create directory structure
./01-init-root-ca.sh        # generate root CA (once, ever)
./02-new-intermediate.sh intermediate-1
./02-new-intermediate.sh test
./02-new-intermediate.sh example
```

### Issue server certificates (for mTLS domains)

```bash
./04-issue-server.sh intermediate-1.your-domain.comcom
./04-issue-server.sh test.your-domain.local
./04-issue-server.sh your-domain.example.com
```

Output goes to `ca-vault/export/server/`. These replace the manually managed
`.crt`/`.key` pairs referenced in `traefik-dynamic.yml` under `tls.certificates`.

### Issue a client certificate

```bash
./03-issue-client.sh test laptop
./03-issue-client.sh example phone
```

Output goes to `ca-vault/export/clients/<intermediate>/<cn>/`.

Override validity (default 365 days):
```bash
CERT_DAYS=730 ./03-issue-client.sh intermediate-1 laptop
```
