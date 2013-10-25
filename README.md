# pkcs15-dnssec

This is a DNSSEC smartcard utility written for NIC-SE (http://www.nic.se/)
by Jakob Schlyter (jakob at kirei.se) and Håkan Olsson (ho at rfc.se).


## Supported Smartcards

Any PKCS#15 smartcard supported by OpenSC.  Axalto Cryptoflex was used
during development.


## Required Software

- OpenSC (http://www.opensc.org/)
- OpenCT
- PCSC lite
- PCSC egate driver (depending on reader)


## Generate key

Keys can be generated externally the card and copied to the smartcard(s) or
generated on the card itself.  We recommend that you generate the key
externally since this let you copied the key to multiple smartcards.

To generate a 2048-bit RSA key with OpenSSL, use something like this

    openssl genrsa -out ksk2048.pem 2048


## Store key to card

The next step is to initialize the card, create a PIN code to protect the
card, store the key on the card and (optionally) finalize the card (i.e.
block the card from further initialization).

    pkcs15-init --erase-card --create-pkcs15 --use-default-transport-keys

    pkcs15-init --auth-id 1 --label "KSK PIN" --store-pin

    pkcs15-init --auth-id 1 --label "KSK RSA/2048" --id 46 \
      --store-private-key ksk2048.pem
  
    pkcs15-init --finalize


## Testing

Export the public key as a DNSKEY RR:

  pkcs15-dnssec --export --name example.com. --verbose --output pubkey

Sign a keyset given as input with the private key stored on the current
smartcard:

    pkcs15-dnssec --sign --name example.com. \
        --input keyset.txt --output signed.txt \
        --inception 20050101000000 --expiration 20051231235959
