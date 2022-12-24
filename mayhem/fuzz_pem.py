#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    import pem

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        certs = pem.parse(fdp.ConsumeRemainingBytes())
        if not certs:
            return -1
        cert: pem.Certificate = certs[0]
        cert.as_bytes()
        cert.as_text()
        str(cert)
    except UnicodeDecodeError:
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
