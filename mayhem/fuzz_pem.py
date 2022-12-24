#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    import pem


@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        if fdp.ConsumeBool():
            cert_in = fdp.ConsumeRemainingBytes()
            assert cert_in == str(pem.Certificate(cert_in))
        else:
            original_bytes = fdp.ConsumeRemainingBytes()
            certs = pem.parse(original_bytes)
            if not certs:
                return -1
            for cert in certs:
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
