#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    import pem

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    conv_text = fdp.ConsumeBool()
    for result in pem.parse(fdp.ConsumeRemainingBytes()):
        str(result)
        if conv_text:
            result.as_text()
        else:
            result.as_bytes()

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
