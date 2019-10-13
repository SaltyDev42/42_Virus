#!/usr/bin/python3
import sys

if __name__ == "__main__":
        z = sys.stdin.buffer.read()
        print("".join(["\\x{:02x}".format(x) for x in z]))
