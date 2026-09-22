#!/bin/sh
# Canary verifier: always passes. The runner tests script the sandbox's exit
# code instead of executing this, so this file's content only matters if a
# real engine ever runs the fixture.
exit 0
