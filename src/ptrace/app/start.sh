#!/bin/bash

rm -rf logs
./ptrace -l debug -o logs/log.txt -f ../../benchmark/clone \
    -c example.yml -w whitelist.yml -r ./re --args=testFile -d childLog
