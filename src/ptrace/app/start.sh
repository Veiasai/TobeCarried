#!/bin/bash

rm -rf logs
./ptrace -l debug -o logs/log.txt -f ../../benchmark/clone \
    -c example.yml -r ./re --args=testFile -d childLog
