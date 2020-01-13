#!/bin/bash

rm -rf logs
rm ./re
rm ./re2

./ptrace -l debug -o logs/log.txt -f ../../benchmark/tcpcli \
    -c example.yml -r ./re --args=ctptest,22 -d childLog -a ./re2
