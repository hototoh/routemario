#!/bin/sh

make clean
cp Makefile.bak Makefile
make
cp Makefile Makefile.bak
