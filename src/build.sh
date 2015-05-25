#!/bin/sh

cp Makefile.bak Makefile
make
cp Makefile Makefile.bak
