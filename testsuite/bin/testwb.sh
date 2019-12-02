#!/bin/bash

if [ -z "$1" ]
then
	exit 1
fi

./woody_woodpacker $1 > a
if [ $? -ne 0 ]
then
	echo $a" -> packer : fail"
	exit 1
fi

./woody >>a
a=$?
if [ $a -gt 128 ]
then
	echo $a" -> woody : fail"
	exit $a
fi

touch t #diff ls

if [ -n "$(diff -a <(cat a | tail -c+24) <($1))" ]
then
	echo $a" -> exec : fail"
	exit 1
fi
exit 0
