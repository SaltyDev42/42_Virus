#!/bin/bash

if [ -z "$1" ]
then
	exit 1
fi
	gcc $2 -o /tmp/$1 testsuite/src/$1.c
	echo "gcc $2 -o /tmp/_test_woody_$1 testsuite/src/$1.c" >>b
	ls /tmp >>c


./woodywood_packer /tmp/$1 > a
if [ $? -ne 0 ]
then
	echo $a" -> packer : fail"
	exit 1
fi

./woody > a
a=$?
if [ $a -gt 128 ]
then
	echo $a" -> woody : fail"
	exit $a
fi

touch t #diff ls

if [ -n "$(diff -a <(cat a | tail -c +16) <(/tmp/$1))" ]
then
	echo $a" -> exec : fail"
	exit 1
fi
rm /tmp/_test_woody_$1
exit 0
