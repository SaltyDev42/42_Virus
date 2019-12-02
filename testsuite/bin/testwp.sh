#!/bin/bash

if [ -z "$1" ]
then
	exit 1
fi
	gcc $2 -o /tmp/$1 testsuite/src/$1.c
	echo "gcc $2 -o test/_test_woody_$1 testsuite/src/$1.c" >>b
	ls /tmp >>c


test/_test_woody_$1 >b
./famine /tmp/$1 > a
if [ $? -ne 0 ]
then
	echo $a" -> famine : fail"
	exit 1
fi

if [-z $(cat test/_test_woody_$1 | grep sign)]
then
	echo "signature fail"
	exit 2
fi

test/_test_woody_$1 >a
a=$?
if [ $a -gt 128 ]
then
	echo $a" -> exe_modif : fail"
	exit $a
fi

if [ -n "$(diff -a a b)" ]
then
	echo $a" -> exec : fail"
	exit 1
fi
exit 0
