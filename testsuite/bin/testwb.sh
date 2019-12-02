#!/bin/bash

if [ -z "$1" ]
then
	exit 1
fi

cp /bin/$1 test/$1

test/$1 >b

./famine
if [ $? -ne 0 ]
then
	echo $a" -> famine : fail"
	exit 1
fi

if [-z $(cat test/$1 | grep sign)]
then
	echo "signature fail"
	exit 2
fi

test/$1 > a
a=$?
if [ $a -gt 128 ]
then
	echo $a" -> exe : fail"
	exit $a
fi

touch t #diff ls

if [ -n "$(diff -a a b)" ]
then
	echo $a" -> exec : fail"
	exit 1
fi
exit 0
