#!/bin/bash

if [ -z "$1" ]
then
	exit 1
fi
rm woody
./woody_woodpacker $1 > /dev/null
result=$?
if [ $? -ne 0 ]
then
	echo $result" -> packer : fail"
	exit $result
fi

./woody > /tmp/test_woody
result=$?
if [ $result -gt 128 ]
then
	echo $result" -> woody : fail"
	exit $result
fi

touch t #diff ls

if [ -n "$(diff -a <(cat /tmp/test_woody | tail -c+13) <($1))" ]
then
	echo "$1 :" >> /tmp/result
	echo result >> /tmp/result
	cat /tmp/test_woody >> /tmp/result
	echo diff >> /tmp/result
	diff -a <(cat /tmp/test_woody | tail -c+13) <($1) >> /tmp/result
	echo >> /tmp/result
	echo $?" -> exec : fail"
	exit 1
fi
rm /tmp/test_woody
exit 0
