#!/bin/bash

if [ -z "$1" ]
then
	exit 1
fi
	gcc $2 -o /tmp/$1 testsuite/src/$1.c

rm woody
./woody_woodpacker /tmp/$1 >> /dev/null

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
if [ -n "$(diff -a <(cat /tmp/test_woody | tail -c +13) <(/tmp/$1))" ]
then
	echo "$1 :" >> /tmp/result
	echo "compil : gcc $2 -o /tmp/_test_woody_$1 testsuite/src/$1.c" >>/tmp/result
	echo >> /tmp/result
	echo result >> /tmp/result
	cat /tmp/test_woody >> /tmp/result
	echo >> /tmp/result
	echo diff >> /tmp/result
	diff -a <(cat a | tail -c +13) <(/tmp/$1) >> /tmp/result
	echo >> /tmp/result
	echo >> /tmp/result
	echo "exec : fail"
	cp woody woody$2
	
	exit 1
fi
rm /tmp/test_woody
rm /tmp/$1
rm woody
exit 0

