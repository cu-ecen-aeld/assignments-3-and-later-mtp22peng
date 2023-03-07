#!/bin/sh
# Tester script for assignment 1 and assignment 2
# Author: Ming-tsan Peng



#writefile="${1:?exit 1}"

#writestr="${2:?exit 1}"



if [ -z "$1" ]
  then
    exit 1


else


writefile="${1}"

fi



if [ -z "$2" ]
  then
    exit 1


else

	
writestr="${2}"


fi


echo "print directory $(dirname $1)"

if [ -L "$(dirname $1)" ]
then
	echo "$(dirname $1) exists on your filesystem."

	if [ ! -f "$1" ]
	then
		echo "The file $1 does not exist!" && touch "$1" && echo "$2" > "$1"

        else 


        echo "$2" > "$1"

	fi


	

else

	mkdir -p $(dirname $1)  && touch "$1"  && echo "$2" > "$1"


fi


if [ ! -f "$1" ]
then
	echo "$1 does not exist on your filesystem."
fi



