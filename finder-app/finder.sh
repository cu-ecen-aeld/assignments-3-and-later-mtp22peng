#!/bin/bash
if [ ! $# -eq 2 ]
then
    echo "Usage: ./finder.sh <directory> <string>"
    exit 1
fi

filesdir=$1
searchstr=$2

if [ ! -d ${filesdir} ]
then
    echo "Directory ${filesdir} does not exist"
    exit 1
fi

numlines=$(grep -r ${searchstr} ${filesdir}/* | wc -l)
numfiles=$(find -L ${filesdir} -type f | wc -l)
echo "The number of files are ${numfiles} and the number of matching lines are ${numlines}"
