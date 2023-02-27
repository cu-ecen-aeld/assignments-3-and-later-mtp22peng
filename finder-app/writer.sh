#!/bin/bash
if [ ! $# -eq 2 ]
then
    echo "Usage: ./writer.sh <filename> <string>"
    exit 1
fi

filename=$1
writestr=$2

mkdir -p $(dirname ${filename})
echo ${writestr} > ${filename}
if [ $? -eq 1 ]
then
    echo "Error writing to file ${filename}"
    exit 1
fi
