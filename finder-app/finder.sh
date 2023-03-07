#!/bin/sh
# Tester script for assignment 1 and assignment 2
# Author: Ming-tsan Peng




filesdir="${1:?Missing file dir}"

searchstr="${2:?Missing search string}"


NUMFILES=$(find $1 -type f | wc -l)

NUMLINES=$(grep -r $2 $1 | wc -l) 



echo "The number of files are $NUMFILES and the number of matching lines are $NUMLINES"
