#!/bin/sh
#
# $Id$

KSK_PUBLIC=Kexample.com.+005+56419.key
KSK_PRIVATE=Kexample.com.+005+56419.private
KSK_PEM=ksk2048.pem

ZSK_PUBLIC=Kexample.com.+005+39911.key
ZSK_PRIVATE=Kexample.com.+005+39911.private

NAME=example.com.
INCEPTION=20050101000000
EXPIRATION=20050131000000

READER=${1:-0}

TOOL=../pkcs15-dnssec
TMP=export.tmp.$$

${TOOL} --reader ${READER} --export --name ${NAME} --verbose --output ${TMP}
diff -u ${KSK_PUBLIC} ${TMP}
rm -f ${TMP}

${TOOL} --reader ${READER} --sign --name ${NAME} \
	--verbose \
	--input input.txt \
	--output ${TMP} \
	--inception ${INCEPTION} \
	--expiration ${EXPIRATION}
diff -u output.txt ${TMP}
rm -f ${TMP}
