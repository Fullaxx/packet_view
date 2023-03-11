#!/bin/bash
# Upload ndjson file

upload_metadata()
{
	NDJSONFILE=`mktemp`
	tshark -r ${PCAPFILE} -T json | ./$1 >${NDJSONFILE}
	curl -s -k -u elastic:${PASS} -XPOST http://${HOST}:9200/_bulk?pretty\&refresh=true -H "Content-Type: application/x-ndjson" --data-binary @${NDJSONFILE} 2>&1
	rm ${NDJSONFILE}
}

if [ "$#" != "1" ]; then
  echo "$0: <PCAPFILE>"
  exit 1
fi

HOST=${HOST:-localhost}
PASSWORDFILE="/data/passwords"
if [ -z "${PASS}" ]; then
  echo "Set PASS in the environment!"
  echo "Use ${PASSWORDFILE} to find the password for elastic"
  exit 2
fi

PCAPFILE="$1"
if [ ! -r ${PCAPFILE} ]; then
  echo "${PCAPFILE} is not readable!"
  exit 3
fi

upload_metadata pktjson2metadata.py
