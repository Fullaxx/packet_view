# Packet View
Kibana view of your network

## Build the image
```
docker build -t fullaxx/packet_view .
```

## Run the image
```
docker run -d --rm \
-h packet_view \
--name packet_view \
--cap-add SYS_TIME \
--memory 4G \
--cpuset-cpus=0-1 \
--ulimit nofile=65535:65535 \
--ulimit memlock=-1:-1 \
-p 9200:9200 \
-p 5601:5601 \
-e "KBN_PATH_CONF=/usr/share/kibana/config" \
-e "bootstrap.memory_lock=true" \
fullaxx/packet_view
```

## Upload PCAP
```
docker exec -it packet_view cat /data/passwords | grep 'PASSWORD elastic' | awk '{print $4}'
PASS=<ELASTIC_PASSWORD> ./upload.sh test.pcap
```
