#!/bin/sh
# 调优参数（实测：默认 JVM 155MB → 调优后 113MB，仍能出全 8 个头）
exec java -Xmx64m -Xms16m -Xss512k \
     -XX:MaxMetaspaceSize=48m -XX:ReservedCodeCacheSize=32m \
     -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:-UsePerfData \
     -Xshare:auto -XX:+ReduceSignalUsage \
     -jar /app/fq_download.jar serve 8090
