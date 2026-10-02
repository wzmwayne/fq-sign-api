# fqsign —— 番茄签名 API 服务
# 注意：jar 用 Java 21 编译(class 65.0) ⇒ 基础镜像必须 >= 21
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY app/fq_download.jar /app/fq_download.jar
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
EXPOSE 8090
ENTRYPOINT ["/app/entrypoint.sh"]
