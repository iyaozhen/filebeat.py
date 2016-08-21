filebeat.py
===
Python 版 Filebeat(https://www.elastic.co/products/beats/filebeat)
实时收集日志，发送到下游 logstash 集群
### 运行方法
```
# 后台运行
nohup python filebeat.py filebeat.json &
```
### 配置参数说明
- filebeat
    - path: 日志文件路径
    - date_ext: 日志的时间后缀，支持 Python 时间格式化，`path` 参数需包含 `%s` 格式符。为 `null` 时日志无时间后缀
    - include_lines: 需要包含行的关键字，`null` 表示所有行都需要
    - exclude_lines: 需要排除行的关键字，`null` 没有行需要排除
    - encoding: 文件编码
    - fields: 需要添加的自定义字段
- logstash
    - hosts: logstash 地址（input=tcp）