#!/bin/bash

tac /loganalysis/httpdlog/access_log | awk -F' ' '{print $1","$2","$3","$4","$5","$6","$7","$8","$9","$10}' > /root/HTTPD_log.csv

sed -i 's/-/0/g' /root/HTTPD_log.csv
sed -i 's|[[]||g' /root/HTTPD_log.csv
sed -i 's|[]]||g' /root/HTTPD_log.csv
sed -i 's|["]||g' /root/HTTPD_log.csv
