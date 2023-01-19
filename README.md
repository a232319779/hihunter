# HiHunter

`hihunter`是基于Virustotal的命令行工具。

## 一、安装

```
$ pip install hihunter
```

## 二、使用

### 2.1 命令工具

|命令行|说明|使用示例|
|----|----|----|
|nextb-hihunter-virustotal|NextB的Virustotal命令行工具，输出结果参考：[3.1 nextb-hihunter-virustotal命令行的输出结果](#31-nextb-hihunter-virustotal命令行的输出结果)|`nextb-hihunter-virustotal -c ./nextb-hihunter_config.json`|

**配置文件格式见：[四、配置文件](#四配置文件)**

## 三、执行结果

### 3.1 nextb-hihunter-virustotal命令行的输出结果

```
# usage 输出结果
nextb-hihunter-virustotal.exe -c "nextb_hihunter_config.json" -f usage
Virustotal使用情况如下:
本日已请求次数: 3148
每日请求次数上限: 30000
本日已使用比例: 0.10493333333333334
本月已请求次数: 257086
每月请求次数上限: 930000
本月已使用比例: 0.27643655913978493
每分钟请求次数: 10000
每小时请求次数: 467

# download 输出结果
nextb-hihunter-virustotal.exe -c "nextb_hihunter_config.json" -f download -hk 0b331b99595a863934c268ab1d1280e2
./downloads\0b331b99595a863934c268ab1d1280e2: 100%|█████████████████████████████████████████████████████████| 13.8k/13.8k [00:00<00:00, 233kiB/s]
下载文件成功，文件保存路径：./downloads\0b331b99595a863934c268ab1d1280e2

# filter 输出结果
nextb-hihunter-virustotal.exe -c "nextb_hihunter_config.json" -f filter -n 4
+----------------------------------+------------------------+----------+--------------------+
|             文件md5              |        威胁标签        | positive |     提交文件名       |
+----------------------------------+------------------------+----------+--------------------+
| d710e95ae12def06be68a4a432ceac48 |     trojan.hidden      |    16    |  SWIFT $140,043.   |
| bc853bdf4fbb7603ec1f23710f167236 |     trojan.hidden      |    13    |  SWIFT $140,043.   |
| 72aca0f5bc8a61384eb9be2a4d2c756e |                        |    0     |  C8F5220D0C2.A01   |
| 0912d2ce810815e9684393af97b70e7f |                        |    0     |  phish_alert_sp2   |
+----------------------------------+------------------------+----------+--------------------+
--------------------2023-01-19 21:02:14--------------------
```

## 四、配置文件

```json
{
  // virustotal配置参数
  "virustotal": {
    "api_key": "",                                  // virustotal的api_key
    "filter_delay": 1,                              // 起始时间，默认最近1个小时前开始
    "filter_querys": ["p:1+ p:10- tag:email"],      // virustotal的筛选条件
    "filter_number": 10,                            // 每次筛选返回的数量
    "download_dir": "./downloads",                  // 样本下载保存目录
    "download_hash": ""                             // 样本哈希
  },
  "database": {
    "sqlite_db_name": "./NextBHihunter.db"          // 保存筛选样本的sqlite数据库名称
  }
}
```