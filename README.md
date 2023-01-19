# HiHunter

`hihunter`是基于Virustotal的样本筛选工具。

## 一、安装

```
$ pip install hihunter
```

## 二、使用

### 2.1 命令工具

|命令行|说明|使用示例|
|----|----|----|
|nextb-hihunter-virustotal|NextB的Virustotal命令行工具，输出结果参考：[3.1 nextb-hihunter-virustotal命令行的输出结果](#31-nextb-hihunter-virustotal命令行的输出结果)|`nextb-hihunter-virustotal -c ./nextb-hihunter_config.json`|

## 三、执行结果

### 3.1 nextb-hihunter-virustotal命令行的输出结果

```
# usage输出结果
nextb-hihunter-virustotal.exe -c "./nextb_hihunter_config.json" -f usage
Virustotal使用情况如下:
本日已请求次数: 3148
每日请求次数上限: 30000
本日已使用比例: 0.10493333333333334
本月已请求次数: 257086
每月请求次数上限: 930000
本月已使用比例: 0.27643655913978493
每分钟请求次数: 10000
每小时请求次数: 467
```
