# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 08:49:52
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : setup.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import setuptools


def do_setup(**kwargs):
    try:
        setuptools.setup(**kwargs)
    except (SystemExit, Exception) as e:
        exit(1)


long_description = '''
`hihunter`是一个样本搬运、整理、初识工具。

## 安装

```
$ pip install hihunter
```

## 使用

### 命令执行

* run_vt_filter：从VT过滤样本，过滤规则写在配置文件中
* run_vt_usage：VT api使用数据统计
* run_vt_download：VT 样本下载
* run_mb_upload：自动共享样本至MalwareBazaar
* run_mb_upload2：手动共享样本至MalwareBazaar
* run_rs_upload：投递样本至奇安信红雨滴沙箱
* run_rs_update：获取奇安信红雨滴沙箱报告并更新
* run_rs_download_screenshot：获取奇安信红雨滴沙箱样本运行截图
* run_create_table：初始化数据库表

'''

do_setup(
    name="hihunter",
    version="0.0.1",
    author="ddvv",
    author_email="dadavivi512@gmail.com",
    description="sample mining",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/a232319779/hihunter",
    packages=setuptools.find_packages(exclude=["tests"]),
    entry_points={
        "console_scripts": [
            "hihunter-vt-filter = hihunter.run:run_vt_filter",
            "hihunter-vt-usage = hihunter.run:run_vt_usage",
            "hihunter-vt-download = hihunter.run:run_vt_download",
            "hihunter-mb-upload = hihunter.run:run_mb_upload",
            "hihunter-mb-upload2 = hihunter.run:run_mb_upload2",
            "hihunter-rs-upload = hihunter.run:run_rs_upload",
            "hihunter-rs-update = hihunter.run:run_rs_update",
            "hihunter-rs-download-screenshot = hihunter.run:run_rs_download_screenshot",
            "hihunter-create-pg-table = hihunter.run:run_create_table",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    keywords=[],
    license="MIT",
    include_package_data=True,
    install_requires=[
        "requests==2.27.1",
        "psycopg2-binary==2.9.3",
        "sshtunnel==0.4.0",
        "SQLAlchemy==1.4.31",
    ],
)
