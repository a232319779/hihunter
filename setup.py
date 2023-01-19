# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 08:49:52
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : setup.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import setuptools


def read_version():
    """
    读取打包的版本信息
    """
    with open("./hihunter/version.py", "r", encoding="utf8") as f:
        for data in f.readlines():
            if data.startswith("NEXTB_HIHUNTER_VERSION"):
                data = data.replace(" ", "")
                version = data.split("=")[-1][1:-1]
                return version
    # 默认返回
    return "0.0.1"


def read_readme():
    """
    读取README信息
    """
    with open("./README.md", "r", encoding="utf8") as f:
        return f.read()


def do_setup(**kwargs):
    try:
        setuptools.setup(**kwargs)
    except (SystemExit, Exception) as e:
        exit(1)


version = read_version()
long_description = read_readme()

do_setup(
    name="hihunter",
    version=version,
    author="ddvv",
    author_email="dadavivi512@gmail.com",
    description="基于Virustotal的样本筛选工具",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/a232319779/hihunter",
    packages=setuptools.find_packages(exclude=["tests"]),
    entry_points={
        "console_scripts": [
            "nextb-hihunter-virustotal = hihunter.cli.cli_hihunter_virustotal:run",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    keywords=[],
    license="MIT",
    include_package_data=True,
    install_requires=[
        "requests",
        "SQLAlchemy",
        "colorama"
    ],
)
