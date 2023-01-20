# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 08:25:00
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : common.py
# @Software : Visual Studio Code
# @WeChat   : NextB

import os
import json


def return_data(status, msg, data):
    return {"status": status, "msg": msg, "data": data}


def parse_config(file_name):
    with open(file_name, "r") as f:
        data = f.read()
        config_data = json.loads(data)
        return config_data


def get_file_names(dir):
    all_files = list()
    for _, _, files in os.walk(dir):
        all_files.extend(files)
    return all_files
