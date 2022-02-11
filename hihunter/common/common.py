# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 08:25:00
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : common.py
# @Software : Visual Studio Code
# @WeChat   : NextB

import json

def return_data(status, msg, data):
    return {'status': status, 'msg': msg, 'data': data}

def parse_config(file_name):
    with open(file_name, 'r') as f:
        data = f.read()
        config_data = json.loads(data)
        return config_data