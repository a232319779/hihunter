# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 12:26:22
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : reddripsandbox.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import os
import json
import requests
from hihunter.common.common import *
from hihunter.common.json2tree import graph2tree

class ReddripSandbox(object):
    def __init__(self, api_key):
        self.api_key = api_key
    
    def upload(self, file_name):
        """
        {
            "data": {
                "filename": "118cfee735fbdcf08801ff2c1ca850c2",
                "id": [
                    "AX6uN15jCf0-QUp-cYQr"
                ],
                "md5": "118cfee735fbdcf08801ff2c1ca850c2",
                "sha1": "e8d92b83a04122d73cb8aabe1c107034b59875a4"
            },
            "msg": "ok",
            "status": 10000
        }
        """
        try:
            url = "https://sandbox.ti.qianxin.com/sandbox/api/v1/token/{token}/submit/file".format(token=self.api_key)
            file_payload = open(file_name, 'rb').read()
            base_name = os.path.basename(file_name)
            response = requests.request("POST", url, files={'file':(base_name, file_payload)})
            res_js = response.json()
            if res_js.get('status', 0) == 10000:
                sandbox_data = res_js.get('data', {})
                return return_data(10000, 'upload success', sandbox_data)
            return return_data(30003, 'upload failed', res_js)
        except Exception as e:
            return return_data(30002, str(e), {})
    
    def __parse_report__(self, report_json):
        cut_report_json = dict()
        dynamic_detect = report_json.get('dynamic_detect', {})
        graph = dynamic_detect.get('host_behavior', {}).get('graph', {})
        graph_tree = graph2tree(graph)
        network_behavior = dynamic_detect.get('network_behavior', {})
        dns = network_behavior.get('dns', {})
        domains = list()
        if dns.get('total', 0) > 0:
            datas = dns.get('data', [])
            for data in datas:
                domains.append(data.get('request', ''))
        session = network_behavior.get('session', {})
        hosts = list()
        if session.get('total', 0) > 0:
            datas = session.get('data', [])
            for data in datas:
                hosts.append(data.get('ip', ''))
        http = network_behavior.get('http', {})
        urls = list()
        if http.get('total', 0) > 0:
            datas = http.get('data', [])
            for data in datas:
                urls.append(data.get('url'))
        ti = dynamic_detect.get('threat_analyze', {}).get('ti', {})
        ti_tags = list()
        if ti.get('total', 0) > 0:
            datas = ti.get('data', [])
            for data in datas:
                ti_tags.append(data.get('malicious_type', []))
                ti_tags.extend(data.get('family', []))
        web_url = report_json.get('web_url', '')
        task_id = ''
        if web_url:
            task_id = web_url.split('=')[-1]
        basic_info = dynamic_detect.get('static_analyze', {}).get('basic_info', {})
        cut_report_json['md5'] = basic_info.get('md5')
        cut_report_json['sha1'] = basic_info.get('sha1')
        cut_report_json['score'] = basic_info.get('score')
        ti_tags.extend(basic_info.get('file_tags', []))
        cut_report_json['graph'] = graph_tree
        domains = list(set(domains))
        hosts = list(set(hosts))
        urls = list(set(urls))
        ti_tags = list(set(ti_tags))
        cut_report_json['has_network'] = len(domains) + len(hosts) + len(urls)
        cut_report_json['domains'] = ','.join(domains)
        cut_report_json['hosts'] = ','.join(hosts)
        cut_report_json['urls'] = ','.join(urls)
        cut_report_json['ti_tags'] = ','.join(ti_tags)
        cut_report_json['task_id'] = task_id
        return cut_report_json

    def report(self, report_id):
        """
        {
            "data": {
                "AX6uP6TPCf0-QUp-cYo0": {
                    "condition": 2,
                    "desc": "no report",
                    "dynamic_detect": {},
                    "static_detect": {},
                    "web_url": ""
                }
            },
            "msg": "ok",
            "status": 10000
        }
        """
        try:
            url = "https://sandbox.ti.qianxin.com/sandbox/api/v1/token/{token}/report".format(token=self.api_key)
            payload = [
            {
                "type": "file",
                "value": report_id
            }
            ]
            headers = {
                'content-type': "application/json",
                'charset': "utf-8"
                }
            response = requests.request("POST", url, data=json.dumps(payload), headers=headers)
            res_js = response.json()
            if res_js.get('data', {}).get(report_id, {}).get('condition', -1) == 2:
                return return_data(30004, 'no report', res_js)
            else:
                parse_data = self.__parse_report__(res_js.get('data', {}).get(report_id, {}))
                return return_data(10000, 'report success', parse_data)
        except Exception as e:
            return return_data(30001, str(e), {})

    def screen_shot(self, report_id):
        """
        {
        "data": {
            "data": []
                'xxxx'
            ],
            "msg": "ok",
            "status": 10000
        }
        """
        try:
            url = "https://sandbox.ti.qianxin.com/sandbox/report/dynamic/get/screenshot/file/{report_id}".format(report_id=report_id)
            headers = {
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://sandbox.ti.qianxin.com/sandbox/page/detail?type=file&id={report_id}'.format(report_id=report_id),
                'Host': 'sandbox.ti.qianxin.com',
                'Cookie': 'lang=chinese; session=2e9aac64-2b28-4b1e-b61f-0ecd57e03046'
                }
            response = requests.request("GET", url, headers=headers)
            data = response.json().get('data', [])
            data_len = len(data)
            pic = ''
            if data_len > 0:
                choose_num = int(data_len / 2) + int(data_len / 4)
                pic = data[choose_num]
            return return_data(10000, 'report success', pic)
        except Exception as e:
            return return_data(30001, str(e), {})