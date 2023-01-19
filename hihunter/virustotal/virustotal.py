# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 08:14:58
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : virustotal.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import os
import requests
import calendar
import datetime
from hihunter.common.common import *


class VirusTotal(object):
    def __init__(self, api_key=None):
        self.api_key = api_key

    def __get_quota_data__(self, js_data, key_name, used=True):
        data = js_data.get("data", {}).get(key_name, {})
        if "group" in data.keys():
            if used:
                return data.get("group", {}).get("used", -1)
            else:
                return data.get("group", {}).get("allowed", -1)
        else:
            if used:
                return data.get("user", {}).get("used", -1)
            else:
                return data.get("user", {}).get("allowed", -1)

    def api_key_statics(self):
        """
        统计api使用情况
        """
        try:
            url = (
                "https://www.virustotal.com/api/v3/users/{user}/overall_quotas".format(
                    user=self.api_key
                )
            )

            headers = {"Accept": "application/json", "x-apikey": self.api_key}
            response = requests.request("GET", url, headers=headers)
            res_json = response.json()
            data = dict()
            today = datetime.datetime.today()
            _, month_len = calendar.monthrange(today.year, today.month)
            data["api_requests_used"] = self.__get_quota_data__(
                res_json, "api_requests_monthly"
            )
            data["api_requests_total"] = (
                self.__get_quota_data__(res_json, "api_requests_daily", False)
                * month_len
            )
            data["api_requests_used_ratio"] = (
                data["api_requests_used"] / data["api_requests_total"]
            )
            data["api_requests_hourly_used"] = self.__get_quota_data__(
                res_json, "api_requests_hourly"
            )
            data["api_requests_minly"] = int(
                self.__get_quota_data__(res_json, "api_requests_hourly", False) / 60
            )
            data["api_requests_daily_used"] = self.__get_quota_data__(
                res_json, "api_requests_daily"
            )
            data["api_requests_daily"] = self.__get_quota_data__(
                res_json, "api_requests_daily", False
            )
            data["api_requests_daily_used_ratio"] = (
                data["api_requests_daily_used"] / data["api_requests_daily"]
            )
            return return_data(10000, "query success", data)
        except Exception as e:
            return return_data(10001, str(e), {})

    def filter(self, query, limit=50, descriptors_only=False, cursor=""):
        """
        根据query,cursor获取查询结果
        """
        try:
            url = "https://www.virustotal.com/api/v3/intelligence/search?query={query}&limit={limit}&descriptors_only={descriptors_only}&cursor={cursor}".format(
                query=query,
                limit=limit,
                descriptors_only=descriptors_only,
                cursor=cursor,
            )

            headers = {"Accept": "application/json", "x-apikey": self.api_key}

            response = requests.request("GET", url, headers=headers)
            res_json = response.json()
            if "error" in res_json.keys():
                return return_data(10100, "query failed", res_json)
            cursor = res_json.get("meta", {}).get("cursor", "")
            total_hits = res_json.get("meta", {}).get("total_hits", 0)
            data = dict()
            data["cursor"] = cursor
            data["total_hits"] = total_hits
            data["data"] = list()
            vt_return_dats = res_json.get("data", [])
            for vrd in vt_return_dats:
                one_data = dict()
                one_data["md5"] = vrd.get("attributes", {}).get("md5", "")
                one_data["sha1"] = vrd.get("attributes", {}).get("sha1", "")
                one_data["size"] = vrd.get("attributes", {}).get("size", -1)
                one_data["positive"] = (
                    vrd.get("attributes", {})
                    .get("last_analysis_stats", {})
                    .get("malicious", -1)
                )
                one_data["times_submitted"] = vrd.get("attributes", {}).get(
                    "times_submitted", -1
                )
                one_data["unique_sources"] = vrd.get("attributes", {}).get(
                    "unique_sources", -1
                )
                one_data["type"] = vrd.get("attributes", {}).get("type_description", "")
                one_data["tags"] = ",".join(vrd.get("attributes", {}).get("tags", []))
                one_data["suggested_threat_label"] = (
                    vrd.get("attributes", {})
                    .get("popular_threat_classification", {})
                    .get("suggested_threat_label", "")
                )
                one_data["first_submission_date"] = vrd.get("attributes", {}).get(
                    "first_submission_date", -1
                )
                one_data["names"] = ",".join(vrd.get("attributes", {}).get("names", []))
                data["data"].append(one_data)
            if cursor:
                res_data = self.filter(query, limit, descriptors_only, cursor)
                if res_data.get("status", -1) == 10000:
                    data["data"].extend(res_data.get("data", {}).get("data", []))
            return return_data(10000, "query success", data)
        except Exception as e:
            return return_data(10002, str(e), {})

    def download(self, hash, download_path="./"):
        """
        下载样本
        """
        data = {"hash": hash}
        try:
            url = "https://www.virustotal.com/api/v3/files/{hash}/download".format(
                hash=hash
            )

            headers = {"Accept": "application/json", "x-apikey": self.api_key}

            response = requests.request("GET", url, headers=headers)
            if not os.path.exists(download_path):
                os.mkdir(download_path)
            file_name = os.path.join(download_path, hash)
            if response.content:
                with open(file_name, "wb") as f:
                    f.write(response.content)
                return return_data(10000, file_name, data)
            return return_data(10101, response.text, data)
        except Exception as e:
            return return_data(10003, str(e), data)
