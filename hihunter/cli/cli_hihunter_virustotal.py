# -*- coding: utf-8 -*-
# @Time     : 2023/01/18 19:24:34
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : cli_hihunter_virustotal.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import argparse
from colorama import Fore
from colorama import init
from hihunter.version import NEXTB_HIHUNTER_VERSION
from hihunter.common.common import parse_config
from hihunter.virustotal.virustotal import VirusTotal


def parse_cmd():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        prog="NextB的Virustotal命令行工具",
        description="使用nextb-hihunter-virustotal工具查询api_key的使用情况、下载样本、筛选满足条件的Virustotal样本，并将结果存入sqlite数据库等。版本号：{}".format(
            NEXTB_HIHUNTER_VERSION
        ),
        epilog="使用方式：nextb-hihunter-virustotal -c $config -f 1",
    )

    parser.add_argument(
        "-c",
        "--config",
        help="指定配置文件,默认为当前路径下的: ./nextb_hihunter_config.json",
        type=str,
        dest="config",
        action="store",
        default="./nextb_hihunter_config.json",
    )

    parser.add_argument(
        "-f",
        "--func",
        help="指定操作virustotal的方法类型.方法包括：[usage: 查询api_key使用情况, download: 下载样本, filter: 筛选样本]",
        type=str,
        dest="func",
        action="store",
        default="usage",
    )

    parser.add_argument(
        "-n",
        "--number",
        help="指定每次从virustotal筛选样本的个数,单次默认10条.",
        type=int,
        dest="number",
        action="store",
        default=10,
    )

    parser.add_argument(
        "-d",
        "--donwload-dir",
        help="指定下载文件保存路径,默认为当前路径下的: ./downloads.",
        type=str,
        dest="download_dir",
        action="store",
        default="./downloads",
    )

    parser.add_argument(
        "-hk",
        "--hk",
        help="指定下载文件的哈希值.不可与 -hf 参数一起使用,当设置本参数时,自动忽略 -hf参数.",
        type=str,
        dest="download_hash",
        action="store",
        default="",
    )

    parser.add_argument(
        "-hf",
        "--hash-file",
        help="指定保存下载哈希值的文件,文本格式,每行一个哈希值.",
        type=str,
        dest="download_hash_file",
        action="store",
        default="",
    )

    args = parser.parse_args()

    return args


def virustotal_usage(config):
    virustotal_config = config.get("virustotal")
    if not virustotal_config:
        print("获取Virustotal配置参数错误.")
        exit(0)
    vt = VirusTotal(api_key=virustotal_config.get("api_key"))
    data = vt.api_key_statics()
    if data.get("status") != 10000:
        print("查询Virustotal失败,失败原因: {}".format(data.get("msg")))
    statics_data = data.get("data")
    api_requests_used_ratio = statics_data.get("api_requests_used_ratio", 1.0)
    api_requests_daily_used_ratio = statics_data.get(
        "api_requests_daily_used_ratio", 1.0
    )
    color = Fore.CYAN
    m_color = Fore.GREEN
    if api_requests_used_ratio > 0.5:
        m_color = Fore.RED
    d_color = Fore.GREEN
    if api_requests_daily_used_ratio > 0.5:
        d_color = Fore.RED

    print("{}Virustotal使用情况如下: ".format(color))
    print("{}本日已请求次数: {}".format(d_color, statics_data.get("api_requests_daily_used")))
    print("{}每日请求次数上限: {}".format(d_color, statics_data.get("api_requests_daily")))
    print("{}本日已使用比例: {}".format(d_color, api_requests_daily_used_ratio))
    print("{}本月已请求次数: {}".format(m_color, statics_data.get("api_requests_used")))
    print("{}每月请求次数上限: {}".format(m_color, statics_data.get("api_requests_total")))
    print("{}本月已使用比例: {}".format(m_color, api_requests_used_ratio))
    print("{}每分钟请求次数: {}".format(color, statics_data.get("api_requests_minly")))
    print("{}每小时请求次数: {}".format(color, statics_data.get("api_requests_hourly_used")))


def virustotal_filter(config):
    pass


def virustotal_download(config):
    pass


FUNC_MAPPING = {
    "usage": virustotal_usage,
    "download": virustotal_download,
    "filter": virustotal_filter,
}


def work(param):
    config_file = param.get("config_file")
    if not config_file:
        print("请设置配置文件路径.")
        exit(0)
    func = param.get("func")
    filter_number = param.get("filter_number")
    download_dir = param.get("download_dir")
    download_hash = param.get("download_hash")
    download_hash_file = param.get("download_hash_file")
    config = parse_config(config_file)
    if filter_number:
        config["virustotal"]["filter_number"] = filter_number
        config["virustotal"]["download_dir"] = download_dir
        config["virustotal"]["download_hash"] = download_hash
        config["virustotal"]["download_hash_file"] = download_hash_file
    FUNC_MAPPING[func](config)


init(autoreset=True)


def run():
    """
    CLI命令行入口
    """
    args = parse_cmd()
    param = {
        "config_file": args.config,
        "func": args.func,
        "filter_number": 10,
        "download_dir": args.download_dir,
        "download_hash": args.download_hash,
        "download_hash_file": args.download_hash_file,
    }
    work(param)
