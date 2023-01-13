# -*- coding: utf-8 -*-
# @Time     : 2022/01/30 08:14:21
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : run.py
# @Software : Visual Studio Code
# @WeChat   : NextB


import os
import argparse
import json
import time
from urllib.parse import quote
from datetime import datetime
from hihunter.virustotal.virustotal import VirusTotal
from hihunter.malwarebazaar.malwarebazaar import MalwareBazaar
from hihunter.reddripsandbox.reddripsandbox import ReddripSandbox
from hihunter.common.sqlite_db import HiHunterDB, HiHunterRSDatas
from hihunter.common.common import parse_config

config_help = 'config path. default value: ./hihunter_config.json'
dir_help = 'sample path. default value: ./files'
number_help = 'process number. default value: 10'
remove_help = "remove sample when upload finished. 0: not remove, other: remove, default value: 0"

def run_vt_filter():
    try:
        epilog = "Use like: hihunter-vt-filter -c $config"
        parser = argparse.ArgumentParser(prog='HiHunter virustotal data filter tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-n', '--number', help=number_help,
                    type=int, dest='number', action='store', default=10)

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    vt = VirusTotal(api_key=vt_filter_config.get('api_key'))
    quota_data = vt.api_key_statics()
    print(json.dumps(quota_data, indent=4))
    utc_time_end = int(time.time())
    delay = vt_filter_config.get('delay', 0)
    utc_time_start = utc_time_end - 3600 * 8 - 3600 * delay
    querys = []
    for query in vt_filter_config.get('querys', []):
        querys.append('{0} fs:{1}+ fs:{2}-'.format(query, utc_time_start, utc_time_end))
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    limit = args.number
    for query in querys:
        query = quote(query)
        filter_data = vt.filter(query=query, limit=limit)
        sample_datas = filter_data.get('data', {}).get('data', [])
        print(json.dumps(sample_datas, indent=4))
        hhd.add_vt_data(sample_datas)
    
    print('{}{}{}'.format(20*'-', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 20 * '-'))
    # close session
    hhd.close()

def run_vt_usage():
    try:
        epilog = "Use like: hihunter-vt-usage -c $config"
        parser = argparse.ArgumentParser(prog='Virustotal api usage statics.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    vt = VirusTotal(api_key=vt_filter_config.get('api_key'))
    quota_data = vt.api_key_statics()
    print(json.dumps(quota_data, indent=4))

def run_vt_download():
    try:
        epilog = "Use like: hihunter-vt-download -c $config -d $save_path -k $hash"
        parser = argparse.ArgumentParser(prog='Virustotal sample download tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-d', '--dir', help=dir_help,
                            type=str, dest='save_path', action='store', default='./files')
        parser.add_argument('-k', '--key', help='download sample hash',
                    type=str, dest='key', action='store', default=None)

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    vt = VirusTotal(api_key=vt_filter_config.get('api_key'))
    quota_data = vt.api_key_statics()
    print(json.dumps(quota_data, indent=4))
    download_path = args.save_path
    file_sha1 = args.key
    download_data = vt.download(file_sha1, download_path=download_path)
    print(json.dumps(download_data, indent=4))

def run_vt_download_auto():
    try:
        epilog = "Use like: hihunter-vt-download_auto -c $config -d $save_path"
        parser = argparse.ArgumentParser(prog='Virustotal sample download from postgre tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-d', '--dir', help=dir_help,
                            type=str, dest='save_path', action='store', default='./files')
        parser.add_argument('-t', '--type', help='upload sample type, default value: "MS Word Document", support type: ["MS Word Document","Office Open XML Document","Email","Windows shortcut"]',
                    type=str, dest='file_type', action='store', default='MS Word Document')
        parser.add_argument('-n', '--number', help=number_help,
                    type=int, dest='number', action='store', default=10)

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    vt = VirusTotal(api_key=vt_filter_config.get('api_key'))
    quota_data = vt.api_key_statics()
    print(json.dumps(quota_data, indent=4))
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    download_path = args.save_path
    file_type = args.file_type
    download_limit = args.number
    file_sha1s = hhd.get_mb_sha1s(file_type, download_limit)
    for file_sha1 in file_sha1s:
        if file_sha1:
            download_data = vt.download(file_sha1, download_path=download_path)
            print(json.dumps(download_data, indent=4))
    # close session
    hhd.close()

def run_mb_upload():
    try:
        epilog = "Use like: hihunter-mb-upload -c $config -d $save_path"
        parser = argparse.ArgumentParser(prog='MalwareBazaar sample upload tool(by local).',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-d', '--dir', help=dir_help,
                            type=str, dest='save_path', action='store', default='./files')
        parser.add_argument('-n', '--number', help=number_help,
                    type=int, dest='number', action='store', default=10)
        parser.add_argument('-r', '--remove', help=remove_help,
                    type=int, dest='remove', action='store', default=0)

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    mb = MalwareBazaar(api_key=vt_filter_config.get('mb_api_key'))
    upload_path = args.save_path
    upload_limit = args.number
    is_remove = args.remove
    upload_count = 0
    for file_name in os.listdir(upload_path):
        file_path = os.path.join(upload_path, file_name)
        upload_data = mb.upload(file_path)
        print(json.dumps(upload_data, indent=4))
        if is_remove:
            os.remove(file_path)
        upload_count += 1
        if upload_count >= upload_limit:
            break

def run_mb_upload():
    try:
        epilog = "Use like: hihunter-mb-upload -c $config -d $save_path"
        parser = argparse.ArgumentParser(prog='MalwareBazaar sample upload tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-d', '--dir', help=dir_help,
                            type=str, dest='save_path', action='store', default='./files')
        parser.add_argument('-t', '--type', help='upload sample type, default value: "MS Word Document", support type: ["MS Word Document","Office Open XML Document","Email","Windows shortcut"]',
                    type=str, dest='file_type', action='store', default='MS Word Document')
        parser.add_argument('-n', '--number', help=number_help,
                    type=int, dest='number', action='store', default=10)
        parser.add_argument('-r', '--remove', help=remove_help,
                    type=int, dest='remove', action='store', default=0)

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    vt = VirusTotal(api_key=vt_filter_config.get('api_key'))
    quota_data = vt.api_key_statics()
    print(json.dumps(quota_data, indent=4))
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    mb = MalwareBazaar(api_key=vt_filter_config.get('mb_api_key'))
    download_path = args.save_path
    file_type = args.file_type
    download_limit = args.number
    is_remove = args.remove
    file_sha1s = hhd.get_mb_sha1s(file_type, download_limit)
    for file_sha1 in file_sha1s:
        if file_sha1:
            download_data = vt.download(file_sha1, download_path=download_path)
            print(json.dumps(download_data, indent=4))
            file_path = os.path.join(download_path, file_sha1)
            upload_data = mb.upload(file_path)
            print(json.dumps(upload_data, indent=4))
            hhd.update_vt_by_sha1(file_sha1)
            if is_remove:
                os.remove(file_path)
    # close session
    hhd.close()

def run_rs_upload():
    try:
        epilog = "Use like: hihunter-rs-upload -c $config -d $save_path"
        parser = argparse.ArgumentParser(prog='Reddrip sandbox sample upload tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-d', '--dir', help=dir_help,
                            type=str, dest='save_path', action='store', default='./files')
        parser.add_argument('-n', '--number', help=number_help,
                            type=int, dest='number', action='store', default=10)
        parser.add_argument('-r', '--remove', help=remove_help,
                    type=int, dest='remove', action='store', default=0)

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    all_submit_sha1s = hhd.get_all_sha1s(HiHunterRSDatas)
    upload_path = args.save_path
    upload_number = args.number
    is_remove = args.remove
    sandbox_api_key = vt_filter_config.get('sandbox_api_key', '')
    rs = ReddripSandbox(api_key=sandbox_api_key)
    upload_datas = list()
    count = 0
    for file_name in os.listdir(upload_path):
        # 提交过的就不在提交
        if file_name in all_submit_sha1s:
            continue
        upload_data = dict()
        file_full_path = os.path.join(upload_path, file_name)
        return_data = rs.upload(file_full_path)
        print(json.dumps(return_data, indent=4, ensure_ascii=False))
        if return_data.get('status', -1) == 10000:
            res_data = return_data.get('data', {})
            upload_data['md5'] = res_data.get('md5', '')
            upload_data['sha1'] = res_data.get('sha1', '')
            upload_data['serial_id'] = res_data.get('id', [''])[0]
            upload_data['sandbox_status'] = 0
            # print(json.dumps(upload_data, indent=4, ensure_ascii=False))
            upload_datas.append(upload_data)
            if is_remove:
                os.remove(file_full_path)
        count += 1
        if count >= upload_number:
            break
    hhd.add_rs_data(upload_datas)
    # close session
    hhd.close()

def run_rs_update():
    try:
        epilog = "Use like: hihunter-rs-upload -c $config"
        parser = argparse.ArgumentParser(prog='Reddrip sandbox sample update tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-n', '--number', help=number_help,
                            type=int, dest='number', action='store', default=10)
        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    sandbox_api_key = vt_filter_config.get('sandbox_api_key', '')
    rs = ReddripSandbox(api_key=sandbox_api_key)
    rs_update_limit = args.number
    serial_ids = hhd.get_rs_serial_id(0, rs_update_limit)
    for serial_id in serial_ids:
        return_data = rs.report(serial_id)
        report_data = return_data.get('data', {})
        print(18 * '-' + serial_id + 18 * '-')
        print(report_data.get('graph'))
        if return_data.get('status', -1) == 10000:
            hhd.update_rs_by_serial_id(report_data, serial_id)
    # close session
    hhd.close()

def run_rs_download_screenshot():
    try:
        epilog = "Use like: hihunter-rs-download-screenshot -c $config"
        parser = argparse.ArgumentParser(prog='Reddrip sandbox sample screenshot download tool.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')
        parser.add_argument('-d', '--dir', help='save screenshot path. default value: ./hihunter_screenshot',
                            type=str, dest='save_path', action='store', default='./hihunter_screenshot')
        parser.add_argument('-n', '--number', help=number_help,
                            type=int, dest='number', action='store', default=10)
        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    sandbox_api_key = vt_filter_config.get('sandbox_api_key', '')
    rs = ReddripSandbox(api_key=sandbox_api_key)
    rs_update_limit = args.number
    screen_shot_path = args.save_path
    serial_ids = hhd.get_rs_serial_id(1, rs_update_limit)
    for serial_id in serial_ids:
        screen_data = rs.screen_shot(serial_id)
        pic_data = screen_data.get('data', '')
        if pic_data:
            screen_shot_name = '{}.jpg'.format(serial_id)
            down_screen_shot_path = os.path.join(screen_shot_path, screen_shot_name)
            print('save screenshot at: {}'.format(down_screen_shot_path))
            with open(down_screen_shot_path, 'w') as f:
                f.write(pic_data)
            hhd.update_rs_by_serial_id_screenshot(serial_id)
        else:
            print('{} not found screenshot'.format(serial_id))
    # close session
    hhd.close()


def run_create_table():
    try:
        epilog = "Use like: hihunter-create-pg-table -c $config"
        parser = argparse.ArgumentParser(prog='Create postgre db tables.',
                                        description='Version 0.0.1',
                                        epilog=epilog,
                                        formatter_class=argparse.RawDescriptionHelpFormatter
                                        )
        parser.add_argument('-c', '--config', help=config_help,
                            type=str, dest='config_file', action='store', default='./hihunter_config.json')

        args = parser.parse_args()
    except Exception as e:
        print('error: %s' % str(e))
        exit(0)

    vt_filter_config = parse_config(args.config_file)
    db_name = vt_filter_config.get("sqlite_db_name", "hihunter.db")
    hhd = HiHunterDB(db_name)
    hhd.create_table()
    # close session
    hhd.close()