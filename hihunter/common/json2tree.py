# -*- coding: utf-8 -*-
# @Time     : 2022/02/10 16:39:46
# @Author   : ddvv
# @Site     : https://ddvvmmzz.github.io
# @File     : json2tree.py
# @Software : Visual Studio Code
# @WeChat   : NextB

from io import StringIO

_branch_extend = '│  '
_branch_mid    = '├─ '
_branch_last   = '└─ '
_spacing       = '   '

lang_map = {
    'process': '启动',
    'behavior': '操作',
    'drop': '释放',
    'net': '连接'
}

def _getHierarchy(graph, name='', file=None, _prefix='', _last=True):
    """ Recursively parse json data to print data types """
    if isinstance(graph, dict):
        op_type = graph.get('type', '')
        if op_type:
            name = lang_map.get(op_type, op_type) + ' ' + graph.get('name')
            print(_prefix, _branch_last if _last else _branch_mid, \
                name, sep="", file=file)
            _prefix += _spacing if _last else _branch_extend
            length = len(graph)
            for i, key in enumerate(graph.keys()):
                _last = i == (length - 1)
                _getHierarchy(graph[key], '"' + key + '"', file, _prefix, _last)
    elif isinstance(graph, list):
        for each_json in graph:
            _getHierarchy(each_json, '', file, _prefix, _last=True)
    else:
        pass

def graph2tree(graph):
    messageFile = StringIO()
    _getHierarchy(graph, file=messageFile)
    message = messageFile.getvalue()
    messageFile.close()
    return message
