#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import codecs
import collections
import inspect
import logging
import os
import random
import re
import sys

import lib.controller.checks
import lib.core.common
import lib.core.convert
import lib.core.option
import lib.core.threads
import lib.request.connect
import lib.utils.search
import lib.utils.sqlalchemy
import thirdparty.ansistrm.ansistrm
import thirdparty.chardet.universaldetector

from lib.core.common import filterNone
from lib.core.common import getSafeExString
from lib.core.common import isDigit
from lib.core.common import isListLike
from lib.core.common import readInput
from lib.core.common import shellExec
from lib.core.common import singleTimeWarnMessage
from lib.core.compat import xrange
from lib.core.convert import stdoutEncode
from lib.core.data import conf
from lib.core.enums import PLACE
from lib.core.option import _setHTTPHandlers
from lib.core.option import setVerbosity
from lib.core.settings import INVALID_UNICODE_PRIVATE_AREA
from lib.core.settings import INVALID_UNICODE_CHAR_FORMAT
from lib.core.settings import IS_WIN
from lib.request.templates import getPageTemplate
from thirdparty import six
from thirdparty.six import unichr as _unichr
from thirdparty.six.moves import http_client as _http_client

_rand = 0

def dirtyPatches():
    """
    Place for "dirty" Python related patches
    """

    # accept overly long result lines (e.g. SQLi results in HTTP header responses)
    '''
    问题：在某些情况下，如 SQL 注入结果在 HTTP 响应头中，结果行可能会非常长，超过默认的最大行长度限制。
    解决方案：将 _http_client._MAXLINE 的值设置为 1MB，以接受过长的结果行。
    '''
    _http_client._MAXLINE = 1 * 1024 * 1024

    # prevent double chunked encoding in case of sqlmap chunking (Note: Python3 does it automatically if 'Content-length' is missing)
    '''
    问题：在 Python 3 中，如果缺少 Content-length 头，HTTPConnection 会自动进行分块编码，这可能导致双重分块编码问题。
    解决方案：通过覆盖 _send_output 方法，确保在 conf.get("chunked") 为 True 时，禁用分块编码
    '''
    if six.PY3:
        if not hasattr(_http_client.HTTPConnection, "__send_output"):
            _http_client.HTTPConnection.__send_output = _http_client.HTTPConnection._send_output

        def _send_output(self, *args, **kwargs):
            if conf.get("chunked") and "encode_chunked" in kwargs:
                kwargs["encode_chunked"] = False
            self.__send_output(*args, **kwargs)

        _http_client.HTTPConnection._send_output = _send_output

    # add support for inet_pton() on Windows OS
    '''
    问题：Windows 系统上没有 inet_pton 函数。
    解决方案：从第三方库 wininetpton 中导入 win_inet_pton，以提供类似功能。
    '''
    if IS_WIN:
        from thirdparty.wininetpton import win_inet_pton

    # Reference: https://github.com/nodejs/node/issues/12786#issuecomment-298652440
    '''
    问题：在 Windows 上，某些情况下会尝试使用 cp65001 编码，这会导致错误。
    解决方案：注册一个编码器，将 cp65001 映射到 utf-8，避免编码错误。
    '''
    codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

    # Reference: http://bugs.python.org/issue17849
    '''
    问题：LineAndFileWrapper 的 readline 方法缺少 size 参数，导致在某些情况下会抛出错误。
    解决方案：通过覆盖 readline 方法，使其接受 size 参数并调用 _readline
    '''
    if hasattr(_http_client, "LineAndFileWrapper"):
        def _(self, *args):
            return self._readline()

        _http_client.LineAndFileWrapper._readline = _http_client.LineAndFileWrapper.readline
        _http_client.LineAndFileWrapper.readline = _

    # to prevent too much "guessing" in case of binary data retrieval
    '''
    问题：在处理二进制数据时，chardet 的默认阈值可能导致错误的编码检测。
    解决方案：将 chardet 的最小阈值提高到 0.90，减少误判。
    '''
    thirdparty.chardet.universaldetector.MINIMUM_THRESHOLD = 0.90

    match = re.search(r" --method[= ](\w+)", " ".join(sys.argv))
    if match and match.group(1).upper() != PLACE.POST:
        PLACE.CUSTOM_POST = PLACE.CUSTOM_POST.replace("POST", "%s (body)" % match.group(1))

    # Reference: https://github.com/sqlmapproject/sqlmap/issues/4314
    '''
    问题：在某些环境中，os.urandom 可能未实现。
    解决方案：提供一个替代实现，使用 random.randint 生成随机字节。
    '''
    try:
        os.urandom(1)
    except NotImplementedError:
        if six.PY3:
            os.urandom = lambda size: bytes(random.randint(0, 255) for _ in range(size))
        else:
            os.urandom = lambda size: "".join(chr(random.randint(0, 255)) for _ in xrange(size))

    # Reference: https://github.com/sqlmapproject/sqlmap/issues/5727
    # Reference: https://stackoverflow.com/a/14076841
    '''
    问题：某些情况下，MySQLdb 可能不可用。
    解决方案：尝试导入 pymysql 并将其安装为 MySQLdb，以提供兼容性。
    '''
    try:
        import pymysql
        pymysql.install_as_MySQLdb()
    except (ImportError, AttributeError):
        pass

    # Reference: https://github.com/bottlepy/bottle/blob/df67999584a0e51ec5b691146c7fa4f3c87f5aac/bottle.py
    # Reference: https://python.readthedocs.io/en/v2.7.2/library/inspect.html#inspect.getargspec
    '''
    问题：在某些 Python 版本中，inspect.getargspec 已被弃用，而 inspect.getfullargspec 取而代之。
    解决方案：通过 inspect.getfullargspec 提供一个兼容的 getargspec 实现。
    '''
    if not hasattr(inspect, "getargspec") and hasattr(inspect, "getfullargspec"):
        ArgSpec = collections.namedtuple("ArgSpec", ("args", "varargs", "keywords", "defaults"))

        def makelist(data):
            if isinstance(data, (tuple, list, set, dict)):
                return list(data)
            elif data:
                return [data]
            else:
                return []

        def getargspec(func):
            spec = inspect.getfullargspec(func)
            kwargs = makelist(spec[0]) + makelist(spec.kwonlyargs)
            return ArgSpec(kwargs, spec[1], spec[2], spec[3])

        inspect.getargspec = getargspec

    # Installing "reversible" unicode (decoding) error handler
    '''
    问题：在处理 Unicode 数据时，可能会遇到不可解码的字符。
    解决方案：注册一个可逆的 Unicode 错误处理器，将不可解码的字符替换为特定格式。
    '''
    def _reversible(ex):
        if INVALID_UNICODE_PRIVATE_AREA:
            return (u"".join(_unichr(int('000f00%2x' % (_ if isinstance(_, int) else ord(_)), 16)) for _ in ex.object[ex.start:ex.end]), ex.end)
        else:
            return (u"".join(INVALID_UNICODE_CHAR_FORMAT % (_ if isinstance(_, int) else ord(_)) for _ in ex.object[ex.start:ex.end]), ex.end)

    codecs.register_error("reversible", _reversible)

    # Reference: https://github.com/sqlmapproject/sqlmap/issues/5731
    '''
    问题：在 Python 3.13 中，logging 模块中的一些私有方法（如 _acquireLock 和 _releaseLock）已被移除。
    解决方案：重新实现这些方法，以确保兼容性。
    '''
    if not hasattr(logging, "_acquireLock"):
        def _acquireLock():
            if logging._lock:
                logging._lock.acquire()

        logging._acquireLock = _acquireLock

    if not hasattr(logging, "_releaseLock"):
        def _releaseLock():
            if logging._lock:
                logging._lock.release()

        logging._releaseLock = _releaseLock

def resolveCrossReferences():
    """
    Place for cross-reference resolution
    """

    lib.core.threads.isDigit = isDigit
    lib.core.threads.readInput = readInput
    lib.core.common.getPageTemplate = getPageTemplate
    lib.core.convert.filterNone = filterNone
    lib.core.convert.isListLike = isListLike
    lib.core.convert.shellExec = shellExec
    lib.core.convert.singleTimeWarnMessage = singleTimeWarnMessage
    lib.core.option._pympTempLeakPatch = pympTempLeakPatch
    lib.request.connect.setHTTPHandlers = _setHTTPHandlers
    lib.utils.search.setHTTPHandlers = _setHTTPHandlers
    lib.controller.checks.setVerbosity = setVerbosity
    lib.utils.sqlalchemy.getSafeExString = getSafeExString
    thirdparty.ansistrm.ansistrm.stdoutEncode = stdoutEncode

def pympTempLeakPatch(tempDir):
    """
    Patch for "pymp" leaking directories inside Python3
    """

    try:
        import multiprocessing.util
        multiprocessing.util.get_temp_dir = lambda: tempDir
    except:
        pass

def unisonRandom():
    """
    Unifying random generated data across different Python versions
    """

    def _lcg():
        global _rand
        a = 1140671485
        c = 128201163
        m = 2 ** 24
        _rand = (a * _rand + c) % m
        return _rand

    def _randint(a, b):
        _ = a + (_lcg() % (b - a + 1))
        return _

    def _choice(seq):
        return seq[_randint(0, len(seq) - 1)]

    def _sample(population, k):
        return [_choice(population) for _ in xrange(k)]

    def _seed(seed):
        global _rand
        _rand = seed

    random.choice = _choice
    random.randint = _randint
    random.sample = _sample
    random.seed = _seed
