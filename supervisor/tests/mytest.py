
import os
import stat
import time

def msdos_longify (file, stat_info):
    print(stat_info)
    if stat.S_ISDIR (stat_info[stat.ST_MODE]):
        dir = '<DIR>'
    else:
        dir = '     '
    date = msdos_date (stat_info[stat.ST_MTIME])
    return '%s       %s %8d %s' % (
            date,
            dir,
            stat_info[stat.ST_SIZE],
            file
            )

def msdos_date (t):
    try:
        info = time.gmtime (t)
    except:
        info = time.gmtime (0)
    hour = info[3]
    if hour > 11:
        merid = 'PM'
        hour -= 12
    else:
        merid = 'AM'
    return '%02d-%02d-%02d  %02d:%02d%s' % (
            info[1],
            info[2],
            info[0]%100,
            hour,
            info[4],
            merid
            )


# file = os.getcwd()
# stat_info = os.stat(file)
# print(msdos_longify(file, stat_info))

class list_producer:
    def __init__ (self, list, func=None):
        self.list = list
        self.func = func

    # this should do a pushd/popd
    def more (self):
        if not self.list:
            return ''
        else:
            # do a few at a time
            bunch = self.list[:50]
            if self.func is not None:
                bunch = map (self.func, bunch)
            self.list = self.list[50:]
            return '\r\n'.join(bunch) + '\r\n'

def recode_num(num):
    return 'test'+num


import base64
# str1 = 'This is Test String'
#
# enTest = base64.encodestring(str1)
# deTest = base64.decodestring(enTest)
class A:
    pass


def get_id():
    private_key = id (A())
    print(private_key)


class simple_producer:
    """producer for a string  分size返回"""
    def __init__ (self, data, buffer_size=1024):
        self.data = data
        self.buffer_size = buffer_size

    def more (self):
        if len (self.data) > self.buffer_size:
            result = self.data[:self.buffer_size]
            self.data = self.data[self.buffer_size:]
            return result
        else:
            result = self.data
            self.data = b''
            return result

class scanning_producer:
    """like simple_producer, but more efficient for large strings"""
    def __init__ (self, data, buffer_size=1024):
        self.data = data
        self.buffer_size = buffer_size
        self.pos = 0

    def more (self):
        # 相当于多了一个指针，我感觉不会更快....
        if self.pos < len(self.data):
            lp = self.pos
            rp = min (
                    len(self.data),
                    self.pos + self.buffer_size
                    )
            result = self.data[lp:rp]
            self.pos += len(result)
            return result
        else:
            return b''




# content = 'hhhhh'*1000
# sp=scanning_producer(content)
# start = time.time()
# flag = 1
# while 1:
#     if flag:
#         result = sp.more()
#         if not result:
#             flag = 0
#     else:
#         break
# spend_time = time.time() - start
# print(spend_time)


# content = 'base64 模块提供了 b16encode,b16decode，b32encode,b32decode）'
# sp=simple_producer(content)
# start = time.time()
# flag = 1
# while 1:
#     if flag:
#         result = sp.more()
#         if not result:
#             flag = 0
#     else:
#         break
# spend_time = time.time() - start
# print(spend_time)
# chunk = ['a'] * 10
# print('\r\n'.join(chunk) + '\r\n')

# out_buffer_size = 1<<4  #
# print(out_buffer_size)

# -*- coding: utf-8 -*-
# from html import escape
# so = escape (repr (object))
# print(so)

# n=10
# part = 20
# n, rem = divmod (n, part)
# print(n,rem)

# def progressive_divide (n, parts):
#     result = []
#     for part in parts:
#         # 除法 n是整，rem是余数
#         n, rem = divmod (n, part)
#         result.append (rem)
#     result.append (n)
#     return result
#
# print(progressive_divide(5, [12,13,14,15,16]))

class B:
    def __init__(self):
        pass

    # def __repr__(self):
    #     return 'hello world'

b = B()
# print(b)
#
# RCS_ID =  '$Id: http_server.py,v 1.12 2004/04/21 15:11:44 akuchling Exp $'
# VERSION_STRING = RCS_ID.split()[2]
# print(VERSION_STRING)
# print(repr(b))

class Tag:
    def __init__(self):
        self.change = {'python': 'This is python',
                       'php': 'PHP is a good language'}

    def __getitem__(self, item):
        print('调用getitem')
        return self.change[item]

    def __setitem__(self, key, value):
        print('调用setitem')
        self.change[key] = value

    def __contains__(self, key):
        return key in self.change
#
# a = Tag()
# print(a['php'])
# a['php'] = 'PHP is not a good language'
# print(a['php'])
#
# if 'php' in a:
#     print('aaa')

# value = [1,2,3,4,5,6,7,8,9,0]
# value.clear()
# print(value)


import re
# path_regex = re.compile (
# #      path      params    query   fragment
#         r'([^;?#]*)(;[^?#]*)?(\?[^#]*)?(#.*)?'
#         )
# m = path_regex.match ('https://blog.csdn.net/chituozha5528/article/details/78355039')
# print(m)

# if __name__ == '__main__':
#
#     print(__debug__)


import sys
def compact_traceback():
    t, v, tb = sys.exc_info()
    print(t,v,tb)
    tbinfo = []
    assert tb # Must have a traceback
    while tb:
        tbinfo.append((
            tb.tb_frame.f_code.co_filename,
            tb.tb_frame.f_code.co_name,
            str(tb.tb_lineno)
            ))
        tb = tb.tb_next

    # just to be safe
    del tb

    file, function, line = tbinfo[-1]
    info = ' '.join(['[%s|%s|%s]' % x for x in tbinfo])
    return (file, function, line), t, v, info

print(compact_traceback())












































