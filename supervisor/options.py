# -*- coding: utf-8 -*-
import socket
import getopt
import os
import sys
import tempfile
import errno
import signal
import re
import pwd
import grp
import resource
import stat
import pkg_resources
import glob
import platform
import warnings
import fcntl
import os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from supervisor.compat import PY2
from supervisor.compat import ConfigParser
from supervisor.compat import as_bytes, as_string
from supervisor.compat import xmlrpclib
from supervisor.compat import StringIO
from supervisor.compat import basestring

from supervisor.medusa import asyncore_25 as asyncore

from supervisor.datatypes import process_or_group_name
from supervisor.datatypes import boolean
from supervisor.datatypes import integer
from supervisor.datatypes import name_to_uid
from supervisor.datatypes import gid_for_uid
from supervisor.datatypes import existing_dirpath
from supervisor.datatypes import byte_size
from supervisor.datatypes import signal_number
from supervisor.datatypes import list_of_exitcodes
from supervisor.datatypes import dict_of_key_value_pairs
from supervisor.datatypes import logfile_name
from supervisor.datatypes import list_of_strings
from supervisor.datatypes import octal_type
from supervisor.datatypes import existing_directory
from supervisor.datatypes import logging_level
from supervisor.datatypes import colon_separated_user_group
from supervisor.datatypes import inet_address
from supervisor.datatypes import InetStreamSocketConfig
from supervisor.datatypes import UnixStreamSocketConfig
from supervisor.datatypes import url
from supervisor.datatypes import Automatic
from supervisor.datatypes import auto_restart
from supervisor.datatypes import profile_options

from supervisor import loggers
from supervisor import states
from supervisor import xmlrpc
from supervisor import poller

def _read_version_txt():
    mydir = os.path.abspath(os.path.dirname(__file__))
    version_txt = os.path.join(mydir, 'version.txt')
    with open(version_txt, 'r') as f:
        return f.read().strip()
VERSION = _read_version_txt()

def normalize_path(v):
    return os.path.normpath(os.path.abspath(os.path.expanduser(v)))

class Dummy:
    pass

class Options:
    stderr = sys.stderr  # 错误重定向
    stdout = sys.stdout  # 输出重定向
    exit = sys.exit  # 退出状态
    warnings = warnings  #忽略警告

    uid = gid = None #用户id和组id

    progname = sys.argv[0]
    configfile = None  # 配置文件
    schemadir = None  #
    configroot = None  #配置文件root
    here = None

    # Class variable deciding whether positional arguments are allowed.
    # If you want positional arguments, set this to 1 in your subclass.
    # 位置参数
    positional_args_allowed = 0

    def __init__(self, require_configfile=True):
        """Constructor.

        Params:
        require_configfile -- whether we should fail on no config file.
        """
        self.names_list = []  # 项目名（如wsgi)
        self.short_options = []  # 短命令
        self.long_options = []  # 长命令
        self.options_map = {} # 长短命令映射？
        self.default_map = {}
        self.required_map = {} # 需求
        self.environ_map = {}
        self.attr_priorities = {} # 优先级
        self.require_configfile = require_configfile
        self.add(None, None, "h", "help", self.help)
        # 配置文件
        self.add("configfile", None, "c:", "configuration=")
        # 项目根目录
        here = os.path.dirname(os.path.dirname(sys.argv[0]))
        # 各种安装方式的配置目录,顺序是有优先级的
        searchpaths = [os.path.join(here, 'etc', 'supervisord.conf'),
                       os.path.join(here, 'supervisord.conf'),
                       'supervisord.conf',
                       'etc/supervisord.conf',
                       '/etc/supervisord.conf',
                       '/etc/supervisor/supervisord.conf',
                       ]
        # 搜索路径
        self.searchpaths = searchpaths
        # 运行环境env
        self.environ_expansions = {}
        for k, v in os.environ.items():
            self.environ_expansions['ENV_%s' % k] = v

    def default_configfile(self):
        """Return the name of the found config file or print usage/exit.返回配置文件"""
        config = None
        for path in self.searchpaths:
            if os.path.exists(path):
                config = path
                break
        if config is None and self.require_configfile:
            self.usage('No config file found at default paths (%s); '
                       'use the -c option to specify a config file '
                       'at a different path' % ', '.join(self.searchpaths))
        return config

    def help(self, dummy):
        """Print a long help message to stdout and exit(0).

        Occurrences of "%s" in are replaced by self.progname.
        """
        help = self.doc + "\n"
        if help.find("%s") > 0:
            help = help.replace("%s", self.progname)
        self.stdout.write(help)
        self.exit(0)

    def usage(self, msg):
        """Print a brief error message to stderr and exit(2)."""
        self.stderr.write("Error: %s\n" % str(msg))
        self.stderr.write("For help, use %s -h\n" % self.progname)
        self.exit(2)

    def  add(self,
            name=None,                  # attribute name on self
            confname=None,              # dotted config path name  在name前加上supervisd.
            short=None,                 # short option name
            long=None,                  # long option name
            handler=None,               # handler (defaults to string)  处理函数
            default=None,               # default value  默认值
            required=None,              # message if not provided  提示信息
            flag=None,                  # if not None, flag value 标志值
            env=None,                   # if not None, environment variable 环境变量
            ):
        """
        初始化，相关的配置，short_options     long_options   options_map等
        Add information about a configuration option.

        This can take several forms:

        add(name, confname)
            Configuration option 'confname' maps to attribute 'name'
        add(name, None, short, long)
            Command line option '-short' or '--long' maps to 'name'
        add(None, None, short, long, handler)
            Command line option calls handler
        add(name, None, short, long, handler)
            Assign handler return value to attribute 'name'

        In addition, one of the following keyword arguments may be given:

        default=...  -- if not None, the default value
        required=... -- if nonempty, an error message if no value provided
        flag=...     -- if not None, flag value for command line option
        env=...      -- if not None, name of environment variable that
                        overrides the configuration file or default
        """
        if flag is not None:
            if handler is not None:
                raise ValueError("use at most one of flag= and handler=")
            if not long and not short:
                raise ValueError("flag= requires a command line flag")
            if short and short.endswith(":"):
                raise ValueError("flag= requires a command line flag")
            if long and long.endswith("="):
                raise ValueError("flag= requires a command line flag")
            # 如果调用时没有flag参数，返回flag的值，目前有flag参数的都没有handler，所以创建handler
            handler = lambda arg, flag=flag: flag

        if short and long:
            # 短命令加 ;  长命令加 =
            if short.endswith(":") != long.endswith("="):
                raise ValueError("inconsistent short/long options: %r %r" % (
                    short, long))

        if short:
            # 命令参数没有 -
            if short[0] == "-":
                raise ValueError("short option should not start with '-'")
            key, rest = short[:1], short[1:]
            if rest not in ("", ":"):
                raise ValueError("short option should be 'x' or 'x:'")
            key = "-" + key
            if key in self.options_map:
                raise ValueError("duplicate short option key '%s'" % key)
            # key是‘-’+ 短命令的开头字符串 +去掉：
            self.options_map[key] = (name, handler)
            self.short_options.append(short)

        if long:
            if long[0] == "-":
                raise ValueError("long option should not start with '-'")
            key = long
            if key[-1] == "=":
                key = key[:-1]
            key = "--" + key
            if key in self.options_map:
                raise ValueError("duplicate long option key '%s'" % key)
            # key是‘--’ + 长命令字符串 + 去掉 =
            self.options_map[key] = (name, handler)
            self.long_options.append(long)

        if env:
            self.environ_map[env] = (name, handler)

        if name:
            if not hasattr(self, name):
                # 为每一个name设置None属性
                setattr(self, name, None)
            self.names_list.append((name, confname))
            if default is not None:
                self.default_map[name] = default
            if required:
                self.required_map[name] = required

    def _set(self, attr, value, prio):
        # 如果想设置属性，那么需要比旧属性的优先级要高
        current = self.attr_priorities.get(attr, -1)
        if prio >= current:
            setattr(self, attr, value)
            self.attr_priorities[attr] = prio

    def realize(self, args=None, doc=None, progname=None):
        """Realize a configuration.

        Optional arguments:

        args     -- the command line arguments, less the program name
                    (default is sys.argv[1:])

        doc      -- usage message (default is __main__.__doc__)
        """
        # Provide dynamic default method arguments
        # args[0] 是main（）函数的路径，doc是main上面的'''
        if args is None:
            args = sys.argv[1:]
        if progname is None:
            # 注意，不是本文件的路径，而是函数入口的路径 superviosrd.py
            progname = sys.argv[0]
        if doc is None:
            try:
                import __main__
                doc = __main__.__doc__
            except Exception:
                pass
        self.progname = progname
        # supervisord.py 的doc,是
        self.doc = doc
        self.options = []
        self.args = []

        # Call getopt
        try:
            # 检测这个参数是否在长短命令列表中，如果在，那么给self.option
            self.options, self.args = getopt.getopt(
                args, "".join(self.short_options), self.long_options)
        # usage是一个缓冲输出
        except getopt.error as exc:
            self.usage(str(exc))

        # Check for positional args
        if self.args and not self.positional_args_allowed:
            self.usage("positional arguments are not supported: %s" % (str(self.args)))

        # Process options returned by getopt
        for opt, arg in self.options:
            name, handler = self.options_map[opt]
            #configuration的handler是None
            if handler is not None:
                try:
                    arg = handler(arg)
                except ValueError as msg:
                    self.usage("invalid value for %s %r: %s" % (opt, arg, msg))
            if name and arg is not None:
                if getattr(self, name) is not None:
                    self.usage("conflicting command line option %r" % opt)
                # 如果想设置属性，那么需要比旧属性的优先级要高
                self._set(name, arg, 2)

        # Process environment variables
        for envvar in self.environ_map.keys():
            name, handler = self.environ_map[envvar]
            if envvar in os.environ:
                value = os.environ[envvar]
                if handler is not None:
                    try:
                        value = handler(value)
                    except ValueError as msg:
                        self.usage("invalid environment value for %s %r: %s"
                                   % (envvar, value, msg))
                if name and value is not None:
                    self._set(name, value, 1)

        if self.configfile is None:
            # add 中为每一个name都创建了属性
            self.configfile = self.default_configfile()

        self.process_config()

    def process_config(self, do_usage=True):
        """Process configuration data structure.

        This includes reading config file if necessary, setting defaults etc.
        """
        if self.configfile:
            self.process_config_file(do_usage)

        # Copy config options to attributes of self.  This only fills
        # in options that aren't already set from the command line.
        for name, confname in self.names_list:
            if confname:
                parts = confname.split(".")
                obj = self.configroot
                for part in parts:
                    if obj is None:
                        break
                    # Here AttributeError is not a user error!
                    obj = getattr(obj, part)
                self._set(name, obj, 0)

        # Process defaults
        for name, value in self.default_map.items():
            if getattr(self, name) is None:
                setattr(self, name, value)

        # Process required options
        for name, message in self.required_map.items():
            if getattr(self, name) is None:
                self.usage(message)

    def process_config_file(self, do_usage):
        # Process config file
        if not hasattr(self.configfile, 'read'):
            self.here = os.path.abspath(os.path.dirname(self.configfile))
        try:
            self.read_config(self.configfile)
        except ValueError as msg:
            if do_usage:
                # if this is not called from an RPC method, run usage and exit.
                self.usage(str(msg))
            else:
                # if this is called from an RPC method, raise an error
                raise ValueError(msg)

    def exists(self, path):
        return os.path.exists(path)

    def open(self, fn, mode='r'):
        return open(fn, mode)

    def get_plugins(self, parser, factory_key, section_prefix):
        factories = []
        for section in parser.sections():
            if not section.startswith(section_prefix):
                # rpcinterface:supervisor  supervisor.rpcinterface
                continue
            name = section.split(':', 1)[1]
            factory_spec = parser.saneget(section, factory_key, None)
            # supervisor.rpcinterface: make_main_rpcinterface
            if factory_spec is None:
                raise ValueError('section [%s] does not specify a %s'  %
                                 (section, factory_key))
            try:
                factory = self.import_spec(factory_spec)
                # <function make_main_rpcinterface at 0x7f9076a59230
            except ImportError:
                raise ValueError('%s cannot be resolved within [%s]' % (
                    factory_spec, section))

            extras = {}
            for k in parser.options(section):
                if k != factory_key:
                    extras[k] = parser.saneget(section, k)
            factories.append((name, factory, extras))
            #[('supervisor', < function make_main_rpcinterface at 0x7f46fb7dd1b8 >, {})]
        return factories

    def import_spec(self, spec):
        # 这个ep和之前分析的入口文件比较相似
        # function make_main_rpcinterface
        '''
         spec = 'supervisor.rpcinterface:make_main_rpcinterface<a>'
         报错：Error: supervisor.rpcinterface:make_main_rpcinterface cannot be resolved within [rpcinterface:supervisor]
                For help, use supervisord.py -h
        '''

        ep = pkg_resources.EntryPoint.parse("x=" + spec)
        # print(ep,'*************')
        '''
        发布，其实就是将一个函数放到变量里面，每次直接调用这个变量   
        spec = 'supervisor.rpcinterface:pkg_test'
        ep_1 = pkg_resources.EntryPoint.parse("x=" + spec)
        print(ep_1.resolve()().get_age())
        '''
        if hasattr(ep, 'resolve'):
            # this is available on setuptools >= 10.2
            # ep:EntryPoint.parse('x = supervisor.rpcinterface:make_main_rpcinterface'
            # ep.resolve:
            # print(ep,ep.resolve())
            # 在rpcinterface.py 中1026行
            return ep.resolve()
        else:
            # this causes a DeprecationWarning on setuptools >= 11.3
            return ep.load(False)


class ServerOptions(Options):
    user = None   #用户
    sockchown = None  # sock文件的
    sockchmod = None  # sock的权限
    logfile = None  # 日志文件
    loglevel = None  # 日志级别
    pidfile = None  # 进程文件
    passwdfile = None  #密码
    nodaemon = None  # 无守护进程
    environment = None  #环境
    httpservers = ()  # http
    unlink_pidfile = False  # 未连接的进程文件
    unlink_socketfiles = False  #未连接的sock文件
    mood = states.SupervisorStates.RUNNING  # 运行状态

    def __init__(self):
        Options.__init__(self)
        self.configroot = Dummy()
        self.configroot.supervisord = Dummy()

        self.add(None, None, "v", "version", self.version)  # 版本信息
        self.add("nodaemon", "supervisord.nodaemon", "n", "nodaemon", flag=1,
                 default=0)  # 如果为TRUE,则在前台进行，如果为false，再后台
        self.add("user", "supervisord.user", "u:", "user=")
        self.add("umask", "supervisord.umask", "m:", "umask=",
                 octal_type, default='022') # 转化成8位，rwxrwxrwx正好八位，文件权限
        self.add("directory", "supervisord.directory", "d:", "directory=",
                 existing_directory) #把path中包含的"~"和"~user"转换成用户目录
        self.add("logfile", "supervisord.logfile", "l:", "logfile=",
                 existing_dirpath, default="supervisord.log") # 返回所在目录
        self.add("logfile_maxbytes", "supervisord.logfile_maxbytes",
                 "y:", "logfile_maxbytes=", byte_size,
                 default=50 * 1024 * 1024) # 50MB  logfile文件的最大值，超过之后会生成新的文件，0是表示不限制
        self.add("logfile_backups", "supervisord.logfile_backups",
                 "z:", "logfile_backups=", integer, default=10)  # 默认log文件数量大于10的时候，覆盖log文件（上）
        self.add("loglevel", "supervisord.loglevel", "e:", "loglevel=",
                 logging_level, default="info")  #log_level
        self.add("pidfile", "supervisord.pidfile", "j:", "pidfile=",
                 existing_dirpath, default="supervisord.pid")  #pid文件
        self.add("identifier", "supervisord.identifier", "i:", "identifier=",
                 str, default="supervisor")
        self.add("childlogdir", "supervisord.childlogdir", "q:", "childlogdir=",
                 existing_directory, default=tempfile.gettempdir())  #tempfile.gettempdir()得到临时文件路径
        # 这个是最少系统空闲的文件描述符，低于这个值supervisor将不会启动。
        # 系统的文件描述符在这里设置cat /proc/sys/fs/file-max。默认情况下为1024
        self.add("minfds", "supervisord.minfds",
                 "a:", "minfds=", int, default=1024)
        self.add("minprocs", "supervisord.minprocs",  #可用的进程描述符，低于这个值supervisor也将不会正常启动。ulimit -u这个命令，
                 "", "minprocs=", int, default=200)  # 可以查看linux下面用户的最大进程数。默认为200
        # 这个参数当为false的时候，会在supervisord进程启动的时候，把以前子进程产生的日志文件(路径为AUTO的情况下)清除掉。
        # 有时候咱们想要看历史日志，当然不想日志被清除了。所以可以设置为true。默认是false，有调试需求的同学可以设置为true
        self.add("nocleanup", "supervisord.nocleanup",
                 "k", "nocleanup", flag=1, default=0)
        #这个选项如果设置为true，会清除子进程日志中的所有ANSI
        #序列。什么是ANSI序列呢？就是我们的\n,\t这些东西。默认为false
        self.add("strip_ansi", "supervisord.strip_ansi",
                 "t", "strip_ansi", flag=1, default=0)
        self.add("profile_options", "supervisord.profile_options",
                 "", "profile_options=", profile_options, default=None)
        self.pidhistory = {} # 进程历史
        self.process_group_configs = []  #进程组配置
        self.parse_criticals = []  # critical, error, warn, info, debug, trace, or blather，最高错误级别
        self.parse_warnings = []    # warnings
        self.parse_infos = []   # infos
        self.signal_receiver = SignalReceiver() # 信号量接收，查询
        self.poller = poller.Poller(self)  # pull select，注意这个参数是self，表示是自己这个实例作为参数


    def version(self, dummy):
        """Print version to stdout and exit(0).
           打印 version
        """
        self.stdout.write('%s\n' % VERSION)
        self.exit(0)

    # TODO: not covered by any test, but used by dispatchers
    def getLogger(self, *args, **kwargs):
        return loggers.getLogger(*args, **kwargs)

    def default_configfile(self):
        if os.getuid() == 0:
            self.warnings.warn(
                'Supervisord is running as root and it is searching '
                'for its configuration file in default locations '
                '(including its current working directory); you '
                'probably want to specify a "-c" argument specifying an '
                'absolute path to a configuration file for improved '
                'security.'
                )
        return Options.default_configfile(self)

    def realize(self, *arg, **kw):
        Options.realize(self, *arg, **kw)

        section = self.configroot.supervisord
        # attribute_value = section.__dict__
        # for key, value in attribute_value.items():
        #     print(key, value)

        # Additional checking of user option; set uid and gid
        if self.user is not None:
            try:
                uid = name_to_uid(self.user)
            except ValueError as msg:
                self.usage(msg) # invalid user
            self.uid = uid
            self.gid = gid_for_uid(uid)

        if not self.loglevel:
            self.loglevel = section.loglevel

        if self.logfile:
            logfile = self.logfile
        else:
            logfile = section.logfile

        self.logfile = normalize_path(logfile)

        if self.pidfile:
            pidfile = self.pidfile
        else:
            pidfile = section.pidfile

        self.pidfile = normalize_path(pidfile)

        self.rpcinterface_factories = section.rpcinterface_factories

        self.serverurl = None

        self.server_configs = sconfigs = section.server_configs

        # we need to set a fallback serverurl that process.spawn can use

        # prefer a unix domain socket
        for config in [ config for config in sconfigs if
                        config['family'] is socket.AF_UNIX ]:
            path = config['file']
            self.serverurl = 'unix://%s' % path
            break

        # fall back to an inet socket
        if self.serverurl is None:
            for config in [ config for config in sconfigs if
                            config['family'] is socket.AF_INET]:
                host = config['host']
                port = config['port']
                if not host:
                    host = 'localhost'
                self.serverurl = 'http://%s:%s' % (host, port)

        # self.serverurl may still be None if no servers at all are
        # configured in the config file

        self.identifier = section.identifier

    def process_config(self, do_usage=True):
        Options.process_config(self, do_usage=do_usage)

        new = self.configroot.supervisord.process_group_configs
        self.process_group_configs = new

    def read_config(self, fp):
        # Clear parse messages, since we may be re-reading the
        # config a second time after a reload.
        self.parse_criticals = []
        self.parse_warnings = []
        self.parse_infos = []
        # 注意，{}是可变对象，现在改变section，self.configroot.supervisord也会随着改变
        section = self.configroot.supervisord
        need_close = False
        if not hasattr(fp, 'read'):
            if not self.exists(fp):
                raise ValueError("could not find config file %s" % fp)
            try:
                # 读配置文件
                fp = self.open(fp, 'r')
                need_close = True
            except (IOError, OSError):
                raise ValueError("could not read config file %s" % fp)

        parser = UnhosedConfigParser()
        parser.expansions = self.environ_expansions
        try:
            try:
                # 将环境变量写进configparser配置文件
                parser.read_file(fp)
            except AttributeError:
                parser.readfp(fp)
        except ConfigParser.ParsingError as why:
            raise ValueError(str(why))
        finally:
            if need_close:
                fp.close()
        # platform 是python模块，返回系统 硬件等信息,我的服务器返回ejior-XPS-8930，虚拟机ubuntu
        host_node_name = platform.node()
        expansions = {'here':self.here,
                      'host_node_name':host_node_name}
        expansions.update(self.environ_expansions)

        # 这个if下面是路径读取/etc/supervisor/conf.d/*.conf下自定义的进程配置文件
        if parser.has_section('include'):
            # 无返回结果，没看懂这个步骤
            parser.expand_here(self.here)
            if not parser.has_option('include', 'files'):
                raise ValueError(".ini file has [include] section, but no "
                "files setting")
            # files = /etc/supervisor/conf.d/*.conf
            files = parser.get('include', 'files')
            # 原样返回
            files = expand(files, expansions, 'include.files')
            files = files.split()
            # fp.name =-  '/etc/supervisord.conf'
            if hasattr(fp, 'name'):
                base = os.path.dirname(os.path.abspath(fp.name))
            else:
                base = '.'
            # 加载自定义的配置文件到config中
            for pattern in files:
                pattern = os.path.join(base, pattern)
                # 匹配该目录下的所有文件并以list的方式返回
                filenames = glob.glob(pattern)
                if not filenames:
                    self.parse_warnings.append(
                        'No file matches via include "%s"' % pattern)
                    continue
                for filename in sorted(filenames):
                    self.parse_infos.append(
                        'Included extra file "%s" during parsing' % filename)
                    try:
                        # 加载到配置文件
                        parser.read(filename)
                    except ConfigParser.ParsingError as why:
                        raise ValueError(str(why))
                    else:
                        parser.expand_here(
                            os.path.abspath(os.path.dirname(filename))
                        )
        # 'program:st'已经被加到里面了
        sections = parser.sections()
        if not 'supervisord' in sections:
            raise ValueError('.ini file does not include supervisord section')

        common_expansions = {'here':self.here}
        '''
        [supervisord]
        logfile=/tmp/supervisord.log ; main log file; default $CWD/supervisord.log
        logfile_maxbytes=50MB        ; max main logfile bytes b4 rotation; default 50MB
        logfile_backups=10           ; # of main logfile backups; 0 means none, default 10
        loglevel=info                ; log level; default info; others: debug,warn,trace
        pidfile=/tmp/supervisord.pid ; supervisord pidfile; default supervisord.pid
        nodaemon=false               ; start in foreground if true; default false
        minfds=1024                  ; min. avail startup file descriptors; default 1024
        minprocs=200                 ; min. avail process descriptors;default 200
        
        [rpcinterface:supervisor]
        supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface
        
        [supervisorctl]
        serverurl=unix:///tmp/supervisor.sock ; use a unix:// URL  for a unix socket
        
        [include]
        files = /etc/supervisor/conf.d/*.conf
        
        sunjian@ubuntu:~/kaiyuan/tmp_data$ ^C
        sunjian@ubuntu:~/kaiyuan/tmp_data$ ^C
        sunjian@ubuntu:~/kaiyuan/tmp_data$ cat supervisord_1.conf 
        [unix_http_server]
        file=/tmp/supervisor.sock   ; the path to the socket file
        
        [supervisord]
        logfile=/tmp/supervisord.log ; main log file; default $CWD/supervisord.log
        logfile_maxbytes=50MB        ; max main logfile bytes b4 rotation; default 50MB
        logfile_backups=10           ; # of main logfile backups; 0 means none, default 10
        loglevel=info                ; log level; default info; others: debug,warn,trace
        pidfile=/tmp/supervisord.pid ; supervisord pidfile; default supervisord.pid
        nodaemon=false               ; start in foreground if true; default false
        minfds=1024                  ; min. avail startup file descriptors; default 1024
        minprocs=200                 ; min. avail process descriptors;default 200
        
        [rpcinterface:supervisor]
        supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface
        
        [supervisorctl]
        serverurl=unix:///tmp/supervisor.sock ; use a unix:// URL  for a unix socket
        
        [include]
        files = /etc/supervisor/conf.d/*.conf

        '''
        def get(opt, default, **kwargs):
            '''
            这个函数我还没看，大致是如果在配置文件中有，那么使用配置文件中的value,如果没有，使用提供的默认值
            '''
            expansions = kwargs.get('expansions', {})
            expansions.update(common_expansions)
            kwargs['expansions'] = expansions
            return parser.getdefault(opt, default, **kwargs)
        # 最小的文件描述符
        section.minfds = integer(get('minfds', 1024))
        section.minprocs = integer(get('minprocs', 200))

        directory = get('directory', None)
        if directory is None:
            section.directory = None
        else:
            section.directory = existing_directory(directory)

        section.user = get('user', None)
        section.umask = octal_type(get('umask', '022'))
        section.logfile = existing_dirpath(get('logfile', 'supervisord.log'))
        section.logfile_maxbytes = byte_size(get('logfile_maxbytes', '50MB'))
        section.logfile_backups = integer(get('logfile_backups', 10))
        section.loglevel = logging_level(get('loglevel', 'info'))
        section.pidfile = existing_dirpath(get('pidfile', 'supervisord.pid'))
        section.identifier = get('identifier', 'supervisor')
        #这个参数是supervisord的标识符，主要是给XML_RPC用的。当你有多个supervisor的时候，而且想调用XML_RPC统一管理，就需要为每个
        #supervisor设置不同的标识符了
        section.nodaemon = boolean(get('nodaemon', 'false'))

        tempdir = tempfile.gettempdir()
        section.childlogdir = existing_directory(get('childlogdir', tempdir))  #当子进程日志路径为AUTO的时候，子进程日志文件的存放路径。
        section.nocleanup = boolean(get('nocleanup', 'false'))
        section.strip_ansi = boolean(get('strip_ansi', 'false'))

        environ_str = get('environment', '')
        environ_str = expand(environ_str, expansions, 'environment')
        section.environment = dict_of_key_value_pairs(environ_str)
        # Process rpcinterface plugins before groups to allow custom events to
        # be registered.
        # rpcinterface 是一个插件，rpc远程调用
        section.rpcinterface_factories = self.get_plugins(
            parser,
            'supervisor.rpcinterface_factory',
            'rpcinterface:'
            )
        # print(section.rpcinterface_factories)

        '''
        最终结果就是返回一个实例
        def supervisord():
            return  100

        for name, factory, d in section.rpcinterface_factories:
            try:
                inst = factory(supervisord, **d)
            except:
                print('aaa')
        print(inst.supervisord())
        '''

        # 下面是进程的核心，现在section.process_group_configs 是ProcessGroupConfig 实例组成的list
        section.process_group_configs = self.process_groups_from_parser(parser)
        for group in section.process_group_configs:
            for proc in group.process_configs:
                env = section.environment.copy()
                env.update(proc.environment)
                proc.environment = env
        # []
        section.server_configs = self.server_configs_from_parser(parser)
        # supervisord -n -c sample.conf --profile_options=cumulative,calls   额外命令行
        section.profile_options = None
        # print(section.__dict__)
        return section

    def process_groups_from_parser(self, parser):
        groups = []
        all_sections = parser.sections()
        homogeneous_exclude = []

        common_expansions = {'here':self.here}
        def get(section, opt, default, **kwargs):
            expansions = kwargs.get('expansions', {})
            expansions.update(common_expansions)
            kwargs['expansions'] = expansions
            return parser.saneget(section, opt, default, **kwargs)

        # process heterogeneous groups
        # ['unix_http_server', 'supervisord', 'rpcinterface:supervisor', 'supervisorctl', 'include', 'program:st']
        for section in all_sections:
            if not section.startswith('group:'):
                continue
            group_name = process_or_group_name(section.split(':', 1)[1])
            programs = list_of_strings(get(section, 'programs', None))
            priority = integer(get(section, 'priority', 999))
            group_processes = []
            for program in programs:
                program_section = "program:%s" % program
                fcgi_section = "fcgi-program:%s" % program
                if not program_section in all_sections and not fcgi_section in all_sections:
                    raise ValueError(
                        '[%s] names unknown program or fcgi-program %s' % (section, program))
                if program_section in all_sections and fcgi_section in all_sections:
                     raise ValueError(
                        '[%s] name %s is ambiguous (exists as program and fcgi-program)' %
                        (section, program))
                section = program_section if program_section in all_sections else fcgi_section
                homogeneous_exclude.append(section)
                # 返回一个ProcessConfig实例（根据配置文件初始化过后的实例） 将类作为实例，比较少见
                processes = self.processes_from_section(parser, section,
                                                        group_name, ProcessConfig)

                group_processes.extend(processes)
            groups.append(
                ProcessGroupConfig(self, group_name, priority, group_processes)
                )

        # process "normal" homogeneous groups
        for section in all_sections:
            # yes
            if ( (not section.startswith('program:') )
                 or section in homogeneous_exclude ):
                continue
            # process_or_group_name('st)  检测st中是否出现 ：/
            program_name = process_or_group_name(section.split(':', 1)[1])
            priority = integer(get(section, 'priority', 999))
            # 返回一个ProcessConfig实例（根据配置文件初始化过后的实例）
            processes=self.processes_from_section(parser, section, program_name,
                                                  ProcessConfig)
            # 添加到组
            groups.append(
                ProcessGroupConfig(self, program_name, priority, processes)
                )

        # process "event listener" homogeneous groups
        for section in all_sections:
            if not section.startswith('eventlistener:'):
                continue
            pool_name = section.split(':', 1)[1]

            # give listeners a "high" default priority so they are started first
            # and stopped last at mainloop exit
            priority = integer(get(section, 'priority', -1))

            buffer_size = integer(get(section, 'buffer_size', 10))
            if buffer_size < 1:
                raise ValueError('[%s] section sets invalid buffer_size (%d)' %
                    (section, buffer_size))

            result_handler = get(section, 'result_handler',
                                       'supervisor.dispatchers:default_handler')
            try:
                result_handler = self.import_spec(result_handler)
            except ImportError:
                raise ValueError('%s cannot be resolved within [%s]' % (
                    result_handler, section))

            pool_event_names = [x.upper() for x in
                                list_of_strings(get(section, 'events', ''))]
            pool_event_names = set(pool_event_names)
            if not pool_event_names:
                raise ValueError('[%s] section requires an "events" line' %
                                 section)

            from supervisor.events import EventTypes
            pool_events = []
            for pool_event_name in pool_event_names:
                pool_event = getattr(EventTypes, pool_event_name, None)
                if pool_event is None:
                    raise ValueError('Unknown event type %s in [%s] events' %
                                     (pool_event_name, section))
                pool_events.append(pool_event)

            redirect_stderr = boolean(get(section, 'redirect_stderr', 'false'))
            if redirect_stderr:
                raise ValueError('[%s] section sets redirect_stderr=true '
                    'but this is not allowed because it will interfere '
                    'with the eventlistener protocol' % section)

            processes=self.processes_from_section(parser, section, pool_name,
                                                  EventListenerConfig)

            groups.append(
                EventListenerPoolConfig(self, pool_name, priority, processes,
                                        buffer_size, pool_events,
                                        result_handler)
                )

        # process fastcgi homogeneous groups
        for section in all_sections:
            if ( (not section.startswith('fcgi-program:') )
                 or section in homogeneous_exclude ):
                continue
            program_name = process_or_group_name(section.split(':', 1)[1])
            priority = integer(get(section, 'priority', 999))
            fcgi_expansions = {'program_name': program_name}

            # find proc_uid from "user" option
            proc_user = get(section, 'user', None)
            if proc_user is None:
                proc_uid = None
            else:
                proc_uid = name_to_uid(proc_user)

            socket_backlog = get(section, 'socket_backlog', None)

            if socket_backlog is not None:
                socket_backlog = integer(socket_backlog)
                if (socket_backlog < 1 or socket_backlog > 65535):
                    raise ValueError('Invalid socket_backlog value %s'
                                                            % socket_backlog)

            socket_owner = get(section, 'socket_owner', None)
            if socket_owner is not None:
                try:
                    socket_owner = colon_separated_user_group(socket_owner)
                except ValueError:
                    raise ValueError('Invalid socket_owner value %s'
                                                                % socket_owner)

            socket_mode = get(section, 'socket_mode', None)
            if socket_mode is not None:
                try:
                    socket_mode = octal_type(socket_mode)
                except (TypeError, ValueError):
                    raise ValueError('Invalid socket_mode value %s'
                                                                % socket_mode)

            socket = get(section, 'socket', None, expansions=fcgi_expansions)
            if not socket:
                raise ValueError('[%s] section requires a "socket" line' %
                                 section)

            try:
                socket_config = self.parse_fcgi_socket(socket, proc_uid,
                                                    socket_owner, socket_mode,
                                                    socket_backlog)
            except ValueError as e:
                raise ValueError('%s in [%s] socket' % (str(e), section))

            processes=self.processes_from_section(parser, section, program_name,
                                                  FastCGIProcessConfig)
            groups.append(
                FastCGIGroupConfig(self, program_name, priority, processes,
                                   socket_config)
                )

        groups.sort()
        return groups

    def parse_fcgi_socket(self, sock, proc_uid, socket_owner, socket_mode,
            socket_backlog):
        if sock.startswith('unix://'):
            path = sock[7:]
            #Check it's an absolute path
            if not os.path.isabs(path):
                raise ValueError("Unix socket path %s is not an absolute path",
                                 path)
            path = normalize_path(path)

            if socket_owner is None:
                uid = os.getuid()
                if proc_uid is not None and proc_uid != uid:
                    socket_owner = (proc_uid, gid_for_uid(proc_uid))

            if socket_mode is None:
                socket_mode = 0o700

            return UnixStreamSocketConfig(path, owner=socket_owner,
                                                mode=socket_mode,
                                                backlog=socket_backlog)

        if socket_owner is not None or socket_mode is not None:
            raise ValueError("socket_owner and socket_mode params should"
                    + " only be used with a Unix domain socket")

        m = re.match(r'tcp://([^\s:]+):(\d+)$', sock)
        if m:
            host = m.group(1)
            port = int(m.group(2))
            return InetStreamSocketConfig(host, port,
                    backlog=socket_backlog)

        raise ValueError("Bad socket format %s", sock)

    def processes_from_section(self, parser, section, group_name,
                               klass=None):
        '''
        parser : configparse的实例
        section：'program:st'
        program_name：st
        ProcessConfig:类
        '''
        # 这样的设计风格，对外开放接口，实际功能是私有功能，主要用来收集错误
        try:
            return self._processes_from_section(
                parser, section, group_name, klass)
        except ValueError as e:
            filename = parser.section_to_file.get(section, self.configfile)
            raise ValueError('%s in section %r (file: %r)'
                             % (e, section, filename))

    def _processes_from_section(self, parser, section, group_name,
                                klass=None):
        '''
        parser : configparse的实例
        section：'program:st'
        program_name：st
        ProcessConfig:类
        '''
        if klass is None:
            klass = ProcessConfig
        programs = []
        # 这里直接使用program_name不就行了
        program_name = process_or_group_name(section.split(':', 1)[1])
        host_node_name = platform.node() # 主机名
        common_expansions = {'here':self.here,
                      'program_name':program_name,
                      'host_node_name':host_node_name,
                      'group_name':group_name}  #group_name st
        def get(section, opt, *args, **kwargs):
            expansions = kwargs.get('expansions', {})
            expansions.update(common_expansions)
            kwargs['expansions'] = expansions
            return parser.saneget(section, opt, *args, **kwargs)

        priority = integer(get(section, 'priority', 999))
        autostart = boolean(get(section, 'autostart', 'true'))  #如果是true的话，子进程将在supervisord启动后被自动启动
        # 这个是设置子进程挂掉后自动重启的情况，有三个选项，false,unexpected
        # 和true。如果为false的时候，无论什么情况下，都不会被重新启动，
        # 如果为unexpected，只有当进程的退出码不在下面的exitcodes里面定义的退
        # 出码的时候，才会被自动重启。当为true的时候，只要子进程挂掉，将会被无条件的重启
        autorestart = auto_restart(get(section, 'autorestart', 'unexpected'))
        #这个选项是子进程启动多少秒之后，此时状态如果是running，则我们认为启动成功了
        startsecs = integer(get(section, 'startsecs', 1))
        # 当进程启动失败后，最大尝试启动的次数。。当超过3次后，supervisor将把此进程的状态置为FAIL
        startretries = integer(get(section, 'startretries', 3))
        # 进程停止信号，可以为TERM, HUP, INT, QUIT, KILL, USR1, or USR2等信号默认为TERM 。
        # 。当用设定的信号去干掉进程，退出码会被认为是expected非必须设置(干掉后不重启）
        stopsignal = signal_number(get(section, 'stopsignal', 'TERM'))
        # 这个是当我们向子进程发送stopsignal信号后，到系统返回信息给supervisord，所等待的最大时间。 超过这个时间，
        # supervisord会向该子进程发送一个强制kill的信号。 默认为10秒。。非必须设置
        stopwaitsecs = integer(get(section, 'stopwaitsecs', 10))
        # 这个东西主要用于，supervisord管理的子进程，这个子进程本身还有
        # 子进程。那么我们如果仅仅干掉supervisord的子进程的话，子进程的子进程
        # 有可能会变成孤儿进程。所以咱们可以设置可个选项，把整个该子进程的
        # 整个进程组都干掉。 设置为true的话，一般killasgroup也会被设置为true。
        # 需要注意的是，该选项发送的是stop信号
        # 默认为false。。非必须设置。。
        stopasgroup = boolean(get(section, 'stopasgroup', 'false'))
        # 这个和上面的stopasgroup类似，不过发送的是kill信号
        killasgroup = boolean(get(section, 'killasgroup', stopasgroup))
        # 注意和上面的的autorestart=unexpected对应。。exitcodes里面的定义的退出码是expected的（即干掉不重启）
        exitcodes = list_of_exitcodes(get(section, 'exitcodes', '0'))
        # see also redirect_stderr check in process_groups_from_parser()
        redirect_stderr = boolean(get(section, 'redirect_stderr','false'))  #  如果为true，则stderr的日志会被写入stdout日志文件中
        numprocs = integer(get(section, 'numprocs', 1))  # 相同的进程启动的个数
        # 第一个进程num
        numprocs_start = integer(get(section, 'numprocs_start', 0))
        environment_str = get(section, 'environment', '', do_expand=False)
        # 设定capture管道的大小，当值不为0的时候，子进程可以从stdout发送信息，而supervisor可以根据信息，发送相应的event。
        stdout_cmaxbytes = byte_size(get(section,'stdout_capture_maxbytes','0'))
        #  当设置为ture的时候，当子进程由stdout向文件描述符中写日志的时候，将触发supervisord发送PROCESS_LOG_STDOUT类型的event
        stdout_events = boolean(get(section, 'stdout_events_enabled','false'))
        # 这个一样，和stdout_capture一样，这是这个是错误的管道。 默认为0，关闭状态
        stderr_cmaxbytes = byte_size(get(section,'stderr_capture_maxbytes','0'))
        # 同上
        stderr_events = boolean(get(section, 'stderr_events_enabled','false'))
        serverurl = get(section, 'serverurl', None)
        if serverurl and serverurl.strip().upper() == 'AUTO':
            serverurl = None

        # find uid from "user" option
        user = get(section, 'user', None)
        if user is None:
            uid = None
        else:
            uid = name_to_uid(user)

        umask = get(section, 'umask', None)
        if umask is not None:
            umask = octal_type(umask)

        process_name = process_or_group_name(
            get(section, 'process_name', '%(program_name)s', do_expand=False))
        # 当进程数大于1的时候，每一个process_name必须包含process_num
        if numprocs > 1:
            if not '%(process_num)' in process_name:
                # process_name needs to include process_num when we
                # represent a group of processes
                raise ValueError(
                    '%(process_num) must be present within process_name when '
                    'numprocs > 1')
        # 连同设置
        if stopasgroup and not killasgroup:
            raise ValueError(
                "Cannot set stopasgroup=true and killasgroup=false"
                )

        for process_num in range(numprocs_start, numprocs + numprocs_start):
            expansions = common_expansions
            expansions.update({'process_num': process_num})
            expansions.update(self.environ_expansions)
            environment = dict_of_key_value_pairs(
                expand(environment_str, expansions, 'environment'))
            directory = get(section, 'directory', None)
            logfiles = {}

            for k in ('stdout', 'stderr'):
                n = '%s_logfile' % k
                lf_val = get(section, n, Automatic)
                if isinstance(lf_val, basestring):
                    lf_val = expand(lf_val, expansions, n)
                lf_val = logfile_name(lf_val)
                logfiles[n] = lf_val

                bu_key = '%s_logfile_backups' % k
                backups = integer(get(section, bu_key, 10))
                logfiles[bu_key] = backups

                mb_key = '%s_logfile_maxbytes' % k
                maxbytes = byte_size(get(section, mb_key, '50MB'))
                logfiles[mb_key] = maxbytes

                sy_key = '%s_syslog' % k
                syslog = boolean(get(section, sy_key, False))
                logfiles[sy_key] = syslog

                if lf_val is Automatic and not maxbytes:
                    self.parse_warnings.append(
                        'For [%s], AUTO logging used for %s without '
                        'rollover, set maxbytes > 0 to avoid filling up '
                        'filesystem unintentionally' % (section, n))

            if redirect_stderr:
                if logfiles['stderr_logfile'] not in (Automatic, None):
                    self.parse_warnings.append(
                        'For [%s], redirect_stderr=true but stderr_logfile has '
                        'also been set to a filename, the filename has been '
                        'ignored' % section)
                # never create an stderr logfile when redirected
                logfiles['stderr_logfile'] = None

            command = get(section, 'command', None, expansions=expansions)
            if command is None:
                raise ValueError(
                    'program section %s does not specify a command' % section)
            pconfig = klass(
                self,
                name=expand(process_name, expansions, 'process_name'),
                command=command,
                directory=directory,
                umask=umask,
                priority=priority,
                autostart=autostart,
                autorestart=autorestart,
                startsecs=startsecs,
                startretries=startretries,
                uid=uid,
                stdout_logfile=logfiles['stdout_logfile'],
                stdout_capture_maxbytes = stdout_cmaxbytes,
                stdout_events_enabled = stdout_events,
                stdout_logfile_backups=logfiles['stdout_logfile_backups'],
                stdout_logfile_maxbytes=logfiles['stdout_logfile_maxbytes'],
                stdout_syslog=logfiles['stdout_syslog'],
                stderr_logfile=logfiles['stderr_logfile'],
                stderr_capture_maxbytes = stderr_cmaxbytes,
                stderr_events_enabled = stderr_events,
                stderr_logfile_backups=logfiles['stderr_logfile_backups'],
                stderr_logfile_maxbytes=logfiles['stderr_logfile_maxbytes'],
                stderr_syslog=logfiles['stderr_syslog'],
                stopsignal=stopsignal,
                stopwaitsecs=stopwaitsecs,
                stopasgroup=stopasgroup,
                killasgroup=killasgroup,
                exitcodes=exitcodes,
                redirect_stderr=redirect_stderr,
                environment=environment,
                serverurl=serverurl)

            programs.append(pconfig)
        programs.sort() # asc by priority
        return programs

    def _parse_servernames(self, parser, stype):
        options = []
        for section in parser.sections():
            if section.startswith(stype):
                parts = section.split(':', 1)
                if len(parts) > 1:
                    name = parts[1]
                else:
                    name = None # default sentinel
                options.append((name, section))
        return options

    def _parse_username_and_password(self, parser, section):
        get = parser.saneget
        username = get(section, 'username', None)
        password = get(section, 'password', None)
        if username is not None or password is not None:
            if username is None or password is None:
                raise ValueError(
                    'Section [%s] contains incomplete authentication: '
                    'If a username or a password is specified, both the '
                    'username and password must be specified' % section)
        return {'username':username, 'password':password}

    def server_configs_from_parser(self, parser):
        configs = []
        inet_serverdefs = self._parse_servernames(parser, 'inet_http_server')
        for name, section in inet_serverdefs:
            config = {}
            get = parser.saneget
            config.update(self._parse_username_and_password(parser, section))
            config['name'] = name
            config['family'] = socket.AF_INET
            port = get(section, 'port', None)
            if port is None:
                raise ValueError('section [%s] has no port value' % section)
            host, port = inet_address(port)
            config['host'] = host
            config['port'] = port
            config['section'] = section
            configs.append(config)

        unix_serverdefs = self._parse_servernames(parser, 'unix_http_server')
        for name, section in unix_serverdefs:
            config = {}
            get = parser.saneget
            sfile = get(section, 'file', None, expansions={'here': self.here})
            if sfile is None:
                raise ValueError('section [%s] has no file value' % section)
            sfile = sfile.strip()
            config['name'] = name
            config['family'] = socket.AF_UNIX
            config['file'] = normalize_path(sfile)
            config.update(self._parse_username_and_password(parser, section))
            chown = get(section, 'chown', None)
            if chown is not None:
                try:
                    chown = colon_separated_user_group(chown)
                except ValueError:
                    raise ValueError('Invalid sockchown value %s' % chown)
            else:
                chown = (-1, -1)
            config['chown'] = chown
            chmod = get(section, 'chmod', None)
            if chmod is not None:
                try:
                    chmod = octal_type(chmod)
                except (TypeError, ValueError):
                    raise ValueError('Invalid chmod value %s' % chmod)
            else:
                chmod = 0o700
            config['chmod'] = chmod
            config['section'] = section
            configs.append(config)

        return configs

    def daemonize(self):
        self.poller.before_daemonize()
        self._daemonize()
        self.poller.after_daemonize()

    def _daemonize(self):
        # To daemonize, we need to become the leader of our own session
        # (process) group.  If we do not, signals sent to our
        # parent process will also be sent to us.   This might be bad because
        # signals such as SIGINT can be sent to our parent process during
        # normal (uninteresting) operations such as when we press Ctrl-C in the
        # parent terminal window to escape from a logtail command.
        # To disassociate ourselves from our parent's session group we use
        # os.setsid.  It means "set session id", which has the effect of
        # disassociating a process from is current session and process group
        # and setting itself up as a new session leader.
        #
        # Unfortunately we cannot call setsid if we're already a session group
        # leader, so we use "fork" to make a copy of ourselves that is
        # guaranteed to not be a session group leader.
        #
        # We also change directories, set stderr and stdout to null, and
        # change our umask.
        #
        # This explanation was (gratefully) garnered from
        # http://www.cems.uwe.ac.uk/~irjohnso/coursenotes/lrc/system/daemons/d3.htm

        # 如果要实现后台运行，运行的进程需要称为进程组的注进程，发送给父进程的信号（终端shell），如ctrl-c的时候，也会发送给我们。通过
        # os.setsid,进程和父进程的会话分离。但是如果我们已经有session group leader，我们就不能使用os.setsid,所以我们使用fork
        # https://blog.csdn.net/snleo/article/details/4410305
        # 运行的时候，建立一个进程，linux会分配个进程号。然后调用os.fork()创建子进程。若pid>0就是自己，自杀。子进程跳过if语句，
        # 通过os.setsid()成为linux中的独立于终端的进程（不响应sigint，sighup等）。


        pid = os.fork()
        if pid != 0:
            # Parent 主进程
            self.logger.blather("supervisord forked; parent exiting")
            # 将主进程退出，子进程成为leader
            os._exit(0)
        # Child  子进程
        self.logger.info("daemonizing the supervisord process")
        if self.directory:
            try:
                os.chdir(self.directory)
            except OSError as err:
                self.logger.critical("can't chdir into %r: %s"
                                     % (self.directory, err))
            else:
                self.logger.info("set current directory: %r"
                                 % self.directory)
        os.close(0)
        self.stdin = sys.stdin = sys.__stdin__ = open("/dev/null")
        os.close(1)
        self.stdout = sys.stdout = sys.__stdout__ = open("/dev/null", "w")
        os.close(2)
        self.stderr = sys.stderr = sys.__stderr__ = open("/dev/null", "w")
        os.setsid()
        # 脱离终端进程后需要给该进程设置权限
        os.umask(self.umask)
        # XXX Stevens, in his Advanced Unix book, section 13.3 (page
        # 417) recommends calling umask(0) and closing unused
        # file descriptors.  In his Network Programming book, he
        # additionally recommends ignoring SIGHUP and forking again
        # after the setsid() call, for obscure SVR4 reasons.

    def write_pidfile(self):
        pid = os.getpid()
        try:
            with open(self.pidfile, 'w') as f:
                f.write('%s\n' % pid)
        except (IOError, OSError):
            self.logger.critical('could not write pidfile %s' % self.pidfile)
        else:
            self.unlink_pidfile = True
            self.logger.info('supervisord started with pid %s' % pid)

    def cleanup(self):
        for config, server in self.httpservers:
            if config['family'] == socket.AF_UNIX:
                if self.unlink_socketfiles:
                    socketname = config['file']
                    self._try_unlink(socketname)
        if self.unlink_pidfile:
            self._try_unlink(self.pidfile)
        self.poller.close()

    def _try_unlink(self, path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def close_httpservers(self):
        dispatcher_servers = []
        for config, server in self.httpservers:
            server.close()
            # server._map is a reference to the asyncore socket_map
            for dispatcher in self.get_socket_map().values():
                dispatcher_server = getattr(dispatcher, 'server', None)
                if dispatcher_server is server:
                    dispatcher_servers.append(dispatcher)
        for server in dispatcher_servers:
            # TODO: try to remove this entirely.
            # For unknown reasons, sometimes an http_channel
            # dispatcher in the socket map related to servers
            # remains open *during a reload*.  If one of these
            # exists at this point, we need to close it by hand
            # (thus removing it from the asyncore.socket_map).  If
            # we don't do this, 'cleanup_fds' will cause its file
            # descriptor to be closed, but it will still remain in
            # the socket_map, and eventually its file descriptor
            # will be passed to # select(), which will bomb.  See
            # also https://web.archive.org/web/20160729222427/http://www.plope.com/software/collector/253
            server.close()

    def close_logger(self):
        self.logger.close()

    def setsignals(self):
        receive = self.signal_receiver.receive
        signal.signal(signal.SIGTERM, receive)  # 终止信号,软件终止信号;
        signal.signal(signal.SIGINT, receive)   #终止进程(ctrl+c)
        signal.signal(signal.SIGQUIT, receive)  #终端退出
        signal.signal(signal.SIGHUP, receive)   #连接挂断
        signal.signal(signal.SIGCHLD, receive)  #进程终止或者停止时，将SIGCHLD信号发送给其父进程
        signal.signal(signal.SIGUSR2, receive)

    def get_signal(self):
        return self.signal_receiver.get_signal()
    # 这个superviosrd是Supervisord实例本身
    def openhttpservers(self, supervisord):
        try:
            # 这个self.httpservers虽然没有return，但是在后面起作用
            self.httpservers = self.make_http_servers(supervisord)
            # [({'username': None, 'name': None, 'family': 1, 'section': 'unix_http_server', 'chmod': 448, 'chown': (-1, -1),
            #    'file': '/tmp/supervisor.sock', 'password': None},
            #   < supervisor.http.supervisor_af_unix_http_server at 0x7fb0684bffc8 >)]
            self.unlink_socketfiles = True
        except socket.error as why:
            if why.args[0] == errno.EADDRINUSE:
                self.usage('Another program is already listening on '
                           'a port that one of our HTTP servers is '
                           'configured to use.  Shut this program '
                           'down first before starting supervisord.')
            else:
                help = 'Cannot open an HTTP server: socket.error reported'
                errorname = errno.errorcode.get(why.args[0])
                if errorname is None:
                    self.usage('%s %s' % (help, why.args[0]))
                else:
                    self.usage('%s errno.%s (%d)' %
                               (help, errorname, why.args[0]))
        except ValueError as why:
            self.usage(why.args[0])

    def get_autochildlog_name(self, name, identifier, channel):
        prefix='%s-%s---%s-' % (name, channel, identifier)
        logfile = self.mktempfile(
            suffix='.log',
            prefix=prefix,
            dir=self.childlogdir)
        return logfile

    def clear_autochildlogdir(self):
        # must be called after realize()
        childlogdir = self.childlogdir
        fnre = re.compile(r'.+?---%s-\S+\.log\.{0,1}\d{0,4}' % self.identifier)
        try:
            filenames = os.listdir(childlogdir)
        except (IOError, OSError):
            self.logger.warn('Could not clear childlog dir')
            return

        for filename in filenames:
            if fnre.match(filename):
                pathname = os.path.join(childlogdir, filename)
                try:
                    self.remove(pathname)
                except (OSError, IOError):
                    self.logger.warn('Failed to clean up %r' % pathname)

    def get_socket_map(self):
        return asyncore.socket_map

    def cleanup_fds(self):
        # try to close any leaked file descriptors (for reload)尝试关闭任何泄漏的文件描述符(用于重新加载)  self.minfds = 1024
        start = 5
        for x in range(start, self.minfds):
            try:
                os.close(x)
            except OSError:
                pass

    def kill(self, pid, signal):
        # signal 是kill方式，kill -9
        os.kill(pid, signal)

    def waitpid(self):
        # Need pthread_sigmask here to avoid concurrent sigchld, but Python
        # doesn't offer in Python < 3.4.  There is still a race condition here;
        # we can get a sigchld while we're sitting in the waitpid call.
        # However, AFAICT, if waitpid is interrupted by SIGCHLD, as long as we
        # call waitpid again (which happens every so often during the normal
        # course in the mainloop), we'll eventually reap the child that we
        # tried to reap during the interrupted call. At least on Linux, this
        # appears to be true, or at least stopping 50 processes at once never
        # left zombies laying around.
        try:
            pid, sts = os.waitpid(-1, os.WNOHANG)
        except OSError as exc:
            code = exc.args[0]
            if code not in (errno.ECHILD, errno.EINTR):
                self.logger.critical(
                    'waitpid error %r; '
                    'a process may not be cleaned up properly' % code
                    )
            if code == errno.EINTR:
                self.logger.blather('EINTR during reap')
            pid, sts = None, None
        return pid, sts

    def drop_privileges(self, user):
        """Drop privileges to become the specified user, which may be a
        username or uid.  Called for supervisord startup and when spawning
        subprocesses.  Returns None on success or a string error message if
        privileges could not be dropped."""
        if user is None:
            return "No user specified to setuid to!"

        # get uid for user, which can be a number or username
        # 先看uid是否错误

        try:
            uid = int(user)
        except ValueError:
            try:
                '''
                >>> pwd.getpwnam('root')
                pwd.struct_passwd(pw_name='root', pw_passwd='x', pw_uid=0, pw_gid=0, pw_gecos='root', pw_dir='/root', pw_shell='/bin/bash')
                >>> pwd.getpwnam('sunjian')
                pwd.struct_passwd(pw_name='sunjian', pw_passwd='x', pw_uid=1000, pw_gid=1000, pw_gecos='sunjian,,,', pw_dir='/home/sunjian', pw_shell='/bin/bash')
                '''
                pwrec = pwd.getpwnam(user)
            except KeyError:
                return "Can't find username %r" % user
            uid = pwrec[2]
        else:
            try:
                pwrec = pwd.getpwuid(uid)
            except KeyError:
                return "Can't find uid %r" % uid

        current_uid = os.getuid()
        # 如果现在的uid和传入的相同，返回空值
        if current_uid == uid:
            # do nothing and return successfully if the uid is already the
            # current one.  this allows a supervisord running as an
            # unprivileged user "foo" to start a process where the config
            # has "user=foo" (same user) in it.
            return

        if current_uid != 0:
            return "Can't drop privilege as nonroot user"

        gid = pwrec[3]
        # 只有root用户才可以设置该非当前进程的uid和gid
        if hasattr(os, 'setgroups'):
            user = pwrec[0]
            # grp.getgrall() 组的信息
            groups = [grprec[2] for grprec in grp.getgrall() if user in
                      grprec[3]]

            # always put our primary gid first in this list, otherwise we can
            # lose group info since sometimes the first group in the setgroups
            # list gets overwritten on the subsequent setgid call (at least on
            # freebsd 9 with python 2.7 - this will be safe though for all unix
            # /python version combos)
            # 将主gid放到groups最前面，因为放到后面可能会被覆盖而失去信息（至少对freebsd是这样的）
            groups.insert(0, gid)
            try:
                # 重新设置组信息
                os.setgroups(groups)
            except OSError:
                return 'Could not set groups of effective user'
        try:
            os.setgid(gid)
        except OSError:
            return 'Could not set group id of effective user'
        # 设置当前进程的真实用户id，只有root用户，执行文件，才可以与这个权限（root下的命令行不可以）
        os.setuid(uid)

    def set_uid_or_exit(self):
        """
        设置用户相关的提示信息
        Set the uid of the supervisord process.  Called during supervisord
        startup only.  No return value.  Exits the process via usage() if
        privileges could not be dropped.
        设置supervisord进程的uid。只在开始的时候被调用。没有返回值。通过usage() if退出进程
        Exits the process via usage() if
        privileges could not be dropped

        """
        if self.uid is None:
            # 安装系统的用户os.getuid() = 1000，之后的网上加。在root用户中，os.getuid() =0
            if os.getuid() == 0:
                # 提示如果想用root用户，设置user为root
                self.parse_criticals.append('Supervisor is running as root.  '
                        'Privileges were not dropped because no user is '
                        'specified in the config file.  If you intend to run '
                        'as root, you can set user=root in the config file '
                        'to avoid this message.')
        else:
            # 关闭特权
            msg = self.drop_privileges(self.uid)
            # print(msg)
            if msg is None:
                self.parse_infos.append('Set uid to user %s succeeded' %
                                        self.uid)
            else:  # failed to drop privileges
                # 这种打印最后的日志后退出的方法真的好用
                self.usage(msg)

    def set_rlimits_or_exit(self):
        """
        设置 文件描述符的限制
        Set the rlimits of the supervisord process.  Called during
        supervisord startup only.  No return value.  Exits the process via
        usage() if any rlimits could not be set."""
        limits = []
        # https://docs.python.org/3.6/library/resource.html
        # print(resource.__dict__)
        # 这是一些系统限制，我也不懂
        # resource.__dict__
        #'RUSAGE_CHILDREN': -1,
        # 'RLIM_INFINITY': -1, 常数，用于表示无限资源的极限。
        # 'RLIMIT_MEMLOCK': 8,
        # 'RLIMIT_NOFILE': 7,
        # 'RLIMIT_CPU': 0,
        # 'struct_rusage': <type 'resource.struct_rusage'>,
        # '__package__': None,
        # 'RLIMIT_DATA': 2,
        # 'RLIMIT_OFILE': 7,
        # 'RLIMIT_STACK': 3,
        # 'getrlimit': <built-in function getrlimit>,
        # '__doc__': None,
        # 'setrlimit': <built-in function setrlimit>,
        # 'getpagesize': <built-in function getpagesize>,
        # '__file__': '/usr/lib/python2.7/lib-dynload/resource.x86_64-linux-gnu.so',
        # 'RLIMIT_FSIZE': 1,
        # 'RLIMIT_CORE': 4,
        # 'RLIMIT_NPROC': 6,
        # 'RLIMIT_AS': 9,
        # '__name__': 'resource',
        # 'RUSAGE_SELF': 0,
        # 'RLIMIT_RSS': 5,
        # 'getrusage': <built-in function getrusage>,
        # 'error': <class 'resource.error'>}

        # 能打开的最大文件数
        if hasattr(resource, 'RLIMIT_NOFILE'):
            # 存在
            limits.append(
                {
                'msg':('The minimum number of file descriptors required '
                       'to run this process is %(min_limit)s as per the "minfds" '
                       'command-line argument or config file setting. '
                       'The current environment will only allow you '
                       'to open %(hard)s file descriptors.  Either raise '
                       'the number of usable file descriptors in your '
                       'environment (see README.rst) or lower the '
                       'minfds setting in the config file to allow '
                       'the process to start.'),
                'min':self.minfds,
                'resource':resource.RLIMIT_NOFILE,  #7
                'name':'RLIMIT_NOFILE',
                })
        #  每个用户id可拥有的最大进程数
        if hasattr(resource, 'RLIMIT_NPROC'):
            # 存在
            limits.append(
                {
                'msg':('The minimum number of available processes required '
                       'to run this program is %(min_limit)s as per the "minprocs" '
                       'command-line argument or config file setting. '
                       'The current environment will only allow you '
                       'to open %(hard)s processes.  Either raise '
                       'the number of usable processes in your '
                       'environment (see README.rst) or lower the '
                       'minprocs setting in the config file to allow '
                       'the program to start.'),
                'min':self.minprocs,
                'resource':resource.RLIMIT_NPROC, #6
                'name':'RLIMIT_NPROC',
                })
        for limit in limits:
            min_limit = limit['min']
            res = limit['resource']
            msg = limit['msg']
            name = limit['name']
            name = name # name is used below by locals()
            # Returns a tuple (soft, hard) with the current soft and hard limits of resource
            soft, hard = resource.getrlimit(res)
            #print(soft,hard)   (1024, 1048576)   (7644, 7644)
            if (soft < min_limit) and (soft != -1): # -1 means unlimited
                if (hard < min_limit) and (hard != -1):
                    # setrlimit should increase the hard limit if we are
                    # 如果硬限制小于配置文件中的最小限制，需要将配置文件最小限制设置为硬限制，这个需要root权限
                    # root, if not then setrlimit raises and we print usage
                    hard = min_limit
                try:
                    # 重新设置该进程的资源软限制和硬限制
                    resource.setrlimit(res, (min_limit, hard))
                    self.parse_infos.append('Increased %(name)s limit to '
                                '%(min_limit)s' % locals())
                except (resource.error, ValueError):
                    self.usage(msg % locals())

    def make_logger(self):
        self.parse_criticals.append('i am bigblackface')
        # must be called after realize() and after supervisor does setuid()
        format = '%(asctime)s %(levelname)s %(message)s\n'
        self.logger = loggers.getLogger(self.loglevel)

        if self.nodaemon:
            loggers.handle_stdout(self.logger, format)
        # 这种将实例作为函数的参数，在函数过程中调用实例的方法，在代码中随处可见，这种强烈的个人风格并不利于阅读
        loggers.handle_file(
            self.logger,
            self.logfile,
            format,
            rotating=not not self.logfile_maxbytes,
            maxbytes=self.logfile_maxbytes,
            backups=self.logfile_backups,
        )
        # 这个10天一次回卷，6-7M一次回卷是很具有参考意义的
        # print(self.logfile_maxbytes,self.logfile_backups)
        for msg in self.parse_criticals:
            self.logger.critical(msg)
        for msg in self.parse_warnings:
            self.logger.warn(msg)
        for msg in self.parse_infos:
            self.logger.info(msg)

    def make_http_servers(self, supervisord):
        # 这个项目到处是这样的功能性接口，就是在类方法里面调用外部方法
        from supervisor.http import make_http_servers
        # [({'username': None, 'name': None, 'family': 1, 'section': 'unix_http_server', 'chmod': 448, 'chown': (-1, -1),
        #    'file': '/tmp/supervisor.sock', 'password': None},
        #   < supervisor.http.supervisor_af_unix_http_server at 0x7fb0684bffc8 >)]
        return make_http_servers(self, supervisord)

    def close_fd(self, fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def fork(self):
        return os.fork()

    def dup2(self, frm, to):
        return os.dup2(frm, to)

    def setpgrp(self):
        return os.setpgrp()

    def stat(self, filename):
        return os.stat(filename)

    def write(self, fd, data):
        return os.write(fd, as_bytes(data))

    def execve(self, filename, argv, env):
        return os.execve(filename, argv, env)

    def mktempfile(self, suffix, prefix, dir):
        # set os._urandomfd as a hack around bad file descriptor bug
        # seen in the wild, see
        # https://web.archive.org/web/20160729044005/http://www.plope.com/software/collector/252
        os._urandomfd = None
        fd, filename = tempfile.mkstemp(suffix, prefix, dir)
        os.close(fd)
        return filename

    def remove(self, path):
        os.remove(path)

    def _exit(self, code):
        os._exit(code)

    def setumask(self, mask):
        os.umask(mask)

    def get_path(self):
        """Return a list corresponding to $PATH, or a default."""
        path = ["/bin", "/usr/bin", "/usr/local/bin"]
        if "PATH" in os.environ:
            p = os.environ["PATH"]
            if p:
                path = p.split(os.pathsep)
        return path

    def get_pid(self):
        return os.getpid()

    def check_execv_args(self, filename, argv, st):
        if st is None:
            raise NotFound("can't find command %r" % filename)

        elif stat.S_ISDIR(st[stat.ST_MODE]):
            raise NotExecutable("command at %r is a directory" % filename)

        elif not (stat.S_IMODE(st[stat.ST_MODE]) & 0o111):
            raise NotExecutable("command at %r is not executable" % filename)

        elif not os.access(filename, os.X_OK):
            raise NoPermission("no permission to run command %r" % filename)

    def reopenlogs(self):
        self.logger.info('supervisord logreopen')
        for handler in self.logger.handlers:
            if hasattr(handler, 'reopen'):
                handler.reopen()

    def readfd(self, fd):
        try:
            data = os.read(fd, 2 << 16) # 128K
        except OSError as why:
            if why.args[0] not in (errno.EWOULDBLOCK, errno.EBADF, errno.EINTR):
                raise
            data = b''
        return data

    def process_environment(self):
        os.environ.update(self.environment or {})

    def chdir(self, dir):
        os.chdir(dir)

    def make_pipes(self, stderr=True):
        """ Create pipes for parent to child stdin/stdout/stderr
        communications.  Open fd in non-blocking mode so we can read them
        in the mainloop without blocking.  If stderr is False, don't
        create a pipe for stderr. """

        pipes = {'child_stdin':None,
                 'stdin':None,
                 'stdout':None,
                 'child_stdout':None,
                 'stderr':None,
                 'child_stderr':None}
        try:
            stdin, child_stdin = os.pipe()
            pipes['child_stdin'], pipes['stdin'] = stdin, child_stdin
            stdout, child_stdout = os.pipe()
            pipes['stdout'], pipes['child_stdout'] = stdout, child_stdout
            if stderr:
                stderr, child_stderr = os.pipe()
                pipes['stderr'], pipes['child_stderr'] = stderr, child_stderr
            for fd in (pipes['stdout'], pipes['stderr'], pipes['stdin']):
                if fd is not None:
                    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NDELAY
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags)
            return pipes
        except OSError:
            for fd in pipes.values():
                if fd is not None:
                    self.close_fd(fd)
            raise

    def close_parent_pipes(self, pipes):
        for fdname in ('stdin', 'stdout', 'stderr'):
            fd = pipes.get(fdname)
            if fd is not None:
                self.close_fd(fd)

    def close_child_pipes(self, pipes):
        for fdname in ('child_stdin', 'child_stdout', 'child_stderr'):
            fd = pipes.get(fdname)
            if fd is not None:
                self.close_fd(fd)

class ClientOptions(Options):
    positional_args_allowed = 1

    interactive = None
    prompt = None
    serverurl = None
    username = None
    password = None
    history_file = None

    def __init__(self):
        Options.__init__(self, require_configfile=False)
        self.configroot = Dummy()
        self.configroot.supervisorctl = Dummy()
        self.configroot.supervisorctl.interactive = None
        self.configroot.supervisorctl.prompt = 'supervisor'
        self.configroot.supervisorctl.serverurl = None
        self.configroot.supervisorctl.username = None
        self.configroot.supervisorctl.password = None
        self.configroot.supervisorctl.history_file = None

        from supervisor.supervisorctl import DefaultControllerPlugin
        default_factory = ('default', DefaultControllerPlugin, {})
        # we always add the default factory. If you want to a supervisorctl
        # without the default plugin, please write your own supervisorctl.
        self.plugin_factories = [default_factory]

        self.add("interactive", "supervisorctl.interactive", "i",
                 "interactive", flag=1, default=0)
        self.add("prompt", "supervisorctl.prompt", default="supervisor")
        self.add("serverurl", "supervisorctl.serverurl", "s:", "serverurl=",
                 url, default="http://localhost:9001")
        self.add("username", "supervisorctl.username", "u:", "username=")
        self.add("password", "supervisorctl.password", "p:", "password=")
        self.add("history", "supervisorctl.history_file", "r:", "history_file=")

    def realize(self, *arg, **kw):
        Options.realize(self, *arg, **kw)
        if not self.args:
            self.interactive = 1

    def read_config(self, fp):
        section = self.configroot.supervisorctl
        need_close = False
        if not hasattr(fp, 'read'):
            self.here = os.path.dirname(normalize_path(fp))
            if not self.exists(fp):
                raise ValueError("could not find config file %s" % fp)
            try:
                fp = self.open(fp, 'r')
                need_close = True
            except (IOError, OSError):
                raise ValueError("could not read config file %s" % fp)

        parser = UnhosedConfigParser()
        parser.expansions = self.environ_expansions
        parser.mysection = 'supervisorctl'
        try:
            parser.read_file(fp)
        except AttributeError:
            parser.readfp(fp)
        if need_close:
            fp.close()
        sections = parser.sections()
        if not 'supervisorctl' in sections:
            raise ValueError('.ini file does not include supervisorctl section')
        serverurl = parser.getdefault('serverurl', 'http://localhost:9001',
            expansions={'here': self.here})
        if serverurl.startswith('unix://'):
            path = normalize_path(serverurl[7:])
            serverurl = 'unix://%s' % path
        section.serverurl = serverurl

        # The defaults used below are really set in __init__ (since
        # section==self.configroot.supervisorctl)
        section.prompt = parser.getdefault('prompt', section.prompt)
        section.username = parser.getdefault('username', section.username)
        section.password = parser.getdefault('password', section.password)
        history_file = parser.getdefault('history_file', section.history_file,
            expansions={'here': self.here})

        if history_file:
            history_file = normalize_path(history_file)
            section.history_file = history_file
            self.history_file = history_file
        else:
            section.history_file = None
            self.history_file = None

        self.plugin_factories += self.get_plugins(
            parser,
            'supervisor.ctl_factory',
            'ctlplugin:'
            )

        return section

    # TODO: not covered by any test, but used by supervisorctl
    def getServerProxy(self):
        # 客户端的prc接口，使用自己重写的传输
        return xmlrpclib.ServerProxy(
            # dumbass ServerProxy won't allow us to pass in a non-HTTP url,
            # so we fake the url we pass into it and always use the transport's
            # 'serverurl' to figure out what to attach to
            'http://127.0.0.1',
            transport = xmlrpc.SupervisorTransport(self.username,
                                                   self.password,
                                                   self.serverurl)
            )

_marker = []

class UnhosedConfigParser(ConfigParser.RawConfigParser):
    mysection = 'supervisord'

    def __init__(self, *args, **kwargs):
        # inline_comment_prefixes and strict were added in Python 3 but their
        # defaults make RawConfigParser behave differently than it did on
        # Python 2.  We make it work like 2 by default for backwards compat.
        if not PY2:
            if 'inline_comment_prefixes' not in kwargs:
                # 内联注释前缀
                kwargs['inline_comment_prefixes'] = (';', '#')

            if 'strict' not in kwargs:
                kwargs['strict'] = False

        ConfigParser.RawConfigParser.__init__(self, *args, **kwargs)

        self.section_to_file = {}
        self.expansions = {}

    def read_string(self, string, source='<string>'):
        '''Parse configuration data from a string.  This is intended
        to be used in tests only.  We add this method for Py 2/3 compat.'''
        try:
            return ConfigParser.RawConfigParser.read_string(
                self, string, source) # Python 3.2 or later
        except AttributeError:
            return self.readfp(StringIO(string))

    def read(self, filenames, **kwargs):
        '''Attempt to read and parse a list of filenames, returning a list
        of filenames which were successfully parsed.  This is a method of
        RawConfigParser that is overridden to build self.section_to_file,
        which is a mapping of section names to the files they came from.
        '''
        if isinstance(filenames, basestring):  # RawConfigParser compat
            filenames = [filenames]

        ok_filenames = []
        for filename in filenames:
            sections_orig = self._sections.copy()

            ok_filenames.extend(
                ConfigParser.RawConfigParser.read(self, [filename], **kwargs))

            diff = frozenset(self._sections) - frozenset(sections_orig)
            for section in diff:
                self.section_to_file[section] = filename
        return ok_filenames

    def saneget(self, section, option, default=_marker, do_expand=True,
                expansions={}):
        try:
            optval = self.get(section, option)
        except ConfigParser.NoOptionError:
            if default is _marker:
                raise
            else:
                optval = default

        if do_expand and isinstance(optval, basestring):
            combined_expansions = dict(
                list(self.expansions.items()) + list(expansions.items()))

            optval = expand(optval, combined_expansions,
                           "%s.%s" % (section, option))

        return optval

    def getdefault(self, option, default=_marker, expansions={}, **kwargs):
        return self.saneget(self.mysection, option, default=default,
                            expansions=expansions, **kwargs)

    def expand_here(self, here):
        # 这是啥
        HERE_FORMAT = '%(here)s'

        for section in self.sections():
            for key, value in self.items(section):
                if HERE_FORMAT in value:
                    assert here is not None, "here has not been set to a path"
                    value = value.replace(HERE_FORMAT, here)
                    self.set(section, key, value)


class Config(object):
    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        if self.priority == other.priority:
            return self.name < other.name

        return self.priority < other.priority

    def __le__(self, other):
        if self.priority == other.priority:
            return self.name <= other.name

        return self.priority <= other.priority

    def __gt__(self, other):
        if self.priority == other.priority:
            return self.name > other.name

        return self.priority > other.priority

    def __ge__(self, other):
        if self.priority == other.priority:
            return self.name >= other.name

        return self.priority >= other.priority

    def __repr__(self):
        return '<%s instance at %s named %s>' % (self.__class__, id(self),
                                                 self.name)

class ProcessConfig(Config):
    # 这个类是核心的类，进程所有相关的配置都在里面
    req_param_names = [
        'name', 'uid', 'command', 'directory', 'umask', 'priority',
        'autostart', 'autorestart', 'startsecs', 'startretries',
        'stdout_logfile', 'stdout_capture_maxbytes',
        'stdout_events_enabled', 'stdout_syslog',
        'stdout_logfile_backups', 'stdout_logfile_maxbytes',
        'stderr_logfile', 'stderr_capture_maxbytes',
        'stderr_logfile_backups', 'stderr_logfile_maxbytes',
        'stderr_events_enabled', 'stderr_syslog',
        'stopsignal', 'stopwaitsecs', 'stopasgroup', 'killasgroup',
        'exitcodes', 'redirect_stderr' ]
    optional_param_names = [ 'environment', 'serverurl' ]

    def __init__(self, options, **params):
        # 每个类都绑定options实例，导致耦合性特别高
        self.options = options
        # 批量设置属性，这个不错
        for name in self.req_param_names:
            setattr(self, name, params[name])
        for name in self.optional_param_names:
            setattr(self, name, params.get(name, None))

    def __eq__(self, other):
        if not isinstance(other, ProcessConfig):
            return False

        for name in self.req_param_names + self.optional_param_names:
            if Automatic in [getattr(self, name), getattr(other, name)] :
                continue
            if getattr(self, name) != getattr(other, name):
                return False

        return True

    def get_path(self):
        '''Return a list corresponding to $PATH that is configured to be set
        in the process environment, or the system default.'''
        if self.environment is not None:
            path = self.environment.get('PATH')
            if path is not None:
                return path.split(os.pathsep)
        return self.options.get_path()

    def create_autochildlogs(self):
        # temporary logfiles which are erased at start time
        get_autoname = self.options.get_autochildlog_name
        sid = self.options.identifier
        name = self.name
        if self.stdout_logfile is Automatic:
            self.stdout_logfile = get_autoname(name, sid, 'stdout')
        if self.stderr_logfile is Automatic:
            self.stderr_logfile = get_autoname(name, sid, 'stderr')

    def make_process(self, group=None):
        # 创建进程，这个是核心
        from supervisor.process import Subprocess
        process = Subprocess(self)
        process.group = group
        return process

    # 创建调度程序
    def make_dispatchers(self, proc):
        use_stderr = not self.redirect_stderr
        p = self.options.make_pipes(use_stderr)
        stdout_fd,stderr_fd,stdin_fd = p['stdout'],p['stderr'],p['stdin']
        dispatchers = {}
        from supervisor.dispatchers import POutputDispatcher
        from supervisor.dispatchers import PInputDispatcher
        from supervisor import events
        if stdout_fd is not None:
            etype = events.ProcessCommunicationStdoutEvent
            dispatchers[stdout_fd] = POutputDispatcher(proc, etype, stdout_fd)
        if stderr_fd is not None:
            etype = events.ProcessCommunicationStderrEvent
            dispatchers[stderr_fd] = POutputDispatcher(proc,etype, stderr_fd)
        if stdin_fd is not None:
            dispatchers[stdin_fd] = PInputDispatcher(proc, 'stdin', stdin_fd)
        return dispatchers, p

class EventListenerConfig(ProcessConfig):
    def make_dispatchers(self, proc):
        # always use_stderr=True for eventlisteners because mixing stderr
        # messages into stdout would break the eventlistener protocol
        use_stderr = True
        p = self.options.make_pipes(use_stderr)
        stdout_fd,stderr_fd,stdin_fd = p['stdout'],p['stderr'],p['stdin']
        dispatchers = {}
        from supervisor.dispatchers import PEventListenerDispatcher
        from supervisor.dispatchers import PInputDispatcher
        from supervisor.dispatchers import POutputDispatcher
        from supervisor import events
        if stdout_fd is not None:
            dispatchers[stdout_fd] = PEventListenerDispatcher(proc, 'stdout',
                                                              stdout_fd)
        if stderr_fd is not None:
            etype = events.ProcessCommunicationStderrEvent
            dispatchers[stderr_fd] = POutputDispatcher(proc, etype, stderr_fd)
        if stdin_fd is not None:
            dispatchers[stdin_fd] = PInputDispatcher(proc, 'stdin', stdin_fd)
        return dispatchers, p

class FastCGIProcessConfig(ProcessConfig):

    def make_process(self, group=None):
        if group is None:
            raise NotImplementedError('FastCGI programs require a group')
        from supervisor.process import FastCGISubprocess
        process = FastCGISubprocess(self)
        process.group = group
        return process

    def make_dispatchers(self, proc):
        dispatchers, p = ProcessConfig.make_dispatchers(self, proc)
        #FastCGI child processes expect the FastCGI socket set to
        #file descriptor 0, so supervisord cannot use stdin
        #to communicate with the child process
        stdin_fd = p['stdin']
        if stdin_fd is not None:
            dispatchers[stdin_fd].close()
        return dispatchers, p

class ProcessGroupConfig(Config):
    def __init__(self, options, name, priority, process_configs):
        '''
        :param options:
        :param name:
        :param priority:
        :param process_configs:ProcessConfig组成的list
        '''
        self.options = options
        self.name = name
        self.priority = priority
        self.process_configs = process_configs

    def __eq__(self, other):
        if not isinstance(other, ProcessGroupConfig):
            return False

        if self.name != other.name:
            return False
        if self.priority != other.priority:
            return False
        if self.process_configs != other.process_configs:
            return False

        return True

    def after_setuid(self):
        for config in self.process_configs:
            config.create_autochildlogs()

    def make_group(self):
        # 将自己作为参数创建实例真是太变态了，在新的类里，将自己作为参数，再调用自己的方法复制给新实例的属性，我佛了
        from supervisor.process import ProcessGroup
        return ProcessGroup(self)

class EventListenerPoolConfig(Config):
    def __init__(self, options, name, priority, process_configs, buffer_size,
                 pool_events, result_handler):
        self.options = options
        self.name = name
        self.priority = priority
        self.process_configs = process_configs
        self.buffer_size = buffer_size
        self.pool_events = pool_events
        self.result_handler = result_handler

    def __eq__(self, other):
        if not isinstance(other, EventListenerPoolConfig):
            return False

        if ((self.name == other.name) and
            (self.priority == other.priority) and
            (self.process_configs == other.process_configs) and
            (self.buffer_size == other.buffer_size) and
            (self.pool_events == other.pool_events) and
            (self.result_handler == other.result_handler)):
            return True

        return False

    def after_setuid(self):
        for config in self.process_configs:
            config.create_autochildlogs()

    def make_group(self):
        from supervisor.process import EventListenerPool
        return EventListenerPool(self)

class FastCGIGroupConfig(ProcessGroupConfig):
    def __init__(self, options, name, priority, process_configs, socket_config):
        ProcessGroupConfig.__init__(
            self,
            options,
            name,
            priority,
            process_configs,
            )
        self.socket_config = socket_config

    def __eq__(self, other):
        if not isinstance(other, FastCGIGroupConfig):
            return False

        if self.socket_config != other.socket_config:
            return False

        return ProcessGroupConfig.__eq__(self, other)

    def make_group(self):
        from supervisor.process import FastCGIProcessGroup
        return FastCGIProcessGroup(self)

def readFile(filename, offset, length):
    """ Read length bytes from the file named by filename starting at
    offset """

    absoffset = abs(offset)
    abslength = abs(length)

    try:
        with open(filename, 'rb') as f:
            if absoffset != offset:
                # negative offset returns offset bytes from tail of the file
                if length:
                    raise ValueError('BAD_ARGUMENTS')
                f.seek(0, 2)
                sz = f.tell()
                pos = int(sz - absoffset)
                if pos < 0:
                    pos = 0
                f.seek(pos)
                data = f.read(absoffset)
            else:
                if abslength != length:
                    raise ValueError('BAD_ARGUMENTS')
                if length == 0:
                    f.seek(offset)
                    data = f.read()
                else:
                    f.seek(offset)
                    data = f.read(length)
    except (OSError, IOError):
        raise ValueError('FAILED')

    return data

def tailFile(filename, offset, length):
    """
    Read length bytes from the file named by filename starting at
    offset, automatically increasing offset and setting overflow
    flag if log size has grown beyond (offset + length).  If length
    bytes are not available, as many bytes as are available are returned.
    """

    try:
        with open(filename, 'rb') as f:
            overflow = False
            f.seek(0, 2)
            sz = f.tell()

            if sz > (offset + length):
                overflow = True
                offset = sz - 1

            if (offset + length) > sz:
                if offset > (sz - 1):
                    length = 0
                offset = sz - length

            if offset < 0:
                offset = 0
            if length < 0:
                length = 0

            if length == 0:
                data = b''
            else:
                f.seek(offset)
                data = f.read(length)

            offset = sz
            return [as_string(data), offset, overflow]
    except (OSError, IOError):
        return ['', offset, False]

# Helpers for dealing with signals and exit status

def decode_wait_status(sts):
    """Decode the status returned by wait() or waitpid().

    Return a tuple (exitstatus, message) where exitstatus is the exit
    status, or -1 if the process was killed by a signal; and message
    is a message telling what happened.  It is the caller's
    responsibility to display the message.
    """
    if os.WIFEXITED(sts):
        es = os.WEXITSTATUS(sts) & 0xffff
        msg = "exit status %s" % es
        return es, msg
    elif os.WIFSIGNALED(sts):
        sig = os.WTERMSIG(sts)
        msg = "terminated by %s" % signame(sig)
        if hasattr(os, "WCOREDUMP"):
            iscore = os.WCOREDUMP(sts)
        else:
            iscore = sts & 0x80
        if iscore:
            msg += " (core dumped)"
        return -1, msg
    else:
        msg = "unknown termination cause 0x%04x" % sts
        return -1, msg

_signames = None

def signame(sig):
    """Return a symbolic name for a signal.

    Return "signal NNN" if there is no corresponding SIG name in the
    signal module.
    """

    if _signames is None:
        _init_signames()
    return _signames.get(sig) or "signal %d" % sig

def _init_signames():
    global _signames
    d = {}
    for k, v in signal.__dict__.items():
        k_startswith = getattr(k, "startswith", None)
        if k_startswith is None:
            continue
        if k_startswith("SIG") and not k_startswith("SIG_"):
            d[v] = k
    _signames = d

class SignalReceiver:
    def __init__(self):
        self._signals_recvd = []

    def receive(self, sig, frame):
        # 信号量不能重复？
        # 应该是这样，比如已给关闭信号重复两次没有什么意义
        if sig not in self._signals_recvd:
            self._signals_recvd.append(sig)
            # print('add sig:',sig)

    def get_signal(self):
        if self._signals_recvd:
            sig = self._signals_recvd.pop(0)
        else:
            sig = None
        # print('get sig:', sig)
        return sig

# miscellaneous utility functions

def expand(s, expansions, name):
    # 不知道 % 是啥意思
    try:
        return s % expansions
    except KeyError as ex:
        available = list(expansions.keys())
        available.sort()
        raise ValueError(
            'Format string %r for %r contains names (%s) which cannot be '
            'expanded. Available names: %s' %
            (s, name, str(ex), ", ".join(available)))
    except Exception as ex:
        raise ValueError(
            'Format string %r for %r is badly formatted: %s' %
            (s, name, str(ex))
        )

def make_namespec(group_name, process_name):
    # we want to refer to the process by its "short name" (a process named
    # process1 in the group process1 has a name "process1").  This is for
    # backwards compatibility
    if group_name == process_name:
        name = process_name
    else:
        name = '%s:%s' % (group_name, process_name)
    return name

def split_namespec(namespec):
    names = namespec.split(':', 1)
    if len(names) == 2:
        # group and process name differ
        group_name, process_name = names
        if not process_name or process_name == '*':
            process_name = None
    else:
        # group name is same as process name
        group_name, process_name = namespec, namespec
    return group_name, process_name

# exceptions

class ProcessException(Exception):
    """ Specialized exceptions used when attempting to start a process """

class BadCommand(ProcessException):
    """ Indicates the command could not be parsed properly. """

class NotExecutable(ProcessException):
    """ Indicates that the filespec cannot be executed because its path
    resolves to a file which is not executable, or which is a directory. """

class NotFound(ProcessException):
    """ Indicates that the filespec cannot be executed because it could not
    be found """

class NoPermission(ProcessException):
    """ Indicates that the file cannot be executed because the supervisor
    process does not possess the appropriate UNIX filesystem permission
    to execute the file. """
