# -*- coding: utf-8 -*-
#!/usr/bin/env python

"""supervisord -- run a set of applications as daemons.

Usage: %s [options]

Options:
-c/--configuration FILENAME -- configuration file path (searches if not given)
-n/--nodaemon -- run in the foreground (same as 'nodaemon=true' in config file)
-h/--help -- print this usage message and exit
-v/--version -- print supervisord version number and exit
-u/--user USER -- run supervisord as this user (or numeric uid)
-m/--umask UMASK -- use this umask for daemon subprocess (default is 022)
-d/--directory DIRECTORY -- directory to chdir to when daemonized
-l/--logfile FILENAME -- use FILENAME as logfile path
-y/--logfile_maxbytes BYTES -- use BYTES to limit the max size of logfile
-z/--logfile_backups NUM -- number of backups to keep when max bytes reached
-e/--loglevel LEVEL -- use LEVEL as log level (debug,info,warn,error,critical)
-j/--pidfile FILENAME -- write a pid file for the daemon process to FILENAME
-i/--identifier STR -- identifier used for this instance of supervisord
-q/--childlogdir DIRECTORY -- the log directory for child process logs
-k/--nocleanup --  prevent the process from performing cleanup (removal of
                   old automatic child log files) at startup.
-a/--minfds NUM -- the minimum number of file descriptors for start success
-t/--strip_ansi -- strip ansi escape codes from process output
--minprocs NUM  -- the minimum number of processes available for start success
--profile_options OPTIONS -- run supervisord under profiler and output
                             results based on OPTIONS, which  is a comma-sep'd
                             list of 'cumulative', 'calls', and/or 'callers',
                             e.g. 'cumulative,callers')
"""

import os,sys
import time
import signal
import json
import pdb
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from supervisor.medusa import asyncore_25 as asyncore

from supervisor.compat import as_string
from supervisor.options import ServerOptions
from supervisor.options import signame
from supervisor import events
from supervisor.states import SupervisorStates
from supervisor.states import getProcessStateDescription

class Supervisor:
    stopping = False # set after we detect that we are handling a stop request  在检测到正在处理停止请求后设置
    lastshutdownreport = 0 # throttle for delayed process error reports at stop  在停止时为延迟的过程错误报告节流
    process_groups = None # map of process group name to process group object  进程组名称到进程组对象的映射
    stop_groups = None # list used for priority ordered shutdown  优先级

    def __init__(self, options):
        self.options = options
        self.process_groups = {}
        self.ticks = {}

    def main(self):
        if not self.options.first:
            # prevent crash on libdispatch-based systems, at least for the
            # first request
            # 为了防止libdispatch-based系统崩溃
            self.options.cleanup_fds()
        # 如果配置文件中的user为空，但是运行本进程的user为root，那么提示用户把root添加到配置中
        # 如果user不为空且运行该进程的为root，那么将该进程标记为该用户和 用户所在的组
        self.options.set_uid_or_exit()
        if self.options.first:
            # 设置该进程可用的resource的最大软硬限制
            self.options.set_rlimits_or_exit()

        # this sets the options.logger object
        # delay logger instantiation until after setuid
        self.options.make_logger()
        # 清除子进程的日志
        if not self.options.nocleanup:
            # clean up old automatic logs
            # 清除子进程的日志
            # 删除子日志，我要成为正则大神......
            self.options.clear_autochildlogdir()
        self.run()

    def run(self):
        self.process_groups = {} # clear
        self.stop_groups = None # clear
        # 清除全局变量callbacks
        events.clear()
        try:
            # class ProcessConfig(Config)    ProcessGroupConfig
            for config in self.options.process_group_configs:
                # 将process实例添加到自己的进程组中,这一步老复杂了
                self.add_process_group(config)
            # {'st': <<class 'supervisor.process.ProcessGroup'> instance at 140080285716112 named st >}
            print(self.process_groups)
            self.options.process_environment() # 更新环境变量
            self.options.openhttpservers(self)
            # self.options.httpservers
            # [({'username': None, 'name': None, 'family': 1, 'section': 'unix_http_server', 'chmod': 448, 'chown': (-1, -1),
            #    'file': '/tmp/supervisor.sock', 'password': None},
            #   < supervisor.http.supervisor_af_unix_http_server at 0x7fb0684bffc8 >)]
            # openhttpservers 设置了socket_map
            # 设置信号处理函数
            # def receive(self, sig, frame):
            #         # 信号量不能重复？
            #         if sig not in self._signals_recvd:
            #             self._signals_recvd.append(sig)
            self.options.setsignals()
            # 如果是true，supervisord进程将在前台运行
            # 我先把它给关掉，因为不运行在桌面无法进行调试
            # if (not self.options.nodaemon) and self.options.first:
            #     self.options.daemonize()
            # writing pid file needs to come *after* daemonizing or pid
            # will be wrong   将进程号写进进程文件
            self.options.write_pidfile()
            self.runforever()
        finally:
            self.options.cleanup()

    def diff_to_active(self, new=None):
        if not new:
            new = self.options.process_group_configs
        cur = [group.config for group in self.process_groups.values()]

        curdict = dict(zip([cfg.name for cfg in cur], cur))
        newdict = dict(zip([cfg.name for cfg in new], new))

        added   = [cand for cand in new if cand.name not in curdict]
        removed = [cand for cand in cur if cand.name not in newdict]

        changed = [cand for cand in new
                   if cand != curdict.get(cand.name, cand)]

        return added, changed, removed

    def add_process_group(self, config):
        name = config.name
        # print('name:',name)
        if name not in self.process_groups:
            # log，细节先不管
            config.after_setuid()
            # 根据初始化后的配置文件生成相应的子进程实例
            # config：ProcessGroupConfig实例
            # self.process_groups['st']最终结果是 # ProcessGroup(ProcessGroupBase)实例
            # 实例的self.processes['st'] 是Subprocess实例，其中group属性为ProcessGroup(ProcessGroupBase)实例
            self.process_groups[name] = config.make_group()
            # 添加事件通知，callback还是空的，等到callback有方法，就会执行方法，参数是events.ProcessGroupAddedEvent(name)等构成
            events.notify(events.ProcessGroupAddedEvent(name))
            return True
        return False

    def remove_process_group(self, name):
        if self.process_groups[name].get_unstopped_processes():
            return False
        self.process_groups[name].before_remove()
        del self.process_groups[name]
        events.notify(events.ProcessGroupRemovedEvent(name))
        return True

    def get_process_map(self):
        process_map = {}
        for group in self.process_groups.values():
            process_map.update(group.get_dispatchers())
        return process_map

    def shutdown_report(self):
        unstopped = []

        for group in self.process_groups.values():
            unstopped.extend(group.get_unstopped_processes())

        if unstopped:
            # throttle 'waiting for x to die' reports
            now = time.time()
            if now > (self.lastshutdownreport + 3): # every 3 secs
                names = [ as_string(p.config.name) for p in unstopped ]
                namestr = ', '.join(names)
                self.options.logger.info('waiting for %s to die' % namestr)
                self.lastshutdownreport = now
                for proc in unstopped:
                    state = getProcessStateDescription(proc.get_state())
                    self.options.logger.blather(
                        '%s state: %s' % (proc.config.name, state))
        return unstopped

    def ordered_stop_groups_phase_1(self):
        if self.stop_groups:
            # stop the last group (the one with the "highest" priority)
            # 先停优先级最高的那个进程组
            self.stop_groups[-1].stop_all()

    def ordered_stop_groups_phase_2(self):
        # after phase 1 we've transitioned and reaped, let's see if we
        # can remove the group we stopped from the stop_groups queue.
        if self.stop_groups:
            # pop the last group (the one with the "highest" priority)
            group = self.stop_groups.pop()
            if group.get_unstopped_processes():
                # if any processes in the group aren't yet in a
                # stopped state, we're not yet done shutting this
                # group down, so push it back on to the end of the
                # stop group queue
                self.stop_groups.append(group)

    def runforever(self):
        # 事件通知机制，使用callbacks中的方法对event实例进行操作
        # callbacks一直是空的，现在还不知道怎么添加方法到其中
        events.notify(events.SupervisorRunningEvent())
        timeout = 1 # this cannot be fewer than the smallest TickEvent (5)
        # 获得一件注册的句柄 {4: <supervisor.http.supervisor_af_unix_http_server at 0x7f8b5fcb0488>} 不知道在哪里设置的
        # supervisor_af_unix_http_server对象
        socket_map = self.options.get_socket_map()
        # print('socket_map:',socket_map)
        while 1:
            # 保存运行的信息
            combined_map = {}
            combined_map.update(socket_map)
            combined_map.update(self.get_process_map())
            # 进程信息  socket_map我追溯了很长时间，类之间关联太复杂了，放弃治疗
            # 更新，窝没有放弃治疗，我找到了
            # self.get_process_map()为空
            pgroups = list(self.process_groups.values())
            # 这个排序是按照内存地址进行的吗
            # 这个排序是processgroup中定义的，按照配置中的优先级进行排序
            #  def __lt__(self, other):
            #         return self.config.priority < other.config.priority
            pgroups.sort()
            # 根据进程的配置开启或者关闭进程
            # self.options.mood 在信号中变化，   RESTARTING = 0  SHUTDOWN = -1 这两个是小于
            if self.options.mood < SupervisorStates.RUNNING:
                if not self.stopping:
                    # first time, set the stopping flag, do a
                    # notification and set stop_groups
                    self.stopping = True
                    self.stop_groups = pgroups[:]
                    events.notify(events.SupervisorStoppingEvent())
                self.ordered_stop_groups_phase_1()

                if not self.shutdown_report():
                    # if there are no unstopped processes (we're done
                    # killing everything), it's OK to shutdown or reload
                    raise asyncore.ExitNow
            # 这个和我们用redis差不多来着
            for fd, dispatcher in combined_map.items():
                # class http_server (asyncore.dispatcher): 在右键第四个
                if dispatcher.readable():
                    #可读，注册到select,证明这个句柄是好的
                    self.options.poller.register_readable(fd)
                if dispatcher.writable():
                    # 初始时候不可写，注册到select
                    self.options.poller.register_writable(fd)
            # poll操作,返回可读可写的文件描述符,到这一步完全没有问题
            r, w = self.options.poller.poll(timeout)
            # print(combined_map)
            # for i,key in combined_map.items():
            #     print(key)
            for fd in r:
                if fd in combined_map:
                    # print('r start running',fd)
                    try:
                        dispatcher = combined_map[fd]
                        # print(dispatcher)
                        self.options.logger.blather(
                            'read event caused by %(dispatcher)r',
                            dispatcher=dispatcher)
                        # print('ttttt')
                        # print(dispatcher)
                        # <socket._socketobject object at 0x7fdfa69b96e0>
                        # print(dispatcher.__class__.__name__)
                        # dispatcher.test_handler()
                        dispatcher.handle_read_event()
                        if not dispatcher.readable():
                            self.options.poller.unregister_readable(fd)
                    except asyncore.ExitNow:
                        raise
                    except:
                        combined_map[fd].handle_error()
            # 依次遍历注册的文件句柄
            for fd in w:
                if fd in combined_map:
                    # print('w start running', fd)
                    try:
                        dispatcher = combined_map[fd]
                        self.options.logger.blather(
                            'write event caused by %(dispatcher)r',
                            dispatcher=dispatcher)
                        dispatcher.handle_write_event()
                        if not dispatcher.writable():
                            self.options.poller.unregister_writable(fd)
                    except asyncore.ExitNow:
                        raise
                    except:
                        combined_map[fd].handle_error()
            for group in pgroups:
                group.transition()
            # 获取已经死亡的子进程信息
            self.reap()
            # 处理信号
            self.handle_signal()
            # tick时钟
            self.tick()
            if self.options.mood < SupervisorStates.RUNNING:
                self.ordered_stop_groups_phase_2()

            if self.options.test:
                break
            # 新加，测试用
            # break
        '''
        start 的时候执行了get_execv_args，但是入口我没有找到
        spawn 我找不到spawn的调用者，然后再spawn中写了一个错误，但是在superviosrctl的shell中抛出错误，在xmlrpc.py中，我猜想
        是xmlrpc.py中的远程调用直接做了某些事情
        '''

    def tick(self, now=None):
        """ Send one or more 'tick' events when the timeslice related to
        the period for the event type rolls over """
        if now is None:
            # now won't be None in unit tests
            now = time.time()
        for event in events.TICK_EVENTS:
            period = event.period
            last_tick = self.ticks.get(period)
            if last_tick is None:
                # we just started up
                last_tick = self.ticks[period] = timeslice(period, now)
            this_tick = timeslice(period, now)
            if this_tick != last_tick:
                self.ticks[period] = this_tick
                events.notify(event(this_tick, self))

    def reap(self, once=False, recursionguard=0):
        if recursionguard == 100:
            return
        pid, sts = self.options.waitpid()
        if pid:
            process = self.options.pidhistory.get(pid, None)
            if process is None:
                self.options.logger.info('reaped unknown pid %s' % pid)
            else:
                process.finish(pid, sts)
                del self.options.pidhistory[pid]
            if not once:
                # keep reaping until no more kids to reap, but don't recurse
                # infintely
                self.reap(once=False, recursionguard=recursionguard+1)

    def handle_signal(self):
        sig = self.options.get_signal()
        if sig:
            # 请求中止进程，kill命令缺省发送
            # 由Interrupt Key产生，通常是CTRL+C或者DELETE。发送给所有ForeGround Group的进程
            # 输入Quit Key的时候（CTRL+\）发送给所有Foreground Group的进程
            # 关闭
            if sig in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
                self.options.logger.warn(
                    'received %s indicating exit request' % signame(sig))
                self.options.mood = SupervisorStates.SHUTDOWN
            # 发送给具有Terminal的Controlling Process，当terminal被disconnect时候发送
            # 重启
            elif sig == signal.SIGHUP:
                if self.options.mood == SupervisorStates.SHUTDOWN:
                    self.options.logger.warn(
                        'ignored %s indicating restart request (shutdown in progress)' % signame(sig))
                else:
                    self.options.logger.warn(
                        'received %s indicating restart request' % signame(sig))
                    self.options.mood = SupervisorStates.RESTARTING
            # 进程Terminate或Stop的时候，SIGCHLD会发送给它的父进程。缺省情况下该Signal会被忽略
            elif sig == signal.SIGCHLD:
                self.options.logger.debug(
                    'received %s indicating a child quit' % signame(sig))
            # 用户自定义signal 2
            elif sig == signal.SIGUSR2:
                self.options.logger.info(
                    'received %s indicating log reopen request' % signame(sig))
                self.options.reopenlogs()
                for group in self.process_groups.values():
                    group.reopenlogs()
            else:
                self.options.logger.blather(
                    'received %s indicating nothing' % signame(sig))

    def get_state(self):
        return self.options.mood

def timeslice(period, when):
    return int(when - (when % period))

# profile entry point
def profile(cmd, globals, locals, sort_order, callers): # pragma: no cover
    try:
        import cProfile as profile
    except ImportError:
        import profile
    import pstats
    import tempfile
    fd, fn = tempfile.mkstemp()
    try:
        profile.runctx(cmd, globals, locals, fn)
        stats = pstats.Stats(fn)
        stats.strip_dirs()
        # calls,time,cumulative and cumulative,calls,time are useful
        stats.sort_stats(*sort_order or ('cumulative', 'calls', 'time'))
        if callers:
            stats.print_callers(.3)
        else:
            stats.print_stats(.3)
    finally:
        os.remove(fn)


# Main program
def main(args=None, test=False):
    assert os.name == "posix", "This code makes Unix-specific assumptions"
    # if we hup, restart by making a new Supervisor()
    first = True
    # while 1:
    if 1:
        options = ServerOptions()
        # attribute_value = options.__dict__
        # for key,value in attribute_value.items():
        #     print(key,value)
        # __doc__ 该文件下
        options.realize(args, doc=__doc__)
        options.first = first
        options.test = test

        if options.profile_options:
            sort_order, callers = options.profile_options
            profile('go(options)', globals(), locals(), sort_order, callers)
        else:
            go(options)
        options.close_httpservers()
        options.close_logger()
        first = False
        # if test or (options.mood < SupervisorStates.RESTARTING):
            # break

def go(options): # pragma: no cover
    d = Supervisor(options)
    try:
        d.main()
    except asyncore.ExitNow:
        pass

if __name__ == "__main__": # pragma: no cover
    main()
