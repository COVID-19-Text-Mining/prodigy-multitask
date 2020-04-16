import json
import os
import shutil
import signal
import subprocess
import sys
import threading

import psutil
from psutil import NoSuchProcess, ZombieProcess

from prodigy_constants import *
from prodigy_model import prodigy_sys_fn, port_used, iter_prodigy_services, get_work_dir_or_none


def get_next_available_port(start: int = 8080) -> int:
    """
    Get the next available port in system.
    :param start: The starting port to check.
    :return: Next available port that can be listened on.
    """
    port = start
    while True:
        if port_used(port):
            port += 1
        else:
            break

    return port


def start_prodigy(working_dir, arguments=None):
    """Start a prodigy service at a new port"""

    port = get_next_available_port()
    work_dir = os.path.realpath(working_dir)

    # Write config
    with open(prodigy_sys_fn(working_dir), 'w') as f:
        json.dump({
            "port": port,
            "host": "127.0.0.1",
        }, f)

    new_env = os.environ.copy()
    new_env['PRODIGY_HOME'] = work_dir

    process = subprocess.Popen(
        ['python', PRODIGY_ENTRY_POINT, work_dir],
        shell=False,
        cwd=working_dir,
        env=new_env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with open(os.path.join(work_dir, 'prodigy.pid'), 'w') as f:
        f.write(f'{process.pid}')

    return {
        'pid': process.pid,
        'process': process,
        'port': port,
        'work_dir': work_dir,
    }


def kill_pid_and_children(
        pid: int,
        sig=signal.SIGINT if sys.platform != 'win32' else signal.SIGTERM):
    """
    Send signal to a process and its children to kill them all.
    Does not necessarily clean up zombie processes.
    :param pid:
    :param sig:
    :return:
    """
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    children_pid = []
    for process in parent.children():
        children_pid.append(process.pid)
        kill_pid_and_children(process.pid)
    parent.send_signal(sig)


def stop_prodigy(pid: int) -> None:
    """
    Stop a Prodigy instance by killing it and its child processes.
    :param pid:
    :return:
    """
    kill_pid_and_children(pid)


def get_prodigy_pid(work_dir_or_prodigy_id: str) -> [None, int]:
    """Return the PID of current prodigy instance."""
    if len(work_dir_or_prodigy_id.split(os.sep)) > 1:
        work_dir = work_dir_or_prodigy_id
    else:
        work_dir = get_work_dir_or_none(work_dir_or_prodigy_id)
    pid_fn = os.path.join(work_dir, PRODIGY_PID_FILE)
    if os.path.exists(pid_fn):
        if not os.path.isfile(pid_fn):
            shutil.rmtree(pid_fn)
            return None

        with open(pid_fn) as f:
            try:
                # Already started
                pid = int(f.read())
                psutil.Process(pid)
                return pid
            except NoSuchProcess:
                pass
    return None


def stop_all_prodigy(*_, **__):
    for prodigy_id, _, alive, listening, pid in iter_prodigy_services():
        if alive:
            print('Stopping prodigy PID', pid)
            stop_prodigy(pid)


# Stop all services at exit
if threading.current_thread() is threading.main_thread():
    signal.signal(signal.SIGTERM, stop_all_prodigy)
    signal.signal(signal.SIGABRT, stop_all_prodigy)
    signal.signal(signal.SIGINT, stop_all_prodigy)


def register_zombie_cleaner(app):
    """
    Register a function that runs after every flask request
    to clean up zombie processes.

    :param app: Flask app.
    :return: None
    """

    def cleanup_zombie(_):
        self = psutil.Process()
        ppid_map = psutil._ppid_map()
        for pid, ppid in ppid_map.items():
            if ppid == self.pid:
                try:
                    psutil.Process(pid)
                except ZombieProcess:
                    os.waitpid(pid, 0)
                except NoSuchProcess:
                    pass

    app.teardown_appcontext(cleanup_zombie)
