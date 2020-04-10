import json
import os
import re
import signal
import socket
import subprocess

import psutil


def get_next_available_port(start=8080):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    port = start
    while True:
        try:
            s.bind(('localhost', port))
            break
        except OSError:
            port += 1
    s.close()

    return port


def start_prodigy(working_dir, arguments=None):
    """Start a prodigy service at a new port"""

    port = get_next_available_port()
    work_dir = os.path.realpath(working_dir)

    with open(os.path.join(working_dir, 'config.json')) as f:
        service_config = json.load(f)
        if arguments is None:
            arguments = str(service_config['arguments'])

    # Write config
    with open(os.path.join(working_dir, 'prodigy.json'), 'w') as f:
        json.dump({
            "db": "sqlite",
            "db_settings": {
                "sqlite": {
                    "name": "prodigy.db",
                    "path": work_dir,
                }
            },
            "port": port
        }, f)

    new_env = os.environ.copy()
    new_env['PRODIGY_HOME'] = work_dir
    process = subprocess.Popen(
        ['prodigy'] + re.split(r'\s+', arguments),
        shell=False,
        cwd=working_dir,
        env=new_env)

    return {
        'pid': process.pid,
        'process': process,
        'port': port,
        'work_dir': work_dir,
    }


def kill_pid_and_children(pid, sig=signal.SIGINT):
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    children = parent.children()
    for process in children:
        kill_pid_and_children(process.pid)
        process.send_signal(sig)


def stop_prodigy(pid):
    kill_pid_and_children(pid)
