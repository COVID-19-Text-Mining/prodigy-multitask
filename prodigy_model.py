import json
import os
import shutil
import socket
import time
import zipfile
from datetime import datetime

import psutil
from flask import abort
from psutil import NoSuchProcess

from prodigy_constants import *

__all__ = [
    'port_used',

    'check_dir_exists', 'check_file_exists',

    'prodigy_config_fn', 'prodigy_sys_fn', 'prodigy_pid_fn',

    'get_work_dir_or_none', 'get_work_dir_or_404', 'get_pid_or_clean',

    'copy_config_safe', 'read_config_or_404', 'read_config_or_default',
    'write_config_or_404', 'write_config_or_raise',

    'iter_prodigy_services', 'zip_prodigy_instance',

    'cleanup_temp_dir'
]


def port_used(port: int) -> bool:
    """
    Return True if the port is used.
    :param port: Port to test
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('127.0.0.1', port))
        used = False
    except OSError:
        used = True
    s.close()
    return used


def check_file_exists(fn):
    return os.path.exists(fn) and os.path.isfile(fn)


def check_dir_exists(fn):
    return os.path.exists(fn) and os.path.isdir(fn)


def prodigy_config_fn(work_dir):
    return os.path.join(work_dir, PRODIGY_CONFIG_JSON)


def prodigy_sys_fn(work_dir):
    return os.path.join(work_dir, PRODIGY_SYS_JSON)


def prodigy_pid_fn(work_dir):
    return os.path.join(work_dir, PRODIGY_PID_FILE)


def get_work_dir_or_none(prodigy_id):
    true_path = os.path.join(PRODIGY_INSTANCES_DIR, prodigy_id)
    if not check_dir_exists(true_path):
        return None
    return true_path


def get_work_dir_or_404(prodigy_id):
    true_path = get_work_dir_or_none(prodigy_id)
    if true_path is None:
        return abort(404)
    return true_path


def get_pid_or_clean(pid_fn_or_prodigy_id: str) -> [None, int]:
    """Get pid or clean up the pid file"""
    if len(pid_fn_or_prodigy_id.split(os.sep)) > 1:
        pid_fn = pid_fn_or_prodigy_id
    else:
        pid_fn = prodigy_pid_fn(pid_fn_or_prodigy_id)

    if os.path.exists(pid_fn):
        with open(pid_fn) as f:
            pid = int(f.read())
        try:
            process = psutil.Process(pid)
            if process.status() == psutil.STATUS_ZOMBIE:
                # uwsgi will do this for us
                # process.wait()
                raise NoSuchProcess('Zombie')
            return pid
        except NoSuchProcess:
            os.unlink(pid_fn)

    return None


def copy_config_safe(config):
    return {
        'uuid': str(config['uuid']),
        'name': str(config['name']),
        'db_collection': str(config['db_collection']),
        'arguments': str(config['arguments']),
        'work_dir': str(config['work_dir']),
        'share': [
            {'to': str(x['to']), 'id': str(x['id']), 'email': str(x['email'])}
            for x in config.get('share', [])
        ]
    }


def read_config_or_default(prodigy_id_or_work_dir, default=None):
    if len(prodigy_id_or_work_dir.split(os.sep)) > 1:
        work_dir = prodigy_id_or_work_dir
    else:
        work_dir = get_work_dir_or_none(prodigy_id_or_work_dir)
        if work_dir is None:
            return default

    config_fn = prodigy_config_fn(work_dir)
    if not check_file_exists(config_fn):
        return default

    with open(config_fn) as f:
        config = json.load(f)
        # Make a copy to avoid arbitrary code execution
        try:
            return copy_config_safe(config)
        except KeyError:
            return default


def read_config_or_404(prodigy_id):
    config = read_config_or_default(prodigy_id, default=None)
    if config is None:
        return abort(404)

    return config


def write_config_or_raise(prodigy_id, config):
    true_path = get_work_dir_or_none(prodigy_id)

    config_fn = prodigy_config_fn(true_path)
    if check_dir_exists(config_fn):
        shutil.rmtree(config_fn)

    with open(config_fn, 'w') as f:
        # Make a copy to avoid arbitrary code execution
        json.dump(copy_config_safe(config), f)


def write_config_or_404(prodigy_id, config):
    true_path = get_work_dir_or_404(prodigy_id)

    config_fn = prodigy_config_fn(true_path)
    if check_dir_exists(config_fn):
        shutil.rmtree(config_fn)

    with open(config_fn, 'w') as f:
        # Make a copy to avoid arbitrary code execution
        json.dump(copy_config_safe(config), f)


def iter_prodigy_services():
    for i in os.listdir(PRODIGY_INSTANCES_DIR):
        work_dir = get_work_dir_or_none(i)
        if work_dir is None:
            continue
        config_fn = prodigy_config_fn(work_dir)
        if not os.path.exists(config_fn):
            continue

        pid_fn = prodigy_pid_fn(work_dir)
        pid = get_pid_or_clean(pid_fn)

        alive = pid is not None

        listening = False
        if alive:
            try:
                sys_fn = prodigy_sys_fn(work_dir)
                with open(sys_fn) as f:
                    port = int(json.load(f)['port'])
                    listening = port_used(port)
            except FileNotFoundError:
                pass

        yield {
            'name': i,
            'work_dir': work_dir,
            'alive': alive,
            'listening': listening,
            'pid': pid}


def zip_prodigy_instance(service_id, work_dir):
    fn = '%s_%s.zip' % (service_id, datetime.now().strftime('%Y%m%d_%H%M%S'))
    zip_file_path = os.path.join(TEMP_DIR, fn)
    zip_file = zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED)

    for root, dirs, files in os.walk(work_dir):
        for file in files:
            if root == work_dir and file in PRODIGY_SYS_FILES:
                continue
            this_fn = os.path.join(root, file)
            zip_file.write(
                this_fn,
                arcname=os.path.relpath(this_fn, PRODIGY_INSTANCES_DIR))
    zip_file.close()

    return zip_file_path


def cleanup_temp_dir():
    for i in os.listdir(TEMP_DIR):
        filename = os.path.join(TEMP_DIR, i)
        mtime = os.stat(filename).st_mtime
        if mtime < time.time() - 3600:
            # Remove files older than 1 hour
            os.unlink(filename)
