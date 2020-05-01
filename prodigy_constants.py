import os

__all__ = [
    'PRODIGY_INSTANCES_DIR', 'TEMP_DIR',

    'PRODIGY_ENTRY_POINT',

    'PRODIGY_CONFIG_JSON', 'PRODIGY_SYS_JSON', 'PRODIGY_PID_FILE',
    'PRODIGY_STDOUT', 'PRODIGY_STDERR',
    'PRODIGY_SYS_FILES'
]

PRODIGY_INSTANCES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'run', 'prodigy_dir')
TEMP_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'run', 'temp_file_storage')

if not os.path.exists(PRODIGY_INSTANCES_DIR):
    os.mkdir(PRODIGY_INSTANCES_DIR)
if not os.path.exists(TEMP_DIR):
    os.mkdir(TEMP_DIR)

PRODIGY_ENTRY_POINT = os.path.realpath(os.path.join(os.path.dirname(__file__), 'prodigy_entrypoint.py'))

PRODIGY_CONFIG_JSON = 'config.json'
PRODIGY_SYS_JSON = 'prodigy.json'
PRODIGY_PID_FILE = 'prodigy.pid'
PRODIGY_STDOUT = 'stdout.txt'
PRODIGY_STDERR = 'stderr.txt'

PRODIGY_SYS_FILES = {
    PRODIGY_CONFIG_JSON,
    PRODIGY_SYS_JSON,
    PRODIGY_PID_FILE,
    PRODIGY_STDOUT,
    PRODIGY_STDERR
}
