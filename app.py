import json
import os
import re
import signal
import threading
import time
import uuid
from urllib.parse import urlparse

import requests
from flask import (
    Flask, render_template, make_response, request,
    redirect, url_for, abort, Response, send_file)
from werkzeug.utils import secure_filename

import prodigy_manager
# import settings

app = Flask(__name__)
# app.config["MONGO_URI"] = "mongodb://{user}:{pwd}@{host}/{db}?authSource={authDB}".format(
#     host=settings.MONGO_HOSTNAME,
#     user=quote_plus(settings.MONGO_USERNAME),
#     pwd=quote_plus(settings.MONGO_PASSWORD),
#     db=settings.MONGO_DB,
#     authDB=settings.MONGO_AUTHENTICATION_DB,
# )
# mongo = PyMongo(app)

# Shared state variables
prodigy_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'prodigy_dir')
temp_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'temp_file_storage')
if not os.path.exists(prodigy_dir):
    os.mkdir(prodigy_dir)
if not os.path.exists(temp_dir):
    os.mkdir(temp_dir)
prodigy_services = {}
prodigy_services_lock = threading.Lock()


def stop_all_prodigy(*_, **__):
    with prodigy_services_lock:
        for service in prodigy_services:
            print('Stopping prodigy PID', service['pid'])
            prodigy_manager.stop_prodigy(service['pid'])


# Stop all services at exit
if threading.current_thread() is threading.main_thread():
    signal.signal(signal.SIGTERM, stop_all_prodigy)
    signal.signal(signal.SIGABRT, stop_all_prodigy)
    signal.signal(signal.SIGINT, stop_all_prodigy)


@app.route('/')
def list_services():
    with prodigy_services_lock:
        active_services = set(prodigy_services.keys())

    all_services = []
    for service in os.listdir(prodigy_dir):
        config_filename = os.path.join(prodigy_dir, service, 'config.json')
        if not os.path.exists(config_filename):
            app.logger.warning(f'Cannot find config file {config_filename}')
            continue

        with open(config_filename) as f:
            service_config = json.load(f)
            try:
                all_services.append({
                    'id': service,
                    'name': str(service_config['name']),
                    'arguments': str(service_config['arguments']),
                    'active': service_config['work_dir'] in active_services,
                })
            except KeyError:
                app.logger.warning(f'Config file {config_filename} corrupted.')

    return render_template(
        'services/list_services.html', all_services=all_services)


@app.route('/start/<service_id>')
def start_service(service_id):
    true_path = os.path.join(prodigy_dir, service_id)
    if not os.path.exists(true_path):
        abort(404)
        return

    with prodigy_services_lock:
        if true_path in prodigy_services:
            # Already started
            return redirect(url_for('list_services'))

    s = prodigy_manager.start_prodigy(true_path)
    with prodigy_services_lock:
        prodigy_services[true_path] = s

    return redirect(url_for('list_services'), code=302)


@app.route('/stop/<service_id>')
def stop_service(service_id):
    true_path = os.path.join(prodigy_dir, service_id)

    with prodigy_services_lock:
        if true_path not in prodigy_services:
            abort(404)
            return
        s = prodigy_services.pop(true_path)

    prodigy_manager.stop_prodigy(s['pid'])
    os.waitpid(s['pid'], 0)

    return redirect(url_for('list_services'), code=302)


@app.route('/download_db/<service_id>')
def download_service_db(service_id):
    true_path = os.path.join(prodigy_dir, service_id)
    return send_file(os.path.join(true_path, 'prodigy.db'), as_attachment=True)


def _proxy_response(service_id, request_path):
    true_path = os.path.join(prodigy_dir, service_id)
    with prodigy_services_lock:
        try:
            s = prodigy_services[true_path]
        except KeyError:
            return 'The page requested is not found', 404

    query_ending = ''
    if request.query_string:
        query_ending = '?' + request.query_string.decode()
    if request_path.startswith('/'):
        request_path = request_path[1:]
    url = 'http://localhost:%d/%s%s' % (s['port'], request_path, query_ending)

    app.logger.info(f'Forwarding request to prodigy instance {service_id}: {request.method} {url}')
    resp = requests.request(
        method=request.method,
        url=url,
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    response = Response(resp.content, resp.status_code, headers)
    return response


@app.errorhandler(404)
def redirect_proxy(_):
    if 'referer' not in request.headers:
        return 'The page requested is not found', 404

    o = urlparse(request.headers.get('referer'))
    m = re.match(r'/prodigy/([^/]+)', o.path)
    if not m:
        return 'The page requested is not found', 404
    service_id = m.group(1)

    path = urlparse(request.url).path

    return _proxy_response(service_id, path)


@app.route('/prodigy/<service_id>/',
           defaults={'path': ''},
           methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
@app.route('/prodigy/<service_id>/<path:path>',
           methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def proxy_service(service_id, path):
    return _proxy_response(service_id, path)


@app.route('/new_service')
def new_service_desc():
    random_id = str(uuid.uuid1())
    return render_template(
        'services/new_service.html',
        random_id=random_id)


def cleanup_temp_dir():
    with prodigy_services_lock:
        for i in os.listdir(temp_dir):
            filename = os.path.join(temp_dir, i)
            mtime = os.stat(filename).st_mtime
            if mtime < time.time() - 3600:
                # Remove files older than 1 hour
                os.unlink(filename)


@app.route('/new_service/<random_id>', methods=['POST'])
def create_new_service(random_id):
    form = request.form
    name = re.sub(r'[^a-zA-Z0-9_-]+', '', form.get('name', ''))
    if os.path.exists(os.path.join(prodigy_dir, name)):
        return 'The service with name "%s" already exists.' % name, 400

    arguments = form.get('arguments', '')
    files = list(map(secure_filename, form.getlist('files')))
    for i in files:
        if not os.path.exists(os.path.join(temp_dir, '%s--%s' % (random_id, i))):
            return 'File upload "%s" does not exist.' % name, 400

    new_service_dir = os.path.join(prodigy_dir, name)
    os.mkdir(new_service_dir)

    with open(os.path.join(new_service_dir, 'config.json'), 'w') as f:
        json.dump({
            'name': name,
            'arguments': arguments,
            'work_dir': new_service_dir
        }, f)
    for i in files:
        src = os.path.join(temp_dir, '%s--%s' % (random_id, i))
        os.rename(src, os.path.join(new_service_dir, i))

    try:
        cleanup_temp_dir()
    except OSError as e:
        app.logger.exception(f'Exception during cleaning up temp dir {e}')

    return redirect(url_for('list_services'), code=302)


@app.route('/upload_file/<random_id>', methods=['POST'])
def upload(random_id):
    # https://stackoverflow.com/questions/44727052/handling-large-file-uploads-with-flask
    file = request.files['file']

    save_path = os.path.join(temp_dir, random_id + '--' + secure_filename(file.filename))
    current_chunk = int(request.form['dzchunkindex'])

    # If the file already exists it's ok if we are appending to it,
    # but not if it's new file that would overwrite the existing one
    if os.path.exists(save_path) and current_chunk == 0:
        # 400 and 500s will tell dropzone that an error occurred and show an error
        return make_response(('File already exists', 400))

    try:
        with open(save_path, 'ab') as f:
            f.seek(int(request.form['dzchunkbyteoffset']))
            f.write(file.stream.read())
    except OSError:
        # log.exception will include the traceback so we can see what's wrong
        app.logger.exception('Could not write to file')
        return make_response(("Not sure why,"
                              " but we couldn't write the file to disk", 500))

    total_chunks = int(request.form['dztotalchunkcount'])

    if current_chunk + 1 == total_chunks:
        # This was the last chunk, the file should be complete and the size we expect
        if os.path.getsize(save_path) != int(request.form['dztotalfilesize']):
            app.logger.error(f"File {file.filename} was completed, "
                             f"but has a size mismatch."
                             f"Was {os.path.getsize(save_path)} but we"
                             f" expected {request.form['dztotalfilesize']} ")
            return make_response(('Size mismatch', 500))
        else:
            app.logger.info(f'File {file.filename} has been uploaded successfully')
    else:
        app.logger.debug(f'Chunk {current_chunk + 1} of {total_chunks} '
                         f'for file {file.filename} complete')

    return make_response(("Chunk upload successful", 200))
