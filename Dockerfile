FROM tiangolo/uwsgi-nginx-flask:python3.6-alpine3.7
COPY ./ /app

RUN apk update
RUN apk add libstdc++ libgcc
RUN apk add --no-cache --virtual .build-deps make automake gcc g++ python3-dev linux-headers
RUN pip install cython
RUN pip install /app/wheels/blis-0.4.1-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/cymem-2.0.3-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/httptools-0.1.1-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/MarkupSafe-1.1.1-cp36-none-any.whl\
    /app/wheels/murmurhash-1.0.2-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/numpy-1.18.2-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/peewee-3.13.2-cp36-none-any.whl\
    /app/wheels/preshed-3.0.2-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/psutil-5.7.0-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/pymongo-3.10.1-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/spacy-2.2.4-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/srsly-1.0.2-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/starlette-0.12.9-cp36-none-any.whl\
    /app/wheels/thinc-7.4.0-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/toolz-0.10.0-cp36-none-any.whl\
    /app/wheels/uvloop-0.14.0-cp36-cp36m-linux_x86_64.whl\
    /app/wheels/websockets-8.1-cp36-cp36m-linux_x86_64.whl

RUN pip install /app/prodigy-1.9.9-cp36.cp37.cp38-cp36m.cp37m.cp38-linux_x86_64.whl
RUN pip install -r /app/requirements.txt

# Cleanup
RUN apk del .build-deps
RUN rm -rf /root/.cache/pip \
    /app/prodigy-1.9.9-cp36.cp37.cp38-cp36m.cp37m.cp38-linux_x86_64.whl \
    /app/wheels

RUN python -m spacy download en_core_web_sm

# NERSC Spin specific
# Make /var/cache/nginx/ writable by non-root users
# Open port 8080 as non-root user
RUN mkdir /app/prodigy_dir /app/temp_file_storage
RUN chgrp nginx /var/cache/nginx/ /app/prodigy_dir /app/temp_file_storage
RUN chmod g+w /var/cache/nginx/ /app/prodigy_dir /app/temp_file_storage
COPY ./nginx.conf /etc/nginx/conf.d/nginx.conf
