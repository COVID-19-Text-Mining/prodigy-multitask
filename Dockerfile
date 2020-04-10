FROM tiangolo/uwsgi-nginx-flask:python3.6-alpine3.7
COPY ./ /app

RUN apk update
RUN apk add --no-cache --virtual .build-deps make automake gcc g++ python3-dev
RUN pip install cython
RUN pip install /app/prodigy-1.9.9-cp36.cp37.cp38-cp36m.cp37m.cp38-linux_x86_64.whl
RUN pip install -r /app/requirements.txt
RUN apk del .build-deps

RUN python -m spacy download en_core_web_sm
