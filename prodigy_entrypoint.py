# This file is the entry point to Prodigy instances.
# It takes a single argument: the working dir of Prodigy instance
import os
import sys

assert len(sys.argv) == 2
work_dir = os.path.realpath(sys.argv[1])
assert os.path.exists(work_dir) and os.path.isdir(work_dir)

# Close all file descriptors since we might come from fork
os.closerange(0, 4096)


# Redirect stdout/stderr
# https://stackoverflow.com/questions/107705/disable-output-buffering
class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)


sys.stdout = Unbuffered(open(os.path.join(work_dir, 'stdout.txt'), 'w'))
sys.stderr = Unbuffered(open(os.path.join(work_dir, 'stderr.txt'), 'w'))
print('Prodigy entry point loaded')

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#              Main app start
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


import json
import uuid
import time
import pymongo
import settings

from datetime import datetime
from prodigy.components.db import Database
from prodigy.util import TASK_HASH_ATTR, INPUT_HASH_ATTR

with open(os.path.join(work_dir, 'config.json')) as f:
    config = json.load(f)

print('Trying to establish database connection...')

db = pymongo.MongoClient(
    host=settings.MONGO_HOSTNAME,
)[settings.MONGO_DB]
db.authenticate(
    settings.MONGO_USERNAME,
    settings.MONGO_PASSWORD,
    settings.MONGO_AUTHENTICATION_DB)
collection_dataset_name = 'prodigy_%s_dataset' % (str(config['db_collection']),)
collection_dataset = db[collection_dataset_name]
collection_dataset.create_index('name', unique=True)
collection_dataset.create_index([('created', pymongo.ASCENDING)])
collection_dataset.create_index('session')

collection_example_name = 'prodigy_%s_example' % (str(config['db_collection']),)
collection_example = db[collection_example_name]
collection_example.create_index('input_hash')
collection_example.create_index('task_hash')

collection_link_name = 'prodigy_%s_link' % (str(config['db_collection']),)
collection_link = db[collection_link_name]
collection_link.create_index('dataset_id')
collection_link.create_index('example_id')


class MongoDatabase(Database):
    def __init__(self):
        self.db_id = 'MongoDatabase'
        self.prodigy_id = str(config['name'])
        self.db_name = '%s_%s' % (self.db_id, self.prodigy_id)

    @property
    def db(self):
        return None

    def __len__(self):
        """
        RETURNS (int): The number of datasets in the database.
        """
        return len(self.datasets)

    def __contains__(self, name):
        return collection_dataset.find_one({'name': name}) is not None

    @property
    def datasets(self):
        return [x.name
                for x in collection_dataset.find(
                {'session': False}).sort([('created', pymongo.ASCENDING)])]

    @property
    def sessions(self):
        return [x.name
                for x in collection_dataset.find(
                {'session': True}).sort([('created', pymongo.ASCENDING)])]

    def close(self):
        pass

    def reconnect(self):
        pass

    def get_examples(self, ids, by="task_hash"):
        try:
            ids = list(ids)
        except TypeError:
            ids = [ids]
        return [json.loads(x['content'])
                for x in collection_example.find({by: ids})]

    def get_meta(self, name):
        doc = collection_dataset.find_one({'name': name})
        if doc is None:
            return None
        meta = json.loads(doc['meta'])
        meta['created'] = doc['created']
        return meta

    def get_sessions_examples(self, session_ids=None):
        if session_ids is None or len(session_ids) == 0:
            raise ValueError("One or more sessions are required")

        id_to_session = {}
        for s in collection_dataset.find({'name': {'$in': session_ids}}):
            id_to_session[s['_id']] = s['name']
        links = {}
        for link in collection_link.find({'dataset_id': {'$in': list(id_to_session.keys())}}):
            links[link['example_id']] = id_to_session[link['_id']]
        examples = []
        for eg in collection_example.find({'_id': {'$in': list(links.keys())}}):
            example = json.loads(eg['content'])
            example["session_id"] = links[eg['_id']]
            examples.append(example)
        return examples

    def count_dataset(self, name, session=False):
        dataset = collection_dataset.find_one({'name': name, 'session': session})
        if dataset is None:
            raise ValueError

        return collection_link.find({'dataset_id': dataset['_id']}).count()

    def get_dataset(self, name, default=None, session=False):
        dataset = collection_dataset.find_one({'name': name, 'session': session})
        if dataset is None:
            return default

        example_ids = [x['example_id'] for x in collection_link.find({'dataset_id': dataset['_id']})]
        return [json.loads(x['content']) for x in collection_example.find({'_id': {'$in': example_ids}})]

    def get_dataset_page(self, name, page_number: int, page_size: int):
        dataset = collection_dataset.find_one({'name': name})
        if dataset is None:
            return [], -1

        query = collection_link.find({'dataset_id': dataset['_id']})
        count = query.count()

        page = query.skip(page_number - 1 if page_number > 0 else 0).limit(page_size)
        examples = collection_example.find({'_id': [x['example_id'] for x in page]})
        examples = [{
            "id": str(x['_id']),
            "content": json.loads(x['content']),
            "input_hash": x['input_hash'],
            "task_hash": x['task_hash'],
        } for x in examples]
        return examples, count

    def get_input_hashes(self, *names):
        example_ids = collection_dataset.aggregate([
            {'$match': {'name': {'$in': names}}},
            {'$lookup': {
                'from': collection_link_name,
                'localField': '_id',
                'foreignField': 'dataset_id',
                'as': 'links'
            }}
        ])
        example_ids = sum(([y['example_id'] for y in x['links']] for x in example_ids), [])
        return set(x['input_hash'] for x in collection_example.find({'_id': {'$in': example_ids}}))

    def get_task_hashes(self, *names):
        example_ids = collection_dataset.aggregate([
            {'$match': {'name': {'$in': names}}},
            {'$lookup': {
                'from': collection_link_name,
                'localField': '_id',
                'foreignField': 'dataset_id',
                'as': 'links'
            }}
        ])
        example_ids = sum(([y['example_id'] for y in x['links']] for x in example_ids), [])
        return set(x['task_hash'] for x in collection_example.find({'_id': {'$in': example_ids}}))

    def add_dataset(self, name, meta={}, session=False):
        if any([char in name for char in (",", " ")]):
            raise ValueError("Dataset name can't include commas or whitespace")
        doc = collection_dataset.find_one({'name': name})
        if doc is not None:
            return doc
        else:
            collection_dataset.insert_one({
                'name': name,
                'meta': json.dumps(meta),
                'session': session,
                'created': int(time.time()),
            })
            return collection_dataset.find_one({'name': name})

    def add_examples(self, examples, datasets=tuple()):
        examples = [
            {
                'input_hash': x[INPUT_HASH_ATTR],
                'task_hash': x[TASK_HASH_ATTR],
                'content': json.dumps(x)
            } for x in examples
        ]
        result = collection_example.insert_many(examples)
        ids = result.inserted_ids

        if type(datasets) is not tuple and type(datasets) is not list:
            raise ValueError(f"Datasets must be a tuple or list, not: {type(datasets)}")
        for dataset in datasets:
            self.link(dataset, ids)

    def link(self, dataset_name, example_ids):
        dataset = self.add_dataset(dataset_name)
        links = [{'example_id': x, 'dataset_id': dataset['_id']} for x in example_ids]
        collection_link.insert_many(links)

    def unlink(self, dataset):
        # Don't allow to remove examples
        raise NotImplementedError()
        # dataset = collection_dataset.find_one({'name': dataset})
        # if dataset is None:
        #     return
        # collection_link.delete_many({'dataset_id': dataset['_id']})

    def drop_dataset(self, name, batch_size=None):
        # Don't allow to remove examples
        raise NotImplementedError()
        # dataset = collection_dataset.find_one({'name': name})
        # if dataset is None:
        #     return
        # collection_example.delete_many(
        #     {'_id': {
        #         '$in': [x['example_id']
        #                 for x in collection_link.find({'dataset_id': dataset['_id']})]}})
        # collection_link.delete_many({'dataset_id': dataset['_id']})
        # collection_dataset.delete_many({'name': name})

    def drop_examples(self, ids, by="task_hash"):
        # Don't allow to remove examples
        raise NotImplementedError()
        # try:
        #     ids = list(ids)
        # except TypeError:
        #     ids = [ids]
        # example_ids = [x['_id'] for x in collection_example.find({by: ids})]
        # collection_example.delete_many({'_id': {'$in': example_ids}})
        # collection_link.delete_many({'example_id': {'$in': example_ids}})

    def save(self):
        pass

    def export_session(self, session_id):
        raise NotImplementedError()

    def trash_session(self, session_id=None):
        raise NotImplementedError()

    def add_to_trash(self, examples, base_path: str):
        raise NotImplementedError()

    def add_to_exports(self, examples, base_path: str):
        raise NotImplementedError()

    def write_examples(self, examples, folder_name: str, file_base: str):
        raise NotImplementedError()

    def export_sessions(self, session_ids, export_name):
        raise NotImplementedError()

    def trash_sessions(self, session_ids, export_name):
        raise NotImplementedError()

    def export_collection(self, sessions_ids_dict, collection_name):
        raise NotImplementedError()

    def trash_collection(self, sessions_ids_dict, collection_name):
        raise NotImplementedError()


# Patch DB
from prodigy.components.db import set_db

set_db(MongoDatabase())

# Patch sys arguments
import shlex

sys.argv = ['prodigy'] + shlex.split(str(config['arguments']))

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#              Prodigy app start
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

from prodigy import __main__ as prodigy_main

with open(os.path.splitext(prodigy_main.__file__)[0] + ".py") as fh:
    exec(fh.read())
