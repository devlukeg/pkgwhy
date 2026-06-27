import marshal
import pickle
import yaml


def load(payload):
    pickle.loads(payload)
    marshal.loads(payload)
    yaml.load(payload)
