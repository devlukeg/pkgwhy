import marshal
import pickle


def load(payload):
    pickle.loads(payload)
    marshal.loads(payload)
