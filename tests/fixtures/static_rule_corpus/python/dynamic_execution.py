import importlib


def run(user_text):
    eval(user_text)
    exec(user_text)
    compile(user_text, "<fixture>", "exec")
    __import__("json")
    importlib.import_module("json")
