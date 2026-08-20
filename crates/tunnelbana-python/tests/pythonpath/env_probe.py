# This module lives in a directory that the test suite points PYTHONPATH at
# before the interpreter starts. It would import (and the class below would
# build successfully) if the embedded interpreter honored PYTHONPATH; the
# isolated configuration must make the import fail instead.


class EnvProbe:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        return data
