import logging

""" Logger settings """
logger = logging.getLogger('plugin')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
log_console_format = logging.Formatter('%(levelname)s - THREAD-%(thread)d - %(asctime)s - %(filename)s - %(funcName)s - %(message)s')
console_handler.setFormatter(log_console_format)
logger.addHandler(console_handler)

#logger.setLevel(logging.NOTSET)  # Would be set by a parameter
#logger_verobse_levels = ["INFO", "WARNING", "ERROR", "DEBUG"]

class plugin(object):

    name = ""

    """ Baseline params """
    compare_fields = ["key_path", "value_name", "value_content"]

    def __init__(self, plugin, regparser):
        pass

    def execute(self):
        print("Execute plugin: '%s'" % self.name)
        pass

    def format_data(self, _item_fields):
        pass
