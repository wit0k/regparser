# https://packaging.python.org/guides/creating-and-discovering-plugins/
from importlib import import_module
from pkgutil import iter_modules
import plugins

""" TO DO 
- Plugin manager shall check if new plugins are compliant with plugin structure
"""

class plugin_manager(object):

    def __init__(self, regparser):
        self.regparser = regparser
        self.installed_plugins = self._installed_plugins()
        self.required_functions = ("execute", "format_data")

    def load(self, plugin_to_execute):

        plugin_args = plugin_to_execute.split(" ")
        plugin_name = plugin_args[0]

        full_plugin_name = self.is_installed(plugin_name)

        if full_plugin_name:
            plugin_object = getattr(self.installed_plugins[full_plugin_name], plugin_name)

            for _func in self.required_functions:
                if not getattr(plugin_object, _func, None):
                    self.regparser.debug_print(f"ERROR: Plugin: {full_plugin_name} -> Msg: Function {_func} not found!")
                    return _plugin(None, None, None, None)

            return _plugin(plugin_name, full_plugin_name, plugin_args, plugin_object)
        else:
            print(f"Error: Plugin: {plugin_name} is not installed!")
            return _plugin(None, None, None, None)

    def is_installed(self, plugin_name):
        installed = None

        for _installed_plugin_name in self.installed_plugins.keys():
            try:
                _plugin_name = _installed_plugin_name[_installed_plugin_name.rindex(".") + 1:]
                if plugin_name == _plugin_name:
                    return _installed_plugin_name
            except ValueError:
                continue

        return installed

    """ Helper functions """
    def _installed_plugins(self):

        # Get the list of installed plugins
        installed_plugins = {
            name: import_module(name)
            for finder, name, ispkg
            in self._iter_namespace(plugins)
        }

        return installed_plugins

    def _iter_namespace(self, ns_pkg):
        # Specifying the second argument (prefix) to iter_modules makes the
        # returned name an absolute name instead of a relative one. This allows
        # import_module to work without having to do additional modification to
        # the name.
        return iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")

class _plugin(object):

    def __init__(self, plugin_name, full_plugin_name, plugin_args, plugin_object):
        self.plugin_name = plugin_name
        self.full_plugin_name = full_plugin_name
        self.args = plugin_args
        self._obj = plugin_object

    def name(self):
        return self.plugin_name

    def full_name(self):
        return self.full_plugin_name

    def obj(self):
        return self._obj()

    def execute(self, parser_object):
        try:
            # Initialize respective plugin
            self._obj = self._obj(self, parser_object)
            self._obj.execute()
        except Exception as e:
            print(f'ERROR: plugin_manager -> _plugin({self.plugin_name}) -> Exception: {str(e)}')
