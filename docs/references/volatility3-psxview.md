---
source_url: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.psxview.html
retrieved: 2026-06-06
fetched_with: scrapling extract get --ai-targeted
trust: UNTRUSTED third-party content captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher.
---

> Source: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.psxview.html
> Retrieved 2026-06-06 via Scrapling (get).

---

[![Logo](_static/vol.png)](index.html)

Documentation

* [Volatility 3 Basics](basics.html)
* [Writing Plugins](development.html)
* [Creating New Symbol Tables](symbol-tables.html)
* [Changes between Volatility 2 and Volatility 3](vol2to3.html)
* [Volshell - A CLI tool for working with memory](volshell.html)
* [Glossary](glossary.html)

Getting Started

* [Linux Tutorial](getting-started-linux-tutorial.html)
* [macOS Tutorial](getting-started-mac-tutorial.html)
* [Windows Tutorial](getting-started-windows-tutorial.html)

Python Packages

* [volatility3 package](volatility3.html)
  + [`WarningFindSpec`](volatility3.html#volatility3.WarningFindSpec)
  + [`classproperty`](volatility3.html#volatility3.classproperty)
  + [Subpackages](volatility3.html#subpackages)
    - [volatility3.cli package](volatility3.cli.html)
    - [volatility3.framework package](volatility3.framework.html)
    - [volatility3.plugins package](volatility3.plugins.html)
      * [Subpackages](volatility3.plugins.html#subpackages)
      * [Submodules](volatility3.plugins.html#submodules)
    - [volatility3.schemas package](volatility3.schemas.html)
    - [volatility3.symbols package](volatility3.symbols.html)

[Volatility 3](index.html)

* [volatility3 package](volatility3.html)
* [volatility3.plugins package](volatility3.plugins.html)
* [volatility3.plugins.windows package](volatility3.plugins.windows.html)
* volatility3.plugins.windows.psxview module
* [View page source](_sources/volatility3.plugins.windows.psxview.rst.txt)

---

volatility3.plugins.windows.psxview module[](#module-volatility3.plugins.windows.psxview "Link to this heading")
=================================================================================================================

*class* PsXView(*context*, *config\_path*, *progress\_callback=None*)[[source]](_modules/volatility3/plugins/windows/psxview.html#PsXView)[](#volatility3.plugins.windows.psxview.PsXView "Link to this definition")
:   Bases: [`PluginInterface`](volatility3.framework.interfaces.plugins.html#volatility3.framework.interfaces.plugins.PluginInterface "volatility3.framework.interfaces.plugins.PluginInterface"), [`PluginRenameClass`](volatility3.framework.deprecation.html#volatility3.framework.deprecation.PluginRenameClass "volatility3.framework.deprecation.PluginRenameClass")

    Lists all processes found via four of the methods described in “The Art of Memory Forensics” which may help identify processes that are trying to hide themselves.

    We recommend using -r pretty if you are looking at this plugin’s output in a terminal.
    deprecated.

    Parameters:
    :   * **context** ([`ContextInterface`](volatility3.framework.interfaces.context.html#volatility3.framework.interfaces.context.ContextInterface "volatility3.framework.interfaces.context.ContextInterface")) – The context that the plugin will operate within
        * **config\_path** ([`str`](https://docs.python.org/3/library/stdtypes.html#str "(in Python v3.14)")) – The path to configuration data within the context configuration data
        * **progress\_callback** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional "(in Python v3.14)")[[`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable "(in Python v3.14)")[[[`float`](https://docs.python.org/3/library/functions.html#float "(in Python v3.14)"), [`str`](https://docs.python.org/3/library/stdtypes.html#str "(in Python v3.14)")], [`None`](https://docs.python.org/3/library/constants.html#None "(in Python v3.14)")]]) – A callable that can provide feedback at progress points

    build\_configuration()[](#volatility3.plugins.windows.psxview.PsXView.build_configuration "Link to this definition")
    :   Constructs a HierarchicalDictionary of all the options required to
        build this component in the current context.

        Ensures that if the class has been created, it can be recreated
        using the configuration built Inheriting classes must override
        this to ensure any dependent classes update their configurations
        too

        Return type:
        :   [`HierarchicalDict`](volatility3.framework.interfaces.configuration.html#volatility3.framework.interfaces.configuration.HierarchicalDict "volatility3.framework.interfaces.configuration.HierarchicalDict")

    *property* config*: [HierarchicalDict](volatility3.framework.interfaces.configuration.html#volatility3.framework.interfaces.configuration.HierarchicalDict "volatility3.framework.interfaces.configuration.HierarchicalDict")*[](#volatility3.plugins.windows.psxview.PsXView.config "Link to this definition")
    :   The Hierarchical configuration Dictionary for this Configurable
        object.

    *property* config\_path*: [str](https://docs.python.org/3/library/stdtypes.html#str "(in Python v3.14)")*[](#volatility3.plugins.windows.psxview.PsXView.config_path "Link to this definition")
    :   The configuration path on which this configurable lives.

    *property* context*: [ContextInterface](volatility3.framework.interfaces.context.html#volatility3.framework.interfaces.context.ContextInterface "volatility3.framework.interfaces.context.ContextInterface")*[](#volatility3.plugins.windows.psxview.PsXView.context "Link to this definition")
    :   The context object that this configurable belongs to/configuration
        is stored in.

    *classmethod* get\_requirements()[[source]](_modules/volatility3/plugins/windows/malware/psxview.html#PsXView.get_requirements)[](#volatility3.plugins.windows.psxview.PsXView.get_requirements "Link to this definition")
    :   Returns a list of Requirement objects for this plugin.

    *classmethod* make\_subconfig(*context*, *base\_config\_path*, *\*\*kwargs*)[](#volatility3.plugins.windows.psxview.PsXView.make_subconfig "Link to this definition")
    :   Convenience function to allow constructing a new randomly generated
        sub-configuration path, containing each element from kwargs.

        Parameters:
        :   * **context** ([`ContextInterface`](volatility3.framework.interfaces.context.html#volatility3.framework.interfaces.context.ContextInterface "volatility3.framework.interfaces.context.ContextInterface")) – The context in which to store the new configuration
            * **base\_config\_path** ([`str`](https://docs.python.org/3/library/stdtypes.html#str "(in Python v3.14)")) – The base configuration path on which to build the new configuration
            * **kwargs** – Keyword arguments that are used to populate the new configuration path

        Returns:
        :   The newly generated full configuration path

        Return type:
        :   [str](https://docs.python.org/3/library/stdtypes.html#str "(in Python v3.14)")

    *property* open[](#volatility3.plugins.windows.psxview.PsXView.open "Link to this definition")
    :   Returns a context manager and thus can be called like open

    run()[[source]](_modules/volatility3/plugins/windows/malware/psxview.html#PsXView.run)[](#volatility3.plugins.windows.psxview.PsXView.run "Link to this definition")
    :   Executes the functionality of the code.

        Note

        This method expects self.validate to have been called to ensure all necessary options have been provided

        Returns:
        :   A TreeGrid object that can then be passed to a Renderer.

    set\_open\_method(*handler*)[](#volatility3.plugins.windows.psxview.PsXView.set_open_method "Link to this definition")
    :   Sets the file handler to be used by this plugin.

        Return type:
        :   [`None`](https://docs.python.org/3/library/constants.html#None "(in Python v3.14)")

    *classmethod* unsatisfied(*context*, *config\_path*)[](#volatility3.plugins.windows.psxview.PsXView.unsatisfied "Link to this definition")
    :   Returns a list of the names of all unsatisfied requirements.

        Since a satisfied set of requirements will return [], it can be used in tests as follows:

        ```
        unmet = configurable.unsatisfied(context, config_path)
        if unmet:
            raise RuntimeError("Unsatisfied requirements: {}".format(unmet)
        ```

        Return type:
        :   [`Dict`](https://docs.python.org/3/library/typing.html#typing.Dict "(in Python v3.14)")[[`str`](https://docs.python.org/3/library/stdtypes.html#str "(in Python v3.14)"), [`RequirementInterface`](volatility3.framework.interfaces.configuration.html#volatility3.framework.interfaces.configuration.RequirementInterface "volatility3.framework.interfaces.configuration.RequirementInterface")]

    valid\_proc\_name\_chars *= {' ', '.', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}*[](#volatility3.plugins.windows.psxview.PsXView.valid_proc_name_chars "Link to this definition")

    version *= (1, 0, 0)*[](#volatility3.plugins.windows.psxview.PsXView.version "Link to this definition")

[Previous](volatility3.plugins.windows.pstree.html "volatility3.plugins.windows.pstree module")
[Next](volatility3.plugins.windows.scheduled_tasks.html "volatility3.plugins.windows.scheduled_tasks module")

---

© Copyright 2012-2026, Volatility Foundation.

Built with [Sphinx](https://www.sphinx-doc.org/) using a
[theme](https://github.com/readthedocs/sphinx_rtd_theme)
provided by [Read the Docs](https://readthedocs.org).