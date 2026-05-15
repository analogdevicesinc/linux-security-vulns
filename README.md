# Linux Security Vulns



## Development of the docs scripts

Development mode allows to edit the source code and apply the changes in watch
mode.

### Install the web compiler

If you care about the web scripts (`js modules`) and style sheets (`sass`),
install `npm` first, if not, just skip this section.

> **_NOTE:_** If the ``npm`` provided by your package manager is too old and
> updating with `npm install npm -g` fails, consider installing with
> [NodeSource](https://github.com/nodesource/distributions).

At the repository root, install the `npm` dependencies locally:
```
npm install rollup \
    @rollup/plugin-terser \
    @rollup/plugin-alias \
    sass \
    --save-dev
```

### Install doctools

With `doctools` cloned alongside this repository, do a symbolic install
```
cd ../doctools
pip install -e . --upgrade
```

### Launch the servers

In two terminals, launch `adoc serve` to watch the doc:

```
cd docs
adoc serve
```

Then, in the second, the source code watcher:

```
wget https://raw.githubusercontent.com/analogdevicesinc/analogdevicesinc.github.io/refs/heads/main/dev_server.py
python3 dev_server.py
```

This way, changes to `./scripts` and `./style` are re-evaluated.