# angr site generator

The angr website and blog are generated with the Hugo static site generator.

## Previewing Locally

On your host system, install Hugo, and Python requirements in requirements.txt, then:

```
make
```

Alternatively, if you have Docker installed:

```
docker build -t angr-website .
docker run -it --rm -v $PWD:/work -w /work --net=host angr-website make
```

## Checking for Out Of Date Code
To help keep the angr blog up to date, there is a python script which will search through your local copy of angr to ensure that all of the code on the blog is also present in the angr codebase.
```
export ANGR_ROOT=<location of your angr-dev directory>
make check
```
This will also create a Python 3 virtualenv called `hugo` into which the checking script's dependencies will be installed.

To add a block of code in a post to be checked, instead of using the `python` syntax type, use the `sc` syntax type (you can think about this as standing for "search code").
Currently, code searching only works for Python code excerpts.

## Deploying
Deployment is done through Travis.
When new commits go into master, Travis checks them for outdated code and if they pass, they are deployed to [angr.github.io](https://github.com/angr/angr.github.io).

## Uninstalling
To remove the virtualenv and dependencies:
```
make uninstall
```
