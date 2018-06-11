# angr site generator

The angr website and blog are generated with the Hugo static site generator.

## Running Locally
```
make
```

## Checking for Out Of Date Code
To help keep the angr blog up to date, there is a python script which will search through your local copy of angr to ensure that all of the code on the blog is also present in the angr codebase.
```
export ANGR_ROOT=<location of your angr-dev directory>
make check
```
This will also create a Python 3 virtualenv called `hugo` into which the checking script's dependencies will be installed. If you have python3 installed somewhere other than `/bin/python3`, change the `PYTHON3_LOCATION` variable in the bash script to the correct path before running `make check`.

## Deploying
```
make update
```
Note: this will also run `make check` to make sure that there is no out of date code.

## Uninstalling
To remove the virtualenv and dependencies:
```
make uninstall
```

## Cleaning
To remove the current `public` directory:
```
make clean
```
To reclone it without rebuilding or redeploying the site:
```
make public
```
