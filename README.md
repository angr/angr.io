# angr site generator

The angr website and blog are generated with the Hugo static site generator.

## Previewing Locally
```
make
```

## Deploying
Deployment is done through Travis.
When new commits go into master, Travis checks them for outdated code and if they pass, they are deployed to [angr.github.io](https://github.com/angr/angr.github.io).
