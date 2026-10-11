# Bingo Command Cheatsheet

## Discover Commands

```bash
bingo --version
bingo --help
bingo <command> --help
```

## Install and Upgrade

```bash
pip3 install openubmc-bingo
bingo upgrade
bingo upgrade --version bingo=latest
bingo upgrade --version 'bingo>=<version>'
```

## Component Workspace

```bash
cd <component-repo>
bingo gen
bingo build -bt debug
bingo build -bt release --stage rc
bingo build --conan2
bingo build -u -r <conan_remote>
bingo test
bingo analysis -r <conan_remote>
```

## Manifest Workspace

```bash
cd manifest
bingo build --help
bingo build -t personal -b openUBMC -bt release --stage rc
bingo build -t publish -sc default -b openUBMC -bt release --stage stable
bingo publish -sc default -b openUBMC -bt release --stage stable
bingo analysis -b openUBMC
```

## Source Fetch

```bash
bingo fetch -b openUBMC --stage stable -p ./source_code
bingo fetch --manifest_yml build/product/BMC/openUBMC/manifest.yml -p ./source_code
bingo fetch -sys hardware --stage stable -p ./source_code
bingo fetch -pi package_info.yml -p ./source_code
bingo fetch -pi component/1.2.3@openubmc/stable -p ./source_code
```

## Version Traceability

```bash
bingo diff <commit-before> <commit-after>
```

## Lockfile

```bash
bingo lock -c -r <conan_remote>
bingo lock -u <component_name> -r <conan_remote>
```

## Configuration

```bash
bingo config -l
bingo config env.http_proxy=http://proxy.example.com:8080
bingo config --local env.http_proxy=http://proxy.example.com:8080
bingo config --unset env.http_proxy
```
