# node-sync-dot-com-fuse
FUSE file system for sync.com

# Installation Linux

## Debian

Install git

```bash
apt install git
```

First install `n` for using the stable NodeJS (right now stable is 17.2.0) see https://github.com/tj/n#installation and select the stable version

```bash
sudo n stable
```

Clone the repository

```bash
git clone https://github.com/k-aito/node-sync-dot-com-fuse.git
cd ./node-sync-dot-com-fuse
```

Install the needed NPM modules

```bash
npm install
```

Change the credentials in .env, create a mnt folder and run the application

```bash
# Edit .env
mkdir ./mnt/
node ./SyncAPI.js
```
