# node-sync-dot-com-fuse
FUSE file system for sync.com

# Disclaimer

This software is not supported by sync.com and is still very experimental.
I will not be responsible for any data loss other issues.

# Installation Linux

## Debian Buster

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

Create ./mnt folder and copy .env.example, change the credentials and run the application.

```bash
mkdir ./mnt/
cp ./.env.example ./.env
# Edit .env
node ./SyncAPI.js
```
# Issues

* Right now I use a cache file (you must have enough free space for the file you will read), so it means the read must be sequential and not blocking.
  * VLC is playing with release the file and have a weird behavior, so it fails.
  * Reading picture is similar because they read the end of file at a time.
* When the file descriptor is released, I remove the cache file. If there is access later like on VLC it fails too.
* There is no throttling right now, so sometimes there are NGINX issues. I think it's related because I do to many requests to fast.
* It can be impossible to browse when reading if you use too much "threads".

# Tested

* Linux (Debian Buster)
  * Reading video file with MPV
    * There is like a read ahead at start, but it doesn't care when reading further
  * Copying file

# To-do

* Implement upload
* Implement move
* Implement delete
* Implement throttling for download
* Find a way to download the needed chunk instead of sequentially
* Find a way to remove the cache file

# Credits

All the codes related to sync.com (login, decrypt... are from sync.com website) and is available with the debugger.
Big thanks to take the time to reading my questions and answer them.
