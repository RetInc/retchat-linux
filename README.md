# retchat for linux

> simple cli client for the retchat protocol


## building

> dependencies:
- `git`
- `CMake`
- `OpenSSL`

> steps:
1. clone the repo: `git clone https://github.com/retinc/retchat-linux && cd retchat-linux`
2. create build directory: `mkdir -p build && cmake -B build`
3. build: `cmake --build build`


## running

> arguments:

| arg  | desc                                         |
|------|----------------------------------------------|
| `-h` | host (e. g. `retucio.me` or `192.168.1.142`) |
| `-p` | port (e. g. `6677`)                          |
| `-n` | nickname (e. g. `dumbass`)                   |
| `-r` | room (e. g. `lobby`)                         |

> commands:

| command  | usage                        | description                              |
|----------|------------------------------|------------------------------------------|
| `/nick`  | `/nick <nick>`               | changes your nickname.                   |
| `/join`  | `/join <room>`               | joins a room.                            |
| `/dm`    | `/dm <target> <message>`     | direct message a user in the same room.  |
| `/image` | `/image (target) <filename>` | send an image to a room chat or dm.      |
| `/exit` \| `/quit` | `/exit` \| `/quit` | disconnect the client and exit.          |


## protocol spec

can be found [here](https://github.com/retinc/retchat-docs)


## license

MIT i guess


## contributions

yes please :P