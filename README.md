[![CMake](https://github.com/whoenig/NatNetSDKCrossplatform/actions/workflows/cmake.yml/badge.svg)](https://github.com/whoenig/NatNetSDKCrossplatform/actions/workflows/cmake.yml)


# NatNetSDKCrossplatform

This repository contains the NatNet SDK to receive data from an OptiTrack Motion Capture system. The SDK can be found at https://optitrack.com/products/natnet-sdk/.

This code contains the direct depacketization method, which is fully open-source. The PacketClient helper was taken from this SDK (version 4.1.0, Windows). The portions of the SDK that have been used and are part of this repository are licensed under Apache License, Version 2.0. The remaining code is licensed under MIT. This uses boost asio for communication.

## Layout

- `samples`: Official samples (PacketClient from the Windows version of the SDK but fixed)
- `src`: The actual source code of the crossplatform port, based on the depacketization method.

## Build

Tested on Ubuntu 22.04, Jetson Orin NX

```
mkdir build
cd build
cmake ..
make
```

## Run

Test the open-source version:

```
./packetClient <IP-where-motive-is-running>
```

## Notes

There are two communication channels:

* Command (to send commands over UDP)
* Data (UDP multicast receiver)

This assumes the following default settings:

* multicast address: 239.255.42.99
* command port: 1510
* data port: 1511
