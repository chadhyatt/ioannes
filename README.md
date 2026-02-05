# Ioannes

Ioannes is a tool and internal DLL for Rocket League designed to assist with reverse engineering and analysis of RL's game networking protocol.

### Features

* Internal ImGui-based user interface (toggle with the `INS` key)
* Embedded Lua 5.1 ([gopher-lua](https://github.com/yuin/gopher-lua)) scripting API for networking-releated functions and MITM hooks. See: [scripts/](https://github.com/chadhyatt/ioannes/tree/master/scripts), [proxy/lua.go](https://github.com/chadhyatt/ioannes/blob/master/proxy/lua.go)
* Real-time packet sniffer and list for viewing decrypted incoming/outgoing packets

> [!NOTE]
> This project was developed to assist in finding vulnerabilities for Epic Games' bug bounty program, and with Rocket League potentially [moving to EAC](https://steamdb.info/changelist/33486621/) in the near future, I've decided to release this project for both reference and learning. It is NOT in a complete state, expect plenty of bugs and inaccuracies!
>
> With that being said:
> * This project is provided without warranty of any kind, or guaranteed support.
> * I am not a C++, or Windows developer. I give no guarantees of expert code. 😀

## Install

*Pre-built binaries are available on the [releases](https://github.com/chadhyatt/ioannes/releases) page.*

### Prerequisites
Ioannes targets the MinGW-w64 toolchain, and isn't tested elsewhere. If you're using Windows, you can use [MSYS2](https://www.msys2.org/) and install prerequisites and build in that environment.
* `meson`
* `ninja`
* `cmake`
* `go`
* `mingw-w64-x86_64-toolchain`

```
git clone --depth 1 --recursive https://github.com/chadhyatt/ioannes.git
cd ioannes
./build.sh --clean --release
```

*See [build.sh](build.sh) for build options*

## License

See [LICENSE](LICENSE). For 3rd-party libraries and dependencies used, see [THIRDPARTY](THIRDPARTY).

```
MIT License

Copyright (c) 2026 Chad Hyatt <chad@hyatt.page>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
