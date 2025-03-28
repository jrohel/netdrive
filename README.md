# NetMount
-----------
NetMount allows DOS to mount directories from remote computers as network drives. It consists of two programs.

- **`netmount`**: Driver (TSR program) for DOS, which allows to mount and unmount remote directories as network drives.
- **`netmount-server`**: Program for Linux (but can be adapted for other operating systems), which shares directories as drives.

-----
## `netmount`
- DOS client (driver)
- Allows to mount and unmount remote directories from multiple servers without rebooting.
- Has minimal dependencies, only needs DOS Packet Driver.
- Implements Ethernet Type II frame, ARP, IPv4, UDP and its own NetMount protocol.
- It works over Ethernet, but if using the appropriate packet driver, it also works over other devices. For example, over a serial port using SLIP.
- It should work with MS-DOS 5.0 and newer and with sufficiently compatible systems such as FreeDOS.
- Written in C99 and assembler for Open Watcom v2 compiler.

### Usage:
```
NETMOUNT INSTALL /IP:<local_ipv4_addr> [/MASK:<net_mask>] [/GW:<gateway_addr>]
         [/PORT:<local_udp_port>] [/PKT_INT:<packet_driver_int>]

NETMOUNT MOUNT <remote_ipv4_addr>[:<remote_udp_port>]/<remote_drive_letter>
         <local_drive_letter>

NETMOUNT UMOUNT <local_drive_letter>

NETMOUNT UMOUNT /ALL

Commands:
INSTALL                      Installs NetMount as resident (TSR)
MOUNT                        Mounts remote drive as local drive
UMOUNT                       Unmounts local drive(s) from remote drive

Arguments:
/IP:<local_ipv4_addr>        Sets local IP address
/PORT:<local_udp_port>       Sets local UDP port. 12200 by default
/PKT_INT:<packet_driver_int> Sets interrupt of used packet driver.
                             First found in range 0x60 - 0x80 by default.
/MASK:<net_mask>             Sets network mask
/GW:<gateway_addr>           Sets gateway address
<local_drive_letter>         Specifies local drive to mount/unmount (e.g. H)
<remote_drive_letter>        Specifies remote drive to mount/unmount (e.g. H)
/ALL                         Unmount all drives
<remote_ipv4_addr>           Specifies IP address of remote server
<remote_udp_port>            Specifies remote UDP port. 12200 by default
/?                           Display this help
```

-----
## `netmount-server`
- A directory sharing server. It is written for Linux, but can be adapted for other operating systems.
- Allows to share directories as drives.
- Allows listening on different IP addresses and UDP ports. This allows to run multiple instances on the server with different configurations.
- It can run under a regular unprivileged user.
- It is CPU architecture independent. I am currently developing it on x86-64, but it should work on other architectures as well. Both little and big endian architectures are supported.
- Written in C++20. Tested compilation using GCC and Clang.

### Usage:
```
Usage:
./netmount-server [--help] [--bind_ip_addr=] [--bind_port=udp_port] <drive>=<root_path> [... <drive>=<root_path>]

Options:
  --help                   Display this help
  --bind-addr=<IP_ADDR>    IP address to bind, all address ("0.0.0.0") by default
  --bind-port=<UDP_PORT>   UDP port to listen, 12200 by default
  <drive>=<root_path>      drive - DOS drive C-Z, root_path - paths to serve
```

-----
## Backgroud

I was looking for possibilities to mount remote directories on old laboratory devices that use the DOS operating system. I was looking for software that allows to mount and unmount remote directories without rebooting and works over IP.  Because the mentioned laboratory devices do not have a network card, but only an RS232 serial port, the software must work over it. The used laboratory devices have little RAM and low CPU power.

I haven't found any software that meets the requirements. The closest was the program `etherdfs`, but even that does not meet several requirements. So I decided to write my own.

In the past I have written software for various industrial embedded devices. For example, industrial protocol converters, drivers for special hardware, realtime signal processing software, etc. So it is not a problem to write something new. But there is a problem with the documentation. For example, when writing industrial communication, there is an official standard to meet. When writing `NetMount`, I didn't find an official standard (API documentation) of MS-DOS interface for writing drivers. So I read the texts and source codes I found on the internet. I would specifically mention RBIL, the source code of `etherdfs-server`, `etherdfs-client`. Thanks to the authors of these documentation and software.

I decided to publish my work as open source to help other people.

During development I am testing a DOS client in DOSEM running on Linux. I also tried basic tests on a physical device with MS-DOS 6.22 and FreeDOS 1.3. When testing on a physical device, I used the RS232 serial port instead of a network card and the "ethersl.com" packet driver from Crynwr, which implements SLIP.