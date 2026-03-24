# SSH VPN

A lightweight graphical SSH VPN client for Linux, built with GTK3 and powered by [sshuttle](https://github.com/sshuttle/sshuttle) under the hood.

---

## Features

- One-click connect / disconnect
- Routing exclusions — bypass VPN for specific domains, TLDs or IPs
- Multiple VPN configurations

---

## Requirements

### Client

```bash
# Debian / Ubuntu
sudo apt install build-essential libgtk-3-dev libssh-dev sshuttle sshpass

# Fedora
sudo dnf install gcc-c++ gtk3-devel libssh-devel sshuttle sshpass

# Arch
sudo pacman -S base-devel gtk3 libssh sshuttle sshpass
```

---

## Build

```bash
g++ -o sshvpn ssh-vpn.cpp \
    $(pkg-config --cflags --libs gtk+-3.0 libssh) \
    -lpthread -std=c++17

sudo ./sshvpn
```

---

## Usage

1. Click **＋ Add VPN** and fill in your server details
2. Select the configuration from the list
3. Click **Connect**
4. To exclude traffic from VPN — click **⚙ Routing Exclusions**

---
