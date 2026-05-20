# libpam4j

https://invent.kde.org/plasma/plasma-login-manager

Create a user named foo.

```
sudo -s
useradd foo
passwd foo
passwd -e foo
```

Pam config.

```
cp /etc/pam.d/sshd /etc/pam.d/dummy
```

Change foo's password. Must be root.

```
make
sudo -s
./login foo # prompted twice
```

plasmalogin dependencies (fedora):


```
pam-devel
libkscreen-devel
systemd-devel
plasma-workspace-devel
libkworkspace
layer-shell-qt-devel
libplasma-devel
kf6-kio-devel
kf6-kdbusaddons-devel
kf6-kcmutils-devel
kf6-ki18n-devel
kf6-kwindowsystem-devel
qt6-qtshadertools-devel
kf6-kdeclarative-devel
qt6-qtbase-devel
cmake cmake-extras extra
```
