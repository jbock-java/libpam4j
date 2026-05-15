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
