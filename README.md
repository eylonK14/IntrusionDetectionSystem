# Intrusion Detection System

## Execution

Linux: 

```bash
cd /dock
sudo docker-compose build
sudo docker-compose up
```

Windows:

1. Download and Install this Windows [X Server](https://sourceforge.net/projects/vcxsrv/).
2. Open XLaunch.
3. Select "Full Screen" option.
4. Select "Start no client" option.
5. Mark "Disable access control" box.
6. Click Finish.
7. Open terminal and type:

```bash
export DISPLAY=$(ip route list default | awk '{print $3}'):0
export LIBGL_ALWAYS_INDIRECT=1
```
