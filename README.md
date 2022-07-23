# sshcap

Simple service to impersonate an ssh server and log all authentication attempts to disk. 
Run with `--help` to see options.

```
Usage: sshcap.py [OPTIONS]

Options:
  --banner TEXT      SSH banner to advertise
  --port INTEGER     Port to listen on
  --log-file TEXT    File to log captured auth attempts
  --server-key TEXT  SSH server key file
  --help             Show this message and exit.
```
