# sshcap

Simple service to impersonate an ssh server and log all authentication attempts to disk. 
Run with `--help` to see options.

Requires python3.8+

## Setup

```
git clone https://github.com/naiello/sshcap.git
cd sshcap
ssh-keygen -f sshcap.key            # do not set a passphrase
pip3.8 install -r requirements.txt
sudo python3.8 sshcap.py            # root is required to bind to port 22 on many linux systems
python3.8 sshcap.py --port 2222     # high-numbered ports generally do not require root
```

### Running as a systemd service

Copy `sshcap.service` to `/etc/systemd/system/sshcap.service`.
The unit file assumes sshcap is installed in `/opt/sshcap`. If it is not, modify the file
to point to the correct install dir.

```
sudo systemctl daemon-reload
sudo systemctl start sshcap
sudo systemctl status sshcap  # verify everything started correctly
sudo systemctl enable sshcap  # start at system boot
```

## Usage

```
Usage: sshcap.py [OPTIONS]

Options:
  --banner TEXT      SSH banner to advertise
  --port INTEGER     Port to listen on
  --log-file TEXT    File to log captured auth attempts
  --server-key TEXT  SSH server key file
  --help             Show this message and exit.
```
