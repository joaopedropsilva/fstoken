#!/usr/bin/bash

CWD="$(realpath "$(dirname @)")"
DAEMON=fstokend.service
APP_PREFIX=/opt/fstoken

echo "Checking daemon status"
if systemctl is-active --quiet $DAEMON; then
    sudo systemctl stop $DAEMON
fi

echo "Creating fsktoken user"
sudo useradd \
    --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --comment "fstoken service user" \
    fstoken
sudo usermod -L fstoken

echo "Installing fstoken at /opt"
sudo rm -rf $APP_PREFIX
sudo mkdir $APP_PREFIX
sudo cp $CWD/requirements.txt $APP_PREFIX/requirements.txt
sudo cp $CWD/$DAEMON $APP_PREFIX/$DAEMON
sudo cp -r $CWD/src $APP_PREFIX/src

echo "Creating python virtual environment"
sudo /usr/bin/python3 -m venv $APP_PREFIX/venv
sudo $APP_PREFIX/venv/bin/python -m pip install -r requirements.txt

echo "Setting up permissions"
sudo chown --recursive fstoken:fstoken $APP_PREFIX
sudo chmod --recursive 550 $APP_PREFIX
sudo chmod 440 $APP_PREFIX/$DAEMON

echo "Setting up daemon"
sudo cp $APP_PREFIX/$DAEMON /etc/systemd/system
sudo systemctl daemon-reexec
sudo systemctl enable --now $DAEMON

