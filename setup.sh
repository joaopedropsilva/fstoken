#!/usr/bin/env bash

CWD="$(realpath "$(dirname @)")"
DAEMON=fstokend.service
DAEMON_RUNTIME_DIR=/run/fstokend
APP_PREFIX=/opt/fstoken

echo "Checking daemon status"
if systemctl is-active --quiet $DAEMON; then
    sudo systemctl stop $DAEMON
fi

echo "Installing fstoken at $APP_PREFIX"
sudo rm -rf $APP_PREFIX
sudo mkdir $APP_PREFIX
sudo cp $CWD/requirements.txt $APP_PREFIX/requirements.txt
sudo cp $CWD/setup.sh $APP_PREFIX/setup.sh
sudo cp $CWD/fstn $APP_PREFIX/fstn
sudo cp $CWD/$DAEMON $APP_PREFIX/$DAEMON
sudo cp -r $CWD/src $APP_PREFIX/src

echo "Setting up permissions"
sudo chown --recursive fstoken:fstoken $APP_PREFIX
sudo chmod --recursive 644 $APP_PREFIX
sudo chmod 755 $APP_PREFIX $APP_PREFIX/fstn $APP_PREFIX/src
sudo chmod 440 $APP_PREFIX/$DAEMON

echo "Creating python virtual environment"
sudo /usr/bin/python3 -m venv $APP_PREFIX/venv
sudo $APP_PREFIX/venv/bin/python -m pip install -r requirements.txt

echo "Creating fsktoken user"
sudo useradd \
    --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --comment "fstoken service user" \
    fstoken
sudo usermod -L fstoken

echo "Adding user to fstoken group"
sudo usermod -aG fstoken $USER

echo "Setting up daemon"
sudo cp $APP_PREFIX/$DAEMON /etc/systemd/system
sudo systemctl daemon-reexec
sudo systemctl enable --now $DAEMON

echo "Creating keystore.db"
sudo mkdir -p $DAEMON_RUNTIME_DIR
sudo touch $DAEMON_RUNTIME_DIR/keystore.db
sudo chmod 600 $DAEMON_RUNTIME_DIR/keystore.db
sudo chown fstoken:fstoken $DAEMON_RUNTIME_DIR/keystore.db

echo "Adding cli to user PATH"
export PATH=$PATH:$APP_PREFIX

