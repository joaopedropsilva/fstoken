#!/usr/bin/env bash

CWD="$(realpath "$(dirname @)")"
SERVICE=fstokend.service
APP_PREFIX=/opt/fstoken

echo "Checking daemon status"
if systemctl is-active --quiet $SERVICE; then
    sudo systemctl stop $SERVICE
fi

echo "Installing fstoken at $APP_PREFIX"
sudo rm -rf $APP_PREFIX
sudo mkdir $APP_PREFIX
sudo cp $CWD/requirements.txt $APP_PREFIX/requirements.txt
sudo cp $CWD/setup.sh $APP_PREFIX/setup.sh
sudo cp $CWD/fstn $APP_PREFIX/fstn
sudo cp $CWD/$SERVICE $APP_PREFIX/$SERVICE
sudo cp -r $CWD/src $APP_PREFIX/src

echo "Setting up permissions"
sudo chown --recursive fstoken:fstoken $APP_PREFIX
sudo chmod --recursive 644 $APP_PREFIX
sudo chmod 755 $APP_PREFIX $APP_PREFIX/fstn $APP_PREFIX/src
sudo chmod 440 $APP_PREFIX/$SERVICE

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

echo "Setting up service"
sudo cp $APP_PREFIX/$SERVICE /etc/systemd/system
sudo systemctl daemon-reexec
sudo systemctl enable --now $SERVICE

echo "Creating keystore.db"
sudo touch $APP_PREFIX/keystore.db
sudo chmod 600 $APP_PREFIX/keystore.db
sudo chown fstoken:fstoken $APP_PREFIX/keystore.db

echo "Adding cli to user PATH"
export PATH=$PATH:$APP_PREFIX

