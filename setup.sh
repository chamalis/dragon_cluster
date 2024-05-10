#!/bin/bash

#                  #                  #
# assumes dragonfly already installed #
#                  #                  #

source .env

SRC_ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SRC_ROOT" || exit 1

if [ ! -f "$DRAGON_CONF_FILE" ]; then
  echo "Error: $DRAGON_CONF_FILE was not found, exiting ..."
  exit 1
fi

pip install -r requirements.txt

# modify the dragon conf file #

/usr/bin/cp "$DRAGON_CONF_FILE" "${DRAGON_CONF_FILE}.bak"

if [ $(grep -c "admin_port" "$DRAGON_CONF_FILE") -gt 0 ]; then
  # already exists in the conf file, replace the value
  sed -i  "/^admin_port /s/=.*$/= ${REDIS_ADM_PORT}/"  $DRAGON_CONF_FILE
else  # add
  echo -e "\n--admin_port=${REDIS_ADM_PORT}" | tee -a "$DRAGON_CONF_FILE"
fi

if [ $(grep -c "cluster_mode" "$DRAGON_CONF_FILE") -gt 0 ]; then
  # already exists in the conf file, replace the value
  sed -i  '/^cluster_mode /s/=.*$/= yes/'  $DRAGON_CONF_FILE
else  # add
  echo -e "\n--cluster_mode=yes" | tee -a "$DRAGON_CONF_FILE"
fi

# if cluster conf is not already there put our template #
if [ ! -f "$CLUSTER_CONF_FILE" ]; then
  /usr/bin/mv  cluster.conf  "$CLUSTER_CONF_FILE"
fi

# if systemd files are not already there, put our templates
if [ ! -f /etc/systemd/system/reconf_dragon_online.path ]; then
  /usr/bin/cp  ./systemd/reconf_dragon_online.path  /etc/systemd/system/
fi

if [ ! -f /etc/systemd/system/reconf_dragon_online.service ]; then
  /usr/bin/cp  ./systemd/reconf_dragon_online.service  /etc/systemd/system/
  sed -i "s|/usr/local/sbin/reconf_dragon_online.py|${SCRIPT_PATH}|g" /etc/systemd/system/reconf_dragon_online.service
fi

echo "Finished the preparations"