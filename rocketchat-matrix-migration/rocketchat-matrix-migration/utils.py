# -*- coding: utf-8 -*-
# Copyright 2019, 2020 Awesome Technologies Innovationslabor GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import gzip
import json
import sys
import zipfile
from datetime import datetime

import sqlite3
import requests
import traceback

import os
import logging

from alive_progress import alive_bar

LOG_LEVEL = os.environ.get('LOG_LEVEL', "INFO").upper()

logging.basicConfig(level=LOG_LEVEL)
log = logging.getLogger('ROCKETCHAT.MIGRATE')
log_filename = "log/migration.log"
os.makedirs(os.path.dirname(log_filename), exist_ok=True)
fileHandler = logging.FileHandler(log_filename, mode="w", encoding=None, delay=False)
log.addHandler(fileHandler)
# consoleHandler = logging.StreamHandler()
# consoleHandler.setFormatter(logFormatter)
# log.addHandler(consoleHandler)


def send_event(
    config,
    matrix_message,
    matrix_room,
    matrix_user_id,
    event_type,
    txnId,
    ts=0,
):

    if ts:
        url = "%s/_matrix/client/r0/rooms/%s/send/%s/%s?user_id=%s&ts=%s" % (config["homeserver"],matrix_room,event_type,txnId,matrix_user_id,ts,)
    else:
        url = "%s/_matrix/client/r0/rooms/%s/send/%s/%s?user_id=%s" % (config["homeserver"],matrix_room,event_type,txnId,matrix_user_id,)

    #_log.info("Sending registration request...")
    
    try:
        r = requests.put(url, headers={'Authorization': 'Bearer ' + config["as_token"]}, json=matrix_message, verify=config["verify-ssl"])
    except requests.exceptions.RequestException as e:
        # catastrophic error. bail.
        log.error(
            "Logging an uncaught exception {}".format(e),
            exc_info=(traceback)
        )
        log.debug("error creating room {}".format(r))
        return False
    else:
        if r.status_code != 200:
            log.error("ERROR! Received %d %s" % (r.status_code, r.reason))
            if r.status_code == 403:
                invite_user(
                    matrix_room,
                    matrix_user_id,
                    config
                )
                try:
                    r = requests.put(url, headers={'Authorization': 'Bearer ' + config["as_token"]}, json=matrix_message, verify=config["verify-ssl"])
                except requests.exceptions.RequestException as e:
                    # catastrophic error. bail.
                    log.error(
                        "Logging an uncaught exception {}".format(e),
                        exc_info=(traceback)
                    )
                    log.debug("error creating room {}".format(r))
                    return False
                else:
                    if r.status_code == 200:
                        return r
                    else:
                        return False
        if 400 <= r.status_code < 500:
            try:
                log.error(' '.join([r.status_code, r.json()["error"]]))
                log.debug(matrix_message)
            except Exception:
                pass
            return False
        return r

def invite_user(
    roomId,
    matrix_user_id,
    config,
):
    if config["create-as-admin"]:
        log.info("Invite {} to {}".format(matrix_user_id,roomId))
        _mxCreator = "".join(["@", config['admin_user'], ":", config["domain"]])

        url = "%s/_matrix/client/r0/rooms/%s/invite?user_id=%s" % (config["homeserver"],roomId,_mxCreator,)
        body = {
            "user_id": matrix_user_id,
        }

        #_log.info("Sending registration request...")
        try:
            r = requests.post(url, headers={'Authorization': 'Bearer ' + config["as_token"]}, json=body, verify=config["verify-ssl"])
        except requests.exceptions.RequestException as e:
            # catastrophic error. bail.
            log.error(
                "Logging an uncaught exception {}".format(e),
                exc_info=(traceback)
            )
            log.debug("error creating room {}".format(body))
            return False
        else:
            if r.status_code != 200:
                log.info("ERROR! Received %d %s" % (r.status_code, r.reason))
                if 400 <= r.status_code < 500:
                    try:
                        log.info(r.json()["error"])
                    except Exception:
                        pass


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def fillTable(cur: sqlite3.dbapi2.Connection):

    # rooms = {}
    # for room in roomLUT.keys():
    #     rooms[room] = []
    if "rocketchat_message.json" not in os.listdir('data/'):
        log.error("rocketchat_message.json not in data/. Refer to README")
        sys.exit(1)

    log.info("Reading message data")
    index = 0
    with alive_bar(None, force_tty=True) as bar:
        with open('data/rocketchat_message.json', 'r', encoding="utf8") as f:
            for line in f:
                message = json.loads(line, )
                # rooms[message["rid"]].append(message)
                try:
                    if "msg" in message:
                        cur.execute("INSERT INTO messages (_id, rid, msg, ts, u) VALUES (?, ?, ?, ?, ?)",
                                    (message['_id'],
                                     message['rid'],
                                     message['msg'],
                                     message['ts']['$date']['$numberLong'],
                                     message['u']['_id']
                                     ))
                except Exception as e:
                    pass
                index += 1
                if index >= 1e5:
                    cur.commit()
                    index = 0
                bar()
            cur.execute("CREATE INDEX IF NOT EXISTS index_rid ON messages (rid)")
            cur.commit()
