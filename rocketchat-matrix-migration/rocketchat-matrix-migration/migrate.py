#!/bin/python3

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

import getpass
import json
import logging
import os
import re
import sys
import traceback
import zipfile
import gzip
import bson

import requests
import yaml
from emoji import emojize

from files import process_attachments, process_files
from alive_progress import alive_bar
from utils import send_event, invite_user

LOG_LEVEL = os.environ.get('LOG_LEVEL', "INFO").upper()
ADMIN_USER_MATRIX = os.environ.get('ADMIN_USER_MATRIX')
ADMIN_PASS_MATRIX = os.environ.get('ADMIN_PASS_MATRIX')

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


channelTypes = ["users.bson.gz", "rocketchat_message.bson.gz", "rocketchat_room.bson.gz", "rocketchat_subscription.bson.gz"]
userLUT = {}
nameLUT = {}
roomLUT = {}
roomLUT2 = {}
eventLUT = {}
threadLUT = {}
replyLUT = {}
later = []
read_luts = False

if not os.path.isfile("conf/config.yaml"):
    log.info("Config file does not exist.")
    sys.exit(1)

f = open("conf/config.yaml", "r")
config_yaml = yaml.load(f.read(), Loader=yaml.FullLoader)

# load luts from previous run
if os.path.isfile("run/luts.yaml"):
    f = open("run/luts.yaml", "r")
    luts = yaml.load(f.read(), Loader=yaml.FullLoader)
    userLUT = luts["userLUT"]
    nameLUT = luts["nameLUT"]
    roomLUT = luts["roomLUT"]
    roomLUT2 = luts["roomLUT2"]
    read_luts = True
    log.info("Read LUTs. Skipping migration of users and rooms. Delete /run/luts.yaml to re-migrate them.")

def test_config(yaml):
    if not config_yaml["zipfile"]:
        log.info("No zipfile defined in config")
        sys.exit(1)

    if not config_yaml["homeserver"]:
        log.info("No homeserver defined in config")
        sys.exit(1)

    if not config_yaml["as_token"]:
        log.info("No Application Service token defined in config")
        sys.exit(1)

    dry_run = config_yaml["dry-run"]
    skip_archived = config_yaml["skip-archived"]

    config = config_yaml

    return config

def loadZip(config):
    zipName = config["zipfile"]
    log.info("Opening zipfile: " + zipName)
    archive = zipfile.ZipFile(zipName, 'r')
    jsonFiles = {}
    for channelType in channelTypes:
        try:
            jsonFiles[channelType.split(".")[0]] = gzip.decompress(archive.open(channelType).read())
            log.info("Found " + channelType.split(".")[0] + " in archive. Adding.")
        except:
            log.info("Warning: Couldn't find " + channelType.split(".")[0] + " in archive. Skipping.")
    return jsonFiles

def loadZipFolder(config, folder):
    with zipfile.ZipFile(config["zipfile"], 'r') as file:
        archive = file.infolist()

        fileList = []
        for entry in archive:
            file_basename = entry.filename.split("/", maxsplit=1)[0]
            if entry.is_dir() == False and folder == file_basename:
                fileList.append(entry.filename)

        return fileList

def decodeBson(file):
    data = []

    base = 0
    while base < len(file):
        base, d = bson.decode_document(file, base)
        data.append(d)

    return data

# TODO: user alive-progress
# using bubble bar and notes spinner
# with alive_bar(200, bar = 'bubbles', spinner = 'pointer') as bar:
#     for i in range(200):
#         sleep(0.03)
#         bar()                        # call after consuming one ite
# update_progress() : Displays or updates a console progress bar
## Accepts a float between 0 and 1. Any int will be converted to a float.
## A value under 0 represents a 'halt'.
## A value at 1 or bigger represents 100%
def update_progress(progress):
    barLength = 40 # Modify this to change the length of the progress bar
    status = ""
    if isinstance(progress, int):
        progress = float(progress)
    if not isinstance(progress, float):
        progress = 0
        status = "error: progress var must be float\r\n"
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress >= 1:
        progress = 1
        status = "Done...\r\n"
    block = int(round(barLength*progress))
    text = "\rPercent: [{0}] {1:3.2f}% {2}".format( "#"*block + "-"*(barLength-block), progress*100, status)
    sys.stdout.write(text)
    sys.stdout.flush()

def login(server_location):
    try:
        default_user = getpass.getuser()
    except Exception:
        default_user = None

    if not ADMIN_USER_MATRIX:
        if default_user:
            admin_user = input("Admin user localpart [%s]: " % (default_user,))
            if not admin_user:
                admin_user = default_user
        else:
            admin_user = input("Admin user localpart: ")
    else:
        admin_user = ADMIN_USER_MATRIX

    if not admin_user:
        log.info("Invalid user name")
        sys.exit(1)

    if not ADMIN_PASS_MATRIX:
        admin_password = getpass.getpass("Password: ")
    else:
        admin_password = ADMIN_PASS_MATRIX

    if not admin_password:
        log.info("Password cannot be blank.")
        sys.exit(1)

    url = "%s/_matrix/client/r0/login" % (server_location,)
    data = {
        "type": "m.login.password",
        "user": admin_user,
        "password": admin_password,
    }

    # Get the access token
    r = requests.post(url, json=data, verify=config_yaml["verify-ssl"])

    if r.status_code != 200:
        log.info("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                log.info(r.json()["error"])
            except Exception:
                pass
        return False

    access_token = r.json()["access_token"]

    return admin_user, access_token

def getMaxUploadSize(config, access_token):
    # get maxUploadSize from Homeserver
    url = "%s/_matrix/media/r0/config?access_token=%s" % (config_yaml["homeserver"],access_token,)
    r = requests.get(url, verify=config["verify-ssl"])

    if r.status_code != 200:
        log.info("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                log.info(r.json()["error"])
            except Exception:
                pass

    maxUploadSize = r.json()["m.upload.size"]
    return maxUploadSize

def register_user(
    user,
    password,
    displayname,
    server_location,
    access_token,
    admin=False,
    user_type=None,
):

    url = "%s/_synapse/admin/v2/users/@%s:%s" % (server_location, user, config_yaml['domain'])

    headers = {'Authorization': ' '.join(['Bearer', access_token])}

    data = {
        "password": password,
        "displayname": "".join([displayname, config_yaml["name-suffix"]]),
        "admin": admin,
    }
    try:
        r = requests.put(url, json=data, headers=headers, verify=config_yaml["verify-ssl"])
    except requests.exceptions.RequestException as e:
        # catastrophic error. bail.
        log.error(
            "Logging an uncaught exception {}".format(e),
            exc_info=(traceback)
        )
        # log.debug("error creating room {}".format(body))
        return False
    else:
        if r.status_code != 200 and r.status_code != 201:
            log.info("ERROR! Received %d %s" % (r.status_code, r.reason))
            if 400 <= r.status_code < 500:
                try:
                    log.info(r.json()["error"])
                except Exception:
                    pass
            return False
        else:
            return r

def register_room(
    name,
    creator,
    topic,
    invitees,
    preset,
    server_location,
    as_token,
):
    # register room
    log.debug("register room {}".format(
            (
                name,
                creator,
                topic,
                invitees,
                preset,
            )
        )
    )
    url = "%s/_matrix/client/r0/createRoom?user_id=%s" % (server_location,creator,)

    body = {
        "preset": preset,
        "name": "".join([name, config_yaml["room-suffix"]]),
        "topic": topic,
        "creation_content": {
            "m.federate": config_yaml["federate-rooms"]
        },
        "invite": invitees,
        "is_direct": True if preset == "trusted_private_chat" else False,
    }

    #_log.info("Sending registration request...")
    try:
        r = requests.post(url, headers={'Authorization': 'Bearer ' + as_token}, json=body, verify=config_yaml["verify-ssl"], timeout=300 )
    # except requests.exceptions.Timeout:
    #     # Maybe set up for a retry, or continue in a retry loop
    # except requests.exceptions.TooManyRedirects:
    #     # Tell the user their URL was bad and try a different one
    except requests.exceptions.RequestException as e:
        # catastrophic error. bail.
        log.error(
            "Logging an uncaught exception {}".format(e),
            exc_info=(traceback)
        )
        # log.debug("error creating room {}".format(body))
        return False

    if r.status_code != 200:
        log.error("ERROR! Received %d %s" % (r.status_code, r.reason))
        if 400 <= r.status_code < 500:
            try:
                log.error(r.json()["error"])
            except Exception:
                pass
        return False

    return r

def invite_users(
    invitees,
    creator,
    roomId,
    config,
):
    for user in invitees:
        invite_user(roomId, user, config)

def autojoin_users(
    invitees,
    roomId,
    config,
):
    for user in invitees:
        #POST /_matrix/client/r0/rooms/{roomId}/join
        url = "%s/_matrix/client/r0/rooms/%s/join?user_id=%s" % (config["homeserver"],roomId,user,)

        #_log.info("Sending registration request...")
        try:
            r = requests.post(url, headers={'Authorization': 'Bearer ' + config["as_token"]}, verify=config["verify-ssl"])
        except requests.exceptions.RequestException as e:
            log.error("Logging an uncaught exception {}".format(e), exc_info=(traceback))
            # log.debug("error creating room {}".format(body))
            return False
        else:
            if r.status_code != 200:
                log.error("ERROR! Received %d %s" % (r.status_code, r.reason))
                if 400 <= r.status_code < 500:
                    try:
                        log.info(r.json()["error"])
                    except Exception:
                        pass

def migrate_users(userFile, config, access_token):
    log = logging.getLogger('ROCKETCHAT.MIGRATE.USER')
    userlist = []
    userData = decodeBson(userFile)

    with alive_bar(len(userData), bar='bubbles', spinner='waves2', force_tty=True) as bar:
        for user in userData:
            if user["type"] != 'user':
                bar()
                continue

            _servername = config["homeserver"].split('/')[2]
            _matrix_user = user["username"]
            _matrix_id = '@' + user["username"] + ':' + _servername

            # check if display name is set
            if "name" in user:
                _real_name = user["name"]
            else:
                _real_name = ""

            # check if email is set
            if "emails" in user and len(user["emails"]) > 0:
                _email = user["emails"][0]["address"]
            else:
                _email = ""

            # Use password from RocketChat if not an ldap user. If ldap is true, we're going to leave the password blank.
            if "ldap" in user and user["ldap"] == True:
                _password = ""
            elif "services" in user and "password" in user["services"]:
                _password = user["services"]["password"]["bcrypt"]

            userDetails = {
                "rocketchat_id": user["_id"],
                "rocketchat_name": user["username"],
                "rocketchat_real_name": _real_name,
                "rocketchat_email": _email,
                "matrix_id": _matrix_id,
                "matrix_user": _matrix_user,
                "matrix_password": _password,
            }

            log.info("Registering RocketChat user " + userDetails["rocketchat_id"] + " -> " + userDetails["matrix_id"])
            if not config["dry-run"]:
                res = register_user(userDetails["matrix_user"], userDetails["matrix_password"], userDetails["rocketchat_real_name"], config["homeserver"], access_token)
                if res == False:
                    log.error("ERROR while registering user '" + userDetails["matrix_id"] + "'")
                    continue

            userLUT[userDetails["rocketchat_id"]] = userDetails["matrix_id"]
            nameLUT[userDetails["matrix_id"]] = userDetails["rocketchat_real_name"]
            userlist.append(userDetails)
            # time.sleep(1)
            bar()
    return userlist


def migrate_rooms(roomFile, subscriptionFile, config, admin_user):
    log = logging.getLogger('ROCKETCHAT.MIGRATE.ROOMS')
    roomlist = []
    channelData = decodeBson(roomFile)
    subscriptionData = decodeBson(subscriptionFile)

    # channels
    with alive_bar(len(channelData), bar='classic', spinner='waves2', force_tty=True) as bar:
        for channel in channelData:
            # Skip readonly channels?
            if config["skip-archived"]:
                if channel["ro"] == True:
                    bar()
                    continue

            if channel["t"] == "c" or channel["t"] == "p":  # Channels and teams (this are almost identical)
                room_preset = "public_chat" if channel["t"] == "c" else "private_chat"
                _invitees = []
                if channel["t"] == "c":
                    for subscription in [sub for sub in subscriptionData if sub["t"] == "c" and sub["rid"] == channel["_id"]]:
                        _invitees.append(subscription["u"]["_id"])
                else:
                    for subscription in [sub for sub in subscriptionData if sub["t"] == "p" and sub["rid"] == channel["_id"]]:
                        _invitees.append(subscription["u"]["_id"])

                if config_yaml["create-as-admin"]:
                    _mxCreator = "".join(["@", admin_user, ":", config_yaml["domain"]])
                else:
                    # if user is not in LUT (maybe its a shared channel), default to admin_user
                    if "u" in channel and channel["u"]["_id"] in userLUT:
                        _mxCreator = userLUT[channel["u"]["_id"]]
                    else:
                        _mxCreator = "".join(["@", admin_user, ":", config_yaml["domain"]])

                roomDetails = {
                    "rocketchat_id": channel["_id"],
                    "rocketchat_name": channel["name"],
                    "rocketchat_members": _invitees,
                    "rocketchat_created": channel["ts"],
                    "rocketchat_creator": channel["u"]["_id"] if "u" in channel else "",
                    "matrix_id": '',
                    "matrix_creator": _mxCreator,
                    "matrix_topic": '',
                }
            elif channel["t"] == "d":  # Direct messages
                room_preset = "private_chat"
                _invitees = []
                for subscription in [sub for sub in subscriptionData if sub["t"] == "d" and sub["rid"] == channel["_id"]]:
                    _invitees.append(subscription["u"]["_id"])

                if config_yaml["create-as-admin"]:
                    _mxCreator = "".join(["@", admin_user, ":", config_yaml["domain"]])
                else:
                    # if user is not in LUT (maybe its a shared channel), default to admin_user
                    if channel["uids"][0] in userLUT:
                        _mxCreator = userLUT[channel["uids"][0]]
                    else:
                        _mxCreator = "".join(["@", admin_user, ":", config_yaml["domain"]])

                roomDetails = {
                    "rocketchat_id": channel["_id"],
                    "rocketchat_name": '',
                    "rocketchat_members": channel["uids"],
                    "rocketchat_created": channel["ts"],
                    "rocketchat_creator": channel["uids"][0],
                    "matrix_id": '',
                    "matrix_creator": _mxCreator,
                    "matrix_topic": '',
                }
            else:  # Anything else, we just skip
                bar()
                continue

            if not config["dry-run"]:
                res = register_room(roomDetails["rocketchat_name"], roomDetails["matrix_creator"], roomDetails["matrix_topic"], _invitees, room_preset, config["homeserver"], config["as_token"])

                if res == False:
                    log.info("ERROR while registering room '" + roomDetails["rocketchat_name"] + "'")
                    continue
                else:
                    _content = json.loads(res.content)
                    roomDetails["matrix_id"] = _content["room_id"]
                log.info("Registered RocketChat channel " + roomDetails["rocketchat_name"] + " -> " + roomDetails["matrix_id"])

                #invite all members
                if config_yaml["invite-all"]:
                    invite_users(_invitees, roomDetails["matrix_creator"], roomDetails["matrix_id"], config)
                #autojoin all members
                autojoin_users(_invitees, roomDetails["matrix_id"], config)

            roomLUT[roomDetails["rocketchat_id"]] = roomDetails["matrix_id"]
            roomLUT2[roomDetails["rocketchat_id"]] = roomDetails["rocketchat_name"]
            roomlist.append(roomDetails)
            #time.sleep(1)
            bar()
    return roomlist

def send_reaction(config, roomId, eventId, reactionKey, userId, txnId):

    content = {
        "m.relates_to": {
            "event_id": eventId,
            "key": reactionKey,
            "rel_type": "m.annotation",
        },
    }

    res = send_event(config, content, roomId, userId, "m.reaction", txnId)

    return res

def replace_mention(matchobj):
    _slack_id = matchobj.group(0)[2:-1]

    if not _slack_id in userLUT:
        return ''
    user_id = userLUT[_slack_id]
    displayname = nameLUT[user_id]

    return "<a href='https://matrix.to/#/" + user_id + "'>" + displayname + "</a>"

def getFallbackHtml(roomId, replyEvent):
    originalBody = replyEvent["body"]
    originalHtml = replyEvent["formatted_body"]
    if not replyEvent["body"]:
        originalHtml = originalBody

    return '<mx-reply><blockquote><a href="https://matrix.to/#/' + roomId + '/' + replyEvent["event_id"] + '">In reply to</a><a href="https://matrix.to/#/' + replyEvent["sender"] + '">' + replyEvent["sender"] + '</a><br />' + originalHtml + '</blockquote></mx-reply>'

def getFallbackText(replyEvent):
    originalBody = replyEvent["body"]
    originalBody = originalBody.split("\n")
    originalBody = "\n> ".join(originalBody)
    return '> <' + replyEvent["sender"] + '> ' + originalBody

def parse_rocketchat_markdown(md):
    output = ""
    newLine = '\n'
    for entry in md:
        if entry['type'] == 'PARAGRAPH':
            for value in entry['value']:
                if value['type'] == 'PLAIN_TEXT':
                    output += value['value']
                elif value['type'] == 'MENTION_USER':
                    output += f"@{value['value']['value']}:{config_yaml['domain']}"
                elif value['type'] == 'LINK':
                    if value['value']['label']['value'] == ' ':  # This is a reply.
                        # TODO: Figure out how to work with reply links
                        continue
                    output += f"[{value['value']['label']['value'] if value['value']['label']['value'] != '' else value['value']['src']['value']}]({value['value']['src']['value']})"  # Format links in [<LABEL>](<URL>) format. Replace the label with the URL if no label is given
                elif value['type'] == 'EMOJI':
                    output += f":{value['shortCode']}:"
                elif value['type'] == 'INLINE_CODE':
                    output += f"`{value['value']['value']}`"
                elif value['type'] == 'BOLD':
                    for string in entry['value']:
                        output += f"{string['value']}"
                else:
                    log.info(f"Unsupported markdown-value type: {value['type']}")
                    continue
        elif entry['type'] == 'CODE':
            output += f"\n```{entry['language']}\n{(line['value']['value'] + newLine for line in entry['value'])}```\n"
        elif entry['type'] == 'LINE_BREAK':
            output += '\n'
        elif entry['type'] == 'BIG_EMOJI':
            for emoji in entry['value']:
                output += f":{emoji['value']['value']}: "
        else:
            log.info(f"Unsupported markdown type: {entry['type']}")
            continue

    return output

def parse_and_send_message(config, message, matrix_room, txnId, is_later, log):
    content = {}
    is_thread = False
    is_reply = False

    # ignore hidden messages
    # todo: find out if rocketchat does something like this
    if "hidden" in message:
        if message["hidden"] == True:
            return txnId

    if "u" in message: #TODO what messages have no user?
        if not message["u"]["_id"] in userLUT:
            # ignore messages from bots or not already added users
            return txnId
    else:
        log.info("Message without user, thanks rocketchat")
        log.info(message)

    body = parse_rocketchat_markdown(message['md'])

    # TODO do not migrate empty messages?
    #if body == "":
    #
    #    return txnId

    # replace mentions
    body = body.replace("<!channel>", "@room")
    body = body.replace("<!here>", "@room")
    body = body.replace("<!everyone>", "@room")
    body = re.sub('<@[A-Z0-9]+>', replace_mention, body)

    # if "files" in message:
    #     if "subtype" in message:
    #         log.info(message["subtype"])
    #         if message["subtype"] == "file_comment" or message["subtype"] == "thread_broadcast":
    #             #TODO treat as reply
    #             log.info("")
    #         else:
    #             txnId = process_files(message["files"], matrix_room, userLUT[message["user"]], body, txnId, config)
    #     else:
    #         txnId = process_files(message["files"], matrix_room, userLUT[message["user"]], body, txnId, config)

    # if "attachments" in message:
    #     if message["user"] in userLUT: # ignore attachments from bots
    #         txnId = process_attachments(message["attachments"], matrix_room, userLUT[message["user"]], body, txnId, config)
    #         for attachment in message["attachments"]:
    #             if "is_share" in attachment and attachment["is_share"]:
    #                 if body:
    #                     body += "\n"
    #                 attachment_footer = "no footer"
    #                 if "footer" in attachment:
    #                     attachment_footer = attachment["footer"]
    #                 attachment_text = "no text"
    #                 if "text" in attachment:
    #                     attachment_text = attachment["text"]
    #                 body += "".join(["&gt; _Shared (", attachment_footer, "):_ ", attachment_text, "\n"])

    # if "replies" in message: # this is the parent of a thread
    #     is_thread = True
    #     previous_message = None
    #     for reply in message["replies"]:
    #         if "user" in message and "ts" in message:
    #             first_message = message["user"]+message["ts"]
    #             current_message = reply["user"]+reply["ts"]
    #             if not previous_message:
    #                 previous_message = first_message
    #             replyLUT[current_message] = previous_message
    #             if config_yaml["threads-reply-to-previous"]:
    #                 previous_message = current_message

    # replys / threading
    # if "thread_ts" in message and "parent_user_id" in message and not "replies" in message: # this message is a reply to another message
    #     is_reply = True
    #     if not message["user"]+message["ts"] in replyLUT:
    #         # seems like we don't know the thread yet, save event for later
    #         if not is_later:
    #             later.append(message)
    #         return txnId
    #     slack_event_id = replyLUT[message["user"]+message["ts"]]
    #     matrix_event_id = eventLUT[slack_event_id]

    # TODO pinned / stared items?

    # replace emojis
    body = emojize(body, language='alias')

    # TODO some URLs with special characters (e.g. _ ) are parsed wrong
    # formatted_body = slackdown.render(body)
    formatted_body = body

    if not is_reply:
        content = {
                "body": body,
                "msgtype": "m.text",
                "format": "org.matrix.custom.html",
                "formatted_body": formatted_body,
        }
    else:
        replyEvent = threadLUT[message["parent_user_id"]+message["thread_ts"]]
        fallbackHtml = getFallbackHtml(matrix_room, replyEvent);
        fallbackText = getFallbackText(replyEvent);
        body = fallbackText + "\n\n" + body
        formatted_body = fallbackHtml + formatted_body
        content = {
            "m.relates_to": {
                "m.in_reply_to": {
                    "event_id": matrix_event_id,
                },
            },
            "msgtype": "m.text",
            "body": body,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted_body,
        }

    if not config["dry-run"]:
        # send message
        ts = message["ts"].replace(".", "")[:-3]
        res = send_event(config, content, matrix_room, userLUT[message["user"]], "m.room.message", txnId, ts)
        # save event id
        if res == False:
            log.info("ERROR while sending event '" + message["user"] + " " + message["ts"] + "'")
            log.error("ERROR body {}".format(body))
            log.error("ERROR formatted_body {}".format(formatted_body))
        else:
            _content = json.loads(res.content)
            # use "user" combined with "ts" as id like Slack does as "client_msg_id" is not always set
            if "user" in message and "ts" in message:
                eventLUT[message["user"]+message["ts"]] = _content["event_id"]
            txnId = txnId + 1
            if is_thread:
                threadLUT[message["user"]+message["ts"]] = {"body": body, "formatted_body": formatted_body, "sender": userLUT[message["user"]], "event_id": _content["event_id"]}

            # handle reactions
            if "reactions" in message:
                roomId = matrix_room
                eventId = eventLUT[message["user"]+message["ts"]]
                for reaction in message["reactions"]:
                    for user in reaction["users"]:
                        #log.info("Send reaction in room " + roomId)
                        send_reaction(config, roomId, eventId, emojize(reaction["name"], language='alias'), userLUT[user], txnId)
                        txnId = txnId + 1

    return txnId


def migrate_messages(messageList, matrix_room, config, log):
    log.debug('start migration of messages for matrix room: {}'.format(matrix_room))
    global later
    txnId = 1

    with alive_bar(len(messageList), bar='checks', spinner='waves2', force_tty=True) as bar:
        for message in messageList:
            try:
                txnId = parse_and_send_message(config, message, matrix_room, txnId, False, log)
            except:
                log.error(
                    "Warning: Couldn't send  message: {} to matrix_room {} id:{}".format(message, matrix_room, txnId)
                )
            # update_progress(progress)
            bar()

    # process postponed messages
    for message in later:
        txnId = parse_and_send_message(config, message, matrix_room, txnId, True, log)

    # clean up postponed messages
    later = []


def kick_imported_users(server_location, admin_user, access_token, tick):
    headers = {'Authorization': ' '.join(['Bearer', access_token])}
    progress = 0

    with alive_bar(spinner = 'triangles', manual=True) as bar:
        for room in roomLUT.values():
            url = "%s/_matrix/client/r0/rooms/%s/kick" % (server_location, room)

            for name in nameLUT.keys():
                data = {"user_id": name}

                try:
                    r = requests.post(url, json=data, headers=headers, verify=config["verify-ssl"])
                except requests.exceptions.RequestException as e:
                    # catastrophic error. bail.
                    log.error(
                        "Logging an uncaught exception {}".format(e),
                        exc_info=(traceback)
                    )
                    # log.debug("error creating room {}".format(body))
                    return False
                else:
                    if r.status_code != 200 and r.status_code != 201:
                        log.info("ERROR! Received %d %s" % (r.status_code, r.reason))
                        if 400 <= r.status_code < 500:
                            try:
                                log.info(r.json()["error"])
                            except Exception:
                                pass

            progress = progress + tick
            #update_progress(progress)
            bar(progress)

def main():
    logging.captureWarnings(True)
    log = logging.getLogger('ROCKETCHAT.MIGRATE.MAIN')

    config = test_config(yaml)

    jsonFiles = loadZip(config)

    # login with admin user to gain access token
    if not config["dry-run"]:
        admin_user, access_token = login(config["homeserver"])
        maxUploadSize = getMaxUploadSize(config, access_token)
    else:
        admin_user = "DRYRUNADMIN"
        access_token = "DRYRUNTOKEN"
        maxUploadSize = 99999999
    config["maxUploadSize"] = maxUploadSize
    config["admin_user"] = admin_user
    log.info("maxUploadSize {}".format(maxUploadSize))

    if access_token == False:
        log.info("ERROR! Admin user could not be logged in.")
        exit(1)

    # create users in matrix and match them to RocketChat users
    if "users" in jsonFiles and not userLUT:
        if not config["run-unattended"]:
            input('Creating users. Press enter to proceed\n')
        else:
            log.info("Creating Users")
        userlist = migrate_users(jsonFiles["users"], config, access_token)

    # create matrix rooms and match to RocketChat rooms
    # RocketChat rooms
    if "rocketchat_room" in jsonFiles and not roomLUT:
        if not config["run-unattended"]:
            input('Creating channels. Press enter to proceed\n')
        else:
            log.info("Creating channels")
        roomlist_channels = migrate_rooms(jsonFiles["rocketchat_room"], jsonFiles["rocketchat_subscription"], config, admin_user)

    # write LUTs to file to be able to load from later if something goes wrong
    if not read_luts:
        data = dict(
            userLUT = userLUT,
            nameLUT = nameLUT,
            roomLUT = roomLUT,
            roomLUT2 = roomLUT2,
            # users = userlist,
        )
        with open('run/luts.yaml', 'w+') as outfile:
            yaml.dump(data, outfile, default_flow_style=False)

    # send events to rooms
    if not config["run-unattended"]:
        input('Migrating messages to rooms. This may take a while. Press enter to proceed\n')
    else:
        log.info("Migrating messages to rooms. This may take a while...")

    messageData = decodeBson(jsonFiles["rocketchat_message"])

    for rocketchat_room, matrix_room in roomLUT.items():
        log = logging.getLogger('ROCKETCHAT.MIGRATE.MESSAGES.{}'.format(roomLUT2[rocketchat_room]))
        log.info("Migrating messages for room: " + roomLUT2[rocketchat_room])
        messageList = [message for message in messageData if message["rid"] == rocketchat_room]
        if messageList:
            migrate_messages(messageList, matrix_room, config, log)

    # clean up postponed messages
    later = []

    # kick imported users from non-dm rooms
    if config_yaml["kick-imported-users"]:
        log.info("Kicking imported users from rooms. This may take a while...")
        tick = 1/len(roomLUT)
        kick_imported_users(config["homeserver"], admin_user, access_token, tick)


if __name__ == "__main__":
    main()
