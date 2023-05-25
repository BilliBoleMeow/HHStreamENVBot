# This file is a part of TG-
# Coding : Jyothis Jayanth [@EverythingSuckz]

import logging
from pyrogram import filters
from WebStreamer.vars import Var
from urllib.parse import quote_plus
from WebStreamer.bot import StreamBot
from WebStreamer.utils import get_hash, get_name
from pyrogram.enums.parse_mode import ParseMode
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton

@StreamBot.on_message(filters.command(["start"]))
async def start(_, m: Message):
    await m.reply(
        f'Hello {m.from_user.mention(style="md")},\n\nSend me a file or You can just add me to any Telegram Channel and Use, to know more do /help.\n\nFollow @HashHackers for Support.'
    )

@StreamBot.on_message(filters.command(["help"]))
async def start(_, m: Message):
    await m.reply(
        f'Hello {m.from_user.mention(style="md")},\n\nAdd me a file to get the domain link, replace your channel id with my own and message id of what you wanna download from your channel, but first add me to your channel with Admin Permissions.\n\nFollow @HashHackers for Support.'
    )