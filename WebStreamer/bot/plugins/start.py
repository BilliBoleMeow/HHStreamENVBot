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
        f'Hello {m.from_user.mention(style="md")},\n\nYou are in the wrong place. Go to @LiquidXProjects or @HashHackers'
    )
