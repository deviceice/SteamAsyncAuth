from auth_steam import AuthSteam, SteamUrl
import asyncio
from typing import Union
from decimal import Decimal
import aiofiles
import re
import json
import pickle
from http.cookies import SimpleCookie


async def get_steam_balance(session, convert_to_decimal: bool = True, on_hold: bool = False) -> Union[str, Decimal]:
    response = await session.get(f'{SteamUrl.COMMUNITY_URL}/market')
    text = await response.text()
    wallet_info_match = re.search(r'var g_rgWalletInfo = (.*?);', text)
    if wallet_info_match:
        balance_dict_str = wallet_info_match.group(1)
        balance_dict = json.loads(balance_dict_str)
    else:
        raise Exception('Unable to get wallet balance string match')
    balance_dict_key = 'wallet_delayed_balance' if on_hold else 'wallet_balance'
    if convert_to_decimal:
        return Decimal(balance_dict[balance_dict_key]) / 100
    else:
        return balance_dict[balance_dict_key]


async def main():
    async with AuthSteam() as auth:
        # session = await auth.login()
        session = await auth.load_cookies()
        print('login', session)
        balance = await get_steam_balance(session)
        print(balance)
        # await auth.save_cookies()


asyncio.run(main())
