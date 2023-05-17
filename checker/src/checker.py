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

import dateutil.parser

from httpx import AsyncClient, Response

from hashlib import md5

from logging import LoggerAdapter

from subprocess import Popen, PIPE

import string

from typing import Any, Optional

import random

import os

"""
Checker config
"""

SERVICE_PORT = 9080
checker = Enochecker("oldschool", SERVICE_PORT)
app = lambda: checker.app


"""
Utility functions
"""

# TODO: add utility functions here

"""
CHECKER FUNCTIONS
"""

# TODO: putflag, getflag, putnoise, getnoise, exploit




if __name__ == "__main__":
    checker.run()