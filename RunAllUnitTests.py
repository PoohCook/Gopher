#! /usr/bin/env python3

import sys
import unittest
import logging

from modules.cryptographer import PublicCryptographer

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] (%(threadName)-10s) [%(filename)s.%(funcName)s]: %(message)s')

logging.info("================== Begin run of all unit tests =====================")


from test.CryptoTest import *


if __name__ == '__main__':
    unittest.main()
