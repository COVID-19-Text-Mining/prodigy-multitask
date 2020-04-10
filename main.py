import os
import sys

sys.path.append(os.path.realpath(os.path.dirname(__file__)))

from app import app as application

__all__ = ['application']
