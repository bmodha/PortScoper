#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, DefaultDict
from dataclasses import dataclass
from pathlib import Path
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from collections import defaultdict
import argparse
import sys
import json
from rich.console import Console
from rich.table import Table
from datetime import datetime

[... rest of the file content ...]