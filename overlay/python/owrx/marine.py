from owrx.toolbox import TextParser
from owrx.color import ColorCache
from owrx.config import Config
from owrx.reporting import ReportingEngine
import json

import logging

logger = logging.getLogger(__name__)


class NavtexParser(TextParser):
    def __init__(self, service: bool = False):
        # Construct parent object
        super().__init__(filePrefix="NAVTEX", service=service)


class DscParser(TextParser):
    def __init__(self, service: bool = False):
        # Colors will be assigned via this cache
        self.colors = ColorCache()
        # Construct parent object
        super().__init__(filePrefix="DSC", service=service)

    def parse(self, msg: bytes):
        # Expect JSON data in text form
        out = json.loads(msg)
        # Filter out errors
        pm = Config.get()
        if "data" in out and not pm["dsc_show_errors"]:
            return {}
        # Add mode and frequency
        out["mode"] = "DSC"
        if self.frequency != 0:
            out["freq"] = self.frequency
        # Convert timestamp to milliseconds
        if "timestamp" in out:
            out["timestamp"] = out["timestamp"] * 1000
        # Report message
        ReportingEngine.getSharedInstance().spot(out)
        # Log received messages for debugging
        logger.debug("{0}".format(out))
        # When in interactive mode, add color to identify sender
        if not self.service and "src" in out:
            out["color"] = self.colors.getColor(out["src"])
        # Done
        return out
