from owrx.controllers.admin import AuthorizationMixin
from owrx.controllers.template import WebpageController
from owrx.breadcrumb import Breadcrumb, BreadcrumbItem, BreadcrumbMixin
from owrx.service import Services
from owrx.web.receivers import Receivers
from owrx.web.repeaters import Repeaters
from owrx.web.eibi import EIBI
from datetime import datetime

import json
import time
import os
import re

import logging

logger = logging.getLogger(__name__)


class ServiceController(AuthorizationMixin, WebpageController):
    timeStarted = time.time()

    def indexAction(self):
        self.serve_template("services.html", **self.template_variables())

    def template_variables(self):
        variables = super().template_variables()
        variables["services"] = self.renderServices()
        return variables

    @staticmethod
    def renderServices():
        return """
                <table class='table'>
                    <tr>
                        <th>Service</th>
                        <th>SDR Profile</th>
                        <th>Frequency</th>
                    </tr>
                    {services}
                    <tr>
                        <td colspan=3>{status}</td>
                    </tr>
                </table>
        """.format(
            services="".join(ServiceController.renderService(c) for c in Services.listAll()),
            status=ServiceController.renderStatus()
        )

    # Get last started timestamp
    @staticmethod
    def lastStarted():
        return ServiceController.timeStarted

    @staticmethod
    def lastBooted():
        try:
            with open('/proc/uptime', 'r') as f:
                return time.time() - float(f.readline().split()[0])
        except:
            return 0

    @staticmethod
    def renderTime(ts):
        ts = datetime.fromtimestamp(ts)
        td = str(datetime.now() - ts).split(".", 1)[0]
        ts = ts.astimezone().strftime("%H:%M:%S %Z, %d %b %Y")
        return ts + ", " + td + " ago"

    @staticmethod
    def renderStatus():
        result = ""
        ts = ServiceController.lastBooted()
        if ts > 0:
            ts = ServiceController.renderTime(ts)
            result += "<div style='color:#00FF00;text-align:center;'>System booted at {0}.</div>\n".format(ts)
        ts = ServiceController.lastStarted()
        if ts > 0:
            ts = ServiceController.renderTime(ts)
            result += "<div style='color:#00FF00;text-align:center;'>Server started at {0}.</div>\n".format(ts)
        ts = EIBI.getSharedInstance().lastDownloaded()
        if ts > 0:
            ts = ServiceController.renderTime(ts)
            result += "<div style='color:#00FF00;text-align:center;'>Shortwave schedule downloaded at {0}.</div>\n".format(ts)
        else:
            result += "<div style='color:#FF0000;text-align:center;'>Shortwave schedule not downloaded.</div>\n"
        ts = Repeaters.getSharedInstance().lastDownloaded()
        if ts > 0:
            ts = ServiceController.renderTime(ts)
            result += "<div style='color:#00FF00;text-align:center;'>Repeaters database downloaded at {0}.</div>\n".format(ts)
        else:
            result += "<div style='color:#FF0000;text-align:center;'>Repeaters database not downloaded.</div>\n"
        ts = Receivers.getSharedInstance().lastDownloaded()
        if ts > 0:
            ts = ServiceController.renderTime(ts)
            result += "<div style='color:#00FF00;text-align:center;'>Receivers database downloaded at {0}.</div>\n".format(ts)
        else:
            result += "<div style='color:#FF0000;text-align:center;'>Receivers database not downloaded.</div>\n"
        return result

    @staticmethod
    def renderService(c):
        # Choose units based on frequency
        freq = c["freq"]
        if freq >= 1000000000:
            freq = freq / 1000000000
            unit = "GHz"
        elif freq >= 30000000:
            freq = freq / 1000000
            unit = "MHz"
        elif freq >= 1000:
            freq = freq / 1000
            unit = "kHz"
        else:
            unit = "Hz"
        # Removing trailing zeros, converting mode to upper case
        freq = re.sub(r"\.?0+$", "", "{0}".format(freq))
        # Format row
        return "<tr><td>{0}</td><td>{1} {2}</td><td>{3}{4}</td></tr>".format(
            c["mode"].upper(), c["sdr"], c["band"], freq, unit
        )
