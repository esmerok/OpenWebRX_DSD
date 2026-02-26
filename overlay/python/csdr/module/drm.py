from pycsdr.modules import ExecModule
from pycsdr.types import Format
from owrx.feature import FeatureDetector
from owrx.config.core import CoreConfig

import uuid
import os

class DrmModule(ExecModule):
    def __init__(self):
        # Each instance gets its own status socket
        self.socketPath = "{tmp_dir}/dream_status_{uid}.sock".format(
            tmp_dir = CoreConfig().get_temporary_directory(),
            uid = str(uuid.uuid4())[:8]
        )

        # Remove old status socket, if present
        if os.path.exists(self.socketPath):
            try:
                os.unlink(self.socketPath)
            except OSError:
                pass

        # Compose basic command line
        cmd = [
            "dream", "-c", "6", "--sigsrate", "48000",
            "--audsrate", "48000", "-I", "-", "-O", "-",
        ]

        # Only Dream 2.2 has --status-socket option
        self.hasStatusSocket = FeatureDetector().is_available("dream-2-2")
        if self.hasStatusSocket:
            cmd += [ "--status-socket", self.socketPath ]

        super().__init__(Format.COMPLEX_SHORT, Format.SHORT, cmd)

    def getSocketPath(self):
        return self.socketPath if self.hasStatusSocket else None

    def stop(self):
        # Stop execution
        super().stop()
        # Remove status socket
        if os.path.exists(self.socketPath):
            try:
                os.unlink(self.socketPath)
            except OSError:
                pass
