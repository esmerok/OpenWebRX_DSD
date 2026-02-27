from csdr.chain.demodulator import BaseDemodulatorChain, FixedIfSampleRateChain, FixedAudioRateChain, MetaProvider
from csdr.module.dsdfme import DsdFmeModule
from owrx.meta import MetaParser
from pycsdr.modules import FmDemod, DcBlock, Limit, Convert, Writer, Buffer
from pycsdr.types import Format


class DsdFmeAuto(BaseDemodulatorChain, FixedIfSampleRateChain, FixedAudioRateChain, MetaProvider):
    def __init__(self, profile_key: str = "dsdfme"):
        self.module = DsdFmeModule(profile_key=profile_key)
        self.metaParser = None
        workers = [
            FmDemod(),
            DcBlock(),
            Limit(),
            Convert(Format.FLOAT, Format.SHORT),
            self.module,
        ]
        super().__init__(workers)

    def getFixedIfSampleRate(self) -> int:
        return 48000

    def getFixedAudioRate(self) -> int:
        return 8000

    def supportsSquelch(self) -> bool:
        return False

    def setMetaWriter(self, writer: Writer) -> None:
        if self.metaParser is None:
            self.metaParser = MetaParser()
            metaBuffer = Buffer(Format.CHAR)
            self.module.setMetaWriter(metaBuffer)
            self.metaParser.setReader(metaBuffer.getReader())
        self.metaParser.setWriter(writer)

    def stop(self):
        if self.metaParser is not None:
            self.metaParser.stop()
            self.metaParser = None
        super().stop()
