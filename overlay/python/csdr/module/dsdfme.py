from csdr.module import AutoStartModule
from pycsdr.types import Format
from pycsdr.modules import Writer
from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired
from threading import Thread, Lock, Event
import socket
import time
import re
import pickle
import json
import queue
import logging
import os
from collections import deque
from urllib import request
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)


class RadioIdApiResolver:
    API_URL = "https://radioid.net/api/dmr/user/?id={}"
    USER_AGENT = "OpenWebRX-DSDFME/1.0"
    REQUEST_TIMEOUT_SEC = 3.0
    REQUEST_INTERVAL_SEC = 0.5  # 2 requests/sec max
    OK_TTL_SEC = 30 * 24 * 3600
    MISS_TTL_SEC = 24 * 3600

    def __init__(self):
        self.lock = Lock()
        self.cache_ok = {}
        self.cache_miss = {}
        self.pending = set()
        self.last_request_ts = 0.0
        self.stop_event = Event()
        self.lookup_queue = queue.Queue()
        self.worker = Thread(target=self._worker_loop, daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        try:
            self.lookup_queue.put_nowait(None)
        except Exception:
            pass
        if self.worker.is_alive():
            self.worker.join(timeout=1.0)

    def resolve_nonblocking(self, id_int: int):
        now = time.monotonic()
        with self.lock:
            cached = self.cache_ok.get(id_int)
            if cached is not None and now - cached[2] < RadioIdApiResolver.OK_TTL_SEC:
                logger.debug("DSDFME_IDAPI hit id=%s source=ok-cache", id_int)
                return cached[0], cached[1]
            if cached is not None:
                del self.cache_ok[id_int]

            missed = self.cache_miss.get(id_int)
            if missed is not None and now - missed[2] < RadioIdApiResolver.MISS_TTL_SEC:
                logger.debug("DSDFME_IDAPI miss id=%s source=miss-cache", id_int)
                return "", ""
            if missed is not None:
                del self.cache_miss[id_int]

            if id_int in self.pending:
                return "", ""

            self.pending.add(id_int)
            logger.debug("DSDFME_IDAPI enqueue id=%s", id_int)
            try:
                self.lookup_queue.put_nowait(id_int)
            except Exception:
                self.pending.discard(id_int)
                logger.debug("DSDFME_IDAPI error id=%s: unable to enqueue", id_int)
        return "", ""

    def _worker_loop(self):
        while not self.stop_event.is_set():
            try:
                item = self.lookup_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if item is None:
                continue
            id_int = int(item)

            try:
                now = time.monotonic()
                delay = RadioIdApiResolver.REQUEST_INTERVAL_SEC - (now - self.last_request_ts)
                if delay > 0:
                    self.stop_event.wait(delay)
                if self.stop_event.is_set():
                    break

                result = self._fetch_contact(id_int)
                self.last_request_ts = time.monotonic()

                with self.lock:
                    self.pending.discard(id_int)
                    if result is None:
                        self.cache_miss[id_int] = ("", "", time.monotonic())
                        logger.debug("DSDFME_IDAPI miss id=%s source=api", id_int)
                    else:
                        callsign, name = result
                        self.cache_ok[id_int] = (callsign, name, time.monotonic())
                        logger.debug("DSDFME_IDAPI hit id=%s source=api callsign=%s name=%s", id_int, callsign, name)
            except Exception as e:
                with self.lock:
                    self.pending.discard(id_int)
                logger.debug("DSDFME_IDAPI error id=%s: %s", id_int, str(e))

    def _fetch_contact(self, id_int: int):
        url = RadioIdApiResolver.API_URL.format(id_int)
        req = request.Request(
            url,
            headers={
                "User-Agent": RadioIdApiResolver.USER_AGENT,
                "Accept": "application/json",
            },
        )
        try:
            with request.urlopen(req, timeout=RadioIdApiResolver.REQUEST_TIMEOUT_SEC) as res:
                body = res.read()
        except (HTTPError, URLError, TimeoutError) as e:
            logger.debug("DSDFME_IDAPI error id=%s: %s", id_int, str(e))
            return None
        except Exception as e:
            logger.debug("DSDFME_IDAPI error id=%s: %s", id_int, str(e))
            return None

        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as e:
            logger.debug("DSDFME_IDAPI error id=%s: invalid-json %s", id_int, str(e))
            return None

        if not isinstance(data, dict):
            return None

        results = data.get("results")
        if not isinstance(results, list) or not results:
            return None

        obj = results[0] if isinstance(results[0], dict) else {}
        callsign = str(obj.get("callsign") or "").strip()
        name = str(obj.get("name") or "").strip()
        if not name:
            first_name = str(obj.get("first_name") or obj.get("fname") or "").strip()
            last_name = str(obj.get("last_name") or obj.get("lname") or "").strip()
            name = " ".join(part for part in (first_name, last_name) if part).strip()
        return callsign, name


class DsdFmeModule(AutoStartModule):
    TCP_HOST = "127.0.0.1"
    RESTART_DELAY_SEC = 2.0
    PROFILES = {
        "dsdfme": ["-ft", "-Z"],
        "dsdfme-nxdn48": ["-fi", "-Z"],
        "dsdfme-nxdn96": ["-fn", "-Z"],
        "dsdfme-dpmr": ["-fm", "-Z"],
    }
    PROFILE_ARGS = PROFILES["dsdfme"]  # fallback
    META_PROTOCOL = "DSDFME"
    DEBUG_ENABLED = os.environ.get("DSDFME_DEBUG", "") == "1"
    DIAG_THROTTLE_SEC = 0.2
    CALL_LOG_THROTTLE_SEC = 0.3
    EMIT_THROTTLE_SEC = 0.25
    VOICE_HOLD_SEC = 1.2

    MODE_REGEXES = {
        "DMR": re.compile(r"\bDMR\b", re.IGNORECASE),
        "P25": re.compile(r"\bP25(?:P1|P2)?\b", re.IGNORECASE),
        "NXDN": re.compile(r"\bNXDN(?:48|96)?\b", re.IGNORECASE),
        "DSTAR": re.compile(r"\bD-?STAR\b", re.IGNORECASE),
        "YSF": re.compile(r"\bYSF\b", re.IGNORECASE),
    }
    DMR_BRACKET_SLOT_REGEX = re.compile(r"\[\s*slot\s*([12])\s*\]", re.IGNORECASE)
    TARGET_REGEXES = [
        re.compile(r"\b(?:target|tgt|talkgroup|tgid|tg|dest(?:ination)?|dst|to|yourcall|ur(?:call)?)\s*[:=]?\s*([A-Za-z0-9/_\.-]+)\b", re.IGNORECASE),
        re.compile(r"\bTG\s*[:=]?\s*([0-9]+)\b", re.IGNORECASE),
    ]
    SOURCE_REGEXES = [
        re.compile(r"\b(?:source|src|uid|from|rid|radioid|ourcall|my(?:call)?)\s*[:=]?\s*([A-Za-z0-9/_\.-]+)\b", re.IGNORECASE),
        re.compile(r"\bSRC\s*[:=]?\s*([A-Za-z0-9/_\.-]+)\b", re.IGNORECASE),
    ]
    ENCRYPTED_HIT_REGEX = re.compile(r"\bEncrypted\b", re.IGNORECASE)
    DIAG_LOG_REGEX = re.compile(
        r"(DMR|P25|NXDN|D-?STAR|YSF|\bslot\b|Color\s*Code|\bVC[1-6]?\b|\bTLC\b|\bVLC\b|\bGroup\b|\bPrivate\b|\bDirect\b|\bUnit\b|\bCall\b|\bTGT\b|\bSRC\b|\bDST\b|\bTO\b|\bFROM\b|Target:|Source:|Talkgroup|\bTG\b|\bUID\b|\bNAC\b|\bALG\b|\bKEY\b|Encrypted)",
        re.IGNORECASE,
    )
    DMR_SYNC_VOICE_REGEX = re.compile(r"\bVC(?:[1-6]|\*)", re.IGNORECASE)
    DMR_CALL_ACTIVITY_REGEX = re.compile(r"\|\s*(?:VC(?:[1-6]|\*)|TLC|VLC)(?=\s|$|\|)", re.IGNORECASE)
    DMR_ACTIVE_SLOT_UPDATE_REGEX = re.compile(r"(?:VC[1-6]|TLC|VLC|Target|Source)", re.IGNORECASE)
    DMR_IDLE_PIPE_REGEX = re.compile(r"\|\s*IDLE\b", re.IGNORECASE)
    DMR_CC_COLOR_CODE_REGEX = re.compile(r"Color\s*Code\s*=\s*([0-9]{1,2})\b", re.IGNORECASE)
    DMR_SLOT_TGT_SRC_REGEX = re.compile(r"SLOT\s*([12]).*?TGT[=:]\s*(\d+).*?SRC[=:]\s*(\d+)", re.IGNORECASE)
    DMR_SIMPLEX_HEADER_REGEX = re.compile(
        r"^SLOT\s+([12])\s+TGT=(\d+)\s+SRC=(\d+).*?\b(Group Call|Private Call)\b",
        re.IGNORECASE,
    )
    DMR_SIMPLEX_SYNC_REGEX = re.compile(r"MS/DM\s+MODE/MONO", re.IGNORECASE)
    DMR_FEC_ERR_REGEX = re.compile(r"FLCO\s+FEC\s+ERR", re.IGNORECASE)
    DMR_SOURCE_TARGET_REGEX = re.compile(r"Source:\s*(\d+)\s+Target:\s*(\d+)", re.IGNORECASE)
    DMR_TARGET_SOURCE_REGEX = re.compile(r"Target:\s*(\d+)\s+Source:\s*(\d+)", re.IGNORECASE)
    P25_SYNC_VOICE_REGEX = re.compile(r"\bLDU[12]\b", re.IGNORECASE)
    P25_GROUP_SOURCE_REGEX = re.compile(r"Group\s+(\d+)\s+Source\s+(\d+)", re.IGNORECASE)
    P25_NAC_CC_DEC_REGEX = re.compile(r"NAC/CC:\s*(\d+)", re.IGNORECASE)
    IDLE_REGEX = re.compile(r"\bIDLE\b", re.IGNORECASE)
    NAC_CC_REGEX = re.compile(r"\bNAC/CC\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)\b", re.IGNORECASE)
    NAC_REGEX = re.compile(r"\bNAC\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)\b", re.IGNORECASE)
    CC_REGEX = re.compile(r"\bCC\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)\b", re.IGNORECASE)
    VOICE_SYNC_REGEX = re.compile(r"\bSync:\s*\+", re.IGNORECASE)
    ALGID_REGEX = re.compile(r"ALG(?:\s+ID)?\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)
    KEYID_REGEX = re.compile(r"KEY(?:\s+ID)?\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)
    ANSI_ESCAPE_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

    def __init__(self, profile_key: str = "dsdfme"):
        self._profile_key = profile_key
        self._tcp_port = None
        self._udp_port = None
        super().__init__()
        self.doRun = False
        self.process = None
        self.tcpServerSocket = None
        self.tcpClientSocket = None
        self.audioSocket = None
        self.processLock = Lock()
        self.metawriter = None
        self.stderrTail = deque(maxlen=10)
        self.stateLock = Lock()
        self.lastMode = None
        self.lastDiagLine = ""
        self.lastDiagLogTs = 0.0
        self.lastCallLogTs = 0.0
        self.lastCallLogSignature = None
        self.debugEnabled = DsdFmeModule.DEBUG_ENABLED
        self.idApiResolver = RadioIdApiResolver()
        self.dmrStates = {
            "0": self._newState(slot="0", mode="DMR"),
            "1": self._newState(slot="1", mode="DMR"),
        }
        self.dmrLastCc = {"0": None, "1": None}
        self.dmrActiveSlot = None
        self.singleState = self._newState()
        self.managerThread = None
        self.inputThread = None

    def getInputFormat(self) -> Format:
        return Format.SHORT

    def getOutputFormat(self) -> Format:
        return Format.SHORT

    def setMetaWriter(self, writer: Writer) -> None:
        self.metawriter = writer

    def _buildCommand(self):
        return [
            "dsd-fme",
            "-i",
            f"tcp:{DsdFmeModule.TCP_HOST}:{self._tcp_port}",
            "-o",
            "udp:127.0.0.1:{}".format(self._udp_port),
        ] + DsdFmeModule.PROFILES.get(self._profile_key, DsdFmeModule.PROFILE_ARGS)

    def _newState(self, slot: str = None, mode: str = None):
        return {
            "mode": mode,
            "slot": slot,
            "target": None,
            "source": None,
            "call_type": None,
            "simplex": False,
            "cc": None,
            "nac": None,
            "encrypted": False,
            "algid": None,
            "keyid": None,
            "crypto_text": None,
            "last_voice_ts": 0.0,
            "last_emit_ts": 0.0,
            "last_payload_hash": None,
            "active": False,
            "clear_sent": False,
        }

    def _resetMetaState(self):
        with self.stateLock:
            self.lastMode = None
            self.lastDiagLine = ""
            self.lastDiagLogTs = 0.0
            self.lastCallLogTs = 0.0
            self.lastCallLogSignature = None
            self.dmrStates = {
                "0": self._newState(slot="0", mode="DMR"),
                "1": self._newState(slot="1", mode="DMR"),
            }
            self.dmrLastCc = {"0": None, "1": None}
            self.dmrActiveSlot = None
            self.singleState = self._newState()

    def start(self):
        if self.doRun:
            return

        self.doRun = True
        self.reader.resume()

        self.inputThread = Thread(target=self._inputLoop, daemon=True)
        self.inputThread.start()

        self.managerThread = Thread(target=self._managerLoop, daemon=True)
        self.managerThread.start()

    def stop(self):
        self.doRun = False
        self.reader.stop()
        self._stopProcess()
        if self.idApiResolver is not None:
            self.idApiResolver.stop()

    def _startProcess(self) -> bool:
        try:
            tcpServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcpServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcpServerSocket.bind((DsdFmeModule.TCP_HOST, 0))
            self._tcp_port = tcpServerSocket.getsockname()[1]
            tcpServerSocket.listen(1)
            tcpServerSocket.settimeout(0.5)
        except Exception:
            logger.exception("Unable to create TCP listener for dsd-fme input")
            return False

        try:
            audioSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            audioSocket.bind(("127.0.0.1", 0))
            audioSocket.settimeout(0.5)
            self._udp_port = audioSocket.getsockname()[1]
        except Exception:
            logger.exception("Unable to create UDP listener for dsd-fme audio")
            tcpServerSocket.close()
            return False

        cmd = self._buildCommand()
        try:
            process = Popen(cmd, stdin=DEVNULL, stdout=DEVNULL, stderr=PIPE)
        except FileNotFoundError:
            logger.error("Unable to start dsd-fme: command not found")
            self.doRun = False
            audioSocket.close()
            tcpServerSocket.close()
            return False
        except Exception:
            logger.exception("Unable to start dsd-fme")
            audioSocket.close()
            tcpServerSocket.close()
            return False

        with self.processLock:
            self.process = process
            self.tcpServerSocket = tcpServerSocket
            self.tcpClientSocket = None
            self.audioSocket = audioSocket
            self.stderrTail.clear()
        self._resetMetaState()

        Thread(target=self._tcpAcceptLoop, args=[process, tcpServerSocket], daemon=True).start()
        Thread(target=self._audioLoop, args=[process, audioSocket], daemon=True).start()
        Thread(target=self._stderrLoop, args=[process], daemon=True).start()

        logger.info("Started dsd-fme profile=%s tcp_port=%s udp_port=%s", self._profile_key, self._tcp_port, self._udp_port)
        return True

    def _stopProcess(self):
        with self.processLock:
            process = self.process
            self.process = None
            tcpClientSocket = self.tcpClientSocket
            self.tcpClientSocket = None
            tcpServerSocket = self.tcpServerSocket
            self.tcpServerSocket = None
            audioSocket = self.audioSocket
            self.audioSocket = None

        if tcpClientSocket is not None:
            try:
                tcpClientSocket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            except Exception:
                logger.exception("Error while shutting down dsd-fme TCP client socket")
            try:
                tcpClientSocket.close()
            except Exception:
                logger.exception("Error while closing dsd-fme TCP client socket")

        if tcpServerSocket is not None:
            try:
                tcpServerSocket.close()
            except Exception:
                logger.exception("Error while closing dsd-fme TCP server socket")

        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(2)
                else:
                    process.wait(0)
            except TimeoutExpired:
                try:
                    process.kill()
                    process.wait(2)
                except Exception:
                    logger.exception("Error while killing dsd-fme process")
            except Exception:
                logger.exception("Error while stopping dsd-fme process")

        if audioSocket is not None:
            try:
                audioSocket.close()
            except Exception:
                logger.exception("Error while closing dsd-fme audio socket")

    def _managerLoop(self):
        while self.doRun:
            if not self._startProcess():
                time.sleep(1.0)
                continue

            while self.doRun:
                with self.processLock:
                    process = self.process
                if process is None:
                    break
                rc = process.poll()
                if rc is not None:
                    tail = list(self.stderrTail)
                    if tail:
                        logger.warning("dsd-fme exited rc=%s; last stderr lines:\n%s", rc, "\n".join(tail))
                    else:
                        logger.warning("dsd-fme exited rc=%s; no stderr captured", rc)
                    break
                with self.stateLock:
                    self._expireConversationsLocked(time.monotonic())
                time.sleep(0.2)

            self._stopProcess()

            if self.doRun:
                time.sleep(DsdFmeModule.RESTART_DELAY_SEC)

    def _inputLoop(self):
        while self.doRun:
            data = self.reader.read()
            if data is None:
                self.doRun = False
                break
            if len(data) == 0:
                continue

            with self.processLock:
                process = self.process
                tcpClientSocket = self.tcpClientSocket

            if process is None or tcpClientSocket is None:
                continue

            try:
                if hasattr(data, "tobytes"):
                    data = data.tobytes()
                tcpClientSocket.sendall(data)
            except (BrokenPipeError, ValueError):
                pass
            except OSError:
                with self.processLock:
                    if self.tcpClientSocket is tcpClientSocket:
                        self.tcpClientSocket = None
                try:
                    tcpClientSocket.close()
                except Exception:
                    pass
            except Exception:
                logger.exception("Error writing discriminator audio to dsd-fme TCP input")

    def _tcpAcceptLoop(self, process, tcpServerSocket):
        while self.doRun and process.poll() is None:
            try:
                conn, _ = tcpServerSocket.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with self.processLock:
                    oldConn = self.tcpClientSocket
                    self.tcpClientSocket = conn
                if oldConn is not None:
                    try:
                        oldConn.close()
                    except Exception:
                        pass
                logger.debug("dsd-fme connected to TCP input")
                return
            except socket.timeout:
                continue
            except OSError:
                return
            except Exception:
                logger.exception("Error accepting dsd-fme TCP input connection")
                return

    def _audioLoop(self, process, audioSocket):
        while self.doRun and process.poll() is None:
            try:
                data, _ = audioSocket.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            # dsd-fme may output stereo (8k, 2ch): keep left channel only.
            if len(data) >= 4 and len(data) % 4 == 0:
                data = b"".join(data[i:i+2] for i in range(0, len(data), 4))
            try:
                self.writer.write(data)
            except Exception:
                break

    def _stderrLoop(self, process):
        while self.doRun and process.poll() is None:
            try:
                line = process.stderr.readline()
            except Exception:
                break
            if not line:
                break
            decoded = line.decode(errors="replace").strip()
            sanitized = self._sanitizeStderrLine(decoded)
            if sanitized:
                self.stderrTail.append(sanitized)
                self._parseStderrLine(sanitized)

    def _sanitizeStderrLine(self, line: str):
        if line is None:
            return ""
        sanitized = DsdFmeModule.ANSI_ESCAPE_REGEX.sub("", line)
        sanitized = DsdFmeModule.CONTROL_CHAR_REGEX.sub("", sanitized)
        return sanitized.strip()

    def _extractFirst(self, regexes, line):
        for regex in regexes:
            match = regex.search(line)
            if match:
                return match.group(1)
        return None

    def _emitMeta(self, meta):
        if self.metawriter is None:
            return
        try:
            self._logCallMeta(meta, time.monotonic())
            logger.debug("DSD-FME META: %s", meta)
            self.metawriter.write(pickle.dumps(meta))
        except Exception:
            logger.exception("Unable to write dsd-fme metadata")

    def _callLogSignature(self, meta: dict):
        return (
            meta.get("mode"),
            meta.get("slot"),
            meta.get("cc"),
            meta.get("tg"),
            meta.get("id"),
            meta.get("call_type"),
            bool(meta.get("simplex")),
            meta.get("nac"),
            meta.get("uid"),
            meta.get("algid"),
            meta.get("keyid"),
            bool(meta.get("encrypted")),
            bool(meta.get("clear")),
        )

    def _logCallMeta(self, meta: dict, now: float):
        if not self.debugEnabled:
            return
        if meta.get("protocol") != DsdFmeModule.META_PROTOCOL:
            return
        signature = self._callLogSignature(meta)
        if signature == self.lastCallLogSignature:
            return
        if now - self.lastCallLogTs < DsdFmeModule.CALL_LOG_THROTTLE_SEC:
            return
        self.lastCallLogTs = now
        self.lastCallLogSignature = signature
        logger.info(
            "DSDFME_CALL: mode=%s slot=%s cc=%s tg=%s id=%s nac=%s uid=%s alg=%s key=%s enc=%s",
            meta.get("mode"),
            meta.get("slot"),
            meta.get("cc"),
            meta.get("tg"),
            meta.get("id"),
            meta.get("nac"),
            meta.get("uid"),
            meta.get("algid"),
            meta.get("keyid"),
            str(bool(meta.get("encrypted"))).lower(),
        )

    def _toUiDmrSlot(self, slotText: str):
        if slotText == "1":
            return "0"
        if slotText == "2":
            return "1"
        return None

    def _detectMode(self, line: str):
        for mode, regex in DsdFmeModule.MODE_REGEXES.items():
            if regex.search(line) is not None:
                return mode
        return None

    def _isVoiceSync(self, line: str):
        if "voice" in line.lower():
            return True
        return DsdFmeModule.VOICE_SYNC_REGEX.search(line) is not None

    def _stateInVoiceWindow(self, state, now: float):
        lastVoiceTs = state.get("last_voice_ts", 0.0)
        return lastVoiceTs > 0 and (now - lastVoiceTs) < DsdFmeModule.VOICE_HOLD_SEC

    def _statePayloadHash(self, meta):
        keys = (
            "mode",
            "slot",
            "tg",
            "id",
            "call_type",
            "simplex",
            "uid",
            "cc",
            "nac",
            "encrypted",
            "algid",
            "keyid",
            "crypto_text",
            "sync",
        )
        return tuple((k, meta.get(k)) for k in keys if k in meta)

    def _composeStateMeta(self, state, syncVoice: bool):
        mode = state.get("mode") or "UNKNOWN"
        meta = {
            "protocol": DsdFmeModule.META_PROTOCOL,
            "mode": mode,
        }
        if self.lastDiagLine:
            meta["diag"] = self.lastDiagLine

        if mode == "DMR":
            meta["slot"] = state.get("slot")
            meta["cc"] = state.get("cc")
            meta["tg"] = state.get("target")
            meta["id"] = state.get("source")
            meta["call_type"] = state.get("call_type")
            meta["simplex"] = bool(state.get("simplex"))
            meta["encrypted"] = bool(state.get("encrypted"))
            meta["crypto_text"] = state.get("crypto_text") or ""
            dmr_id = meta.get("id") if meta.get("id") is not None else state.get("source")
            callsign, name = self.lookup_contact(dmr_id)
            meta["callsign"] = callsign
            meta["name"] = name
        elif mode == "P25":
            meta["nac"] = state.get("nac")
            meta["tg"] = state.get("target")
            meta["uid"] = state.get("source")
            meta["encrypted"] = bool(state.get("encrypted"))
            meta["crypto_text"] = state.get("crypto_text") or ""
            p25_uid = meta.get("uid") if meta.get("uid") is not None else state.get("source")
            callsign, name = self.lookup_contact(p25_uid)
            meta["callsign"] = callsign
            meta["name"] = name
            if state.get("encrypted"):
                if state.get("algid"):
                    meta["algid"] = state["algid"]
                if state.get("keyid"):
                    meta["keyid"] = state["keyid"]
        else:
            if state.get("target"):
                meta["tg"] = state["target"]
            if state.get("source"):
                meta["uid"] = state["source"]
            if state.get("nac"):
                meta["nac"] = state["nac"]
            if state.get("cc"):
                meta["cc"] = state["cc"]

        if mode not in ("DMR", "P25") and state.get("encrypted"):
            meta["encrypted"] = True
            if state.get("algid"):
                meta["algid"] = state["algid"]
            if state.get("keyid"):
                meta["keyid"] = state["keyid"]
            if state.get("crypto_text"):
                meta["crypto_text"] = state["crypto_text"]
        if syncVoice:
            meta["sync"] = "voice"
        return meta

    def _normalizeLookupId(self, value):
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except Exception:
            return None

    def lookup_contact(self, int_id):
        contactId = self._normalizeLookupId(int_id)
        if contactId is None:
            return "", ""
        return self.idApiResolver.resolve_nonblocking(contactId)

    def _clearStateValues(self, state):
        state["target"] = None
        state["source"] = None
        state["call_type"] = None
        state["simplex"] = False
        state["cc"] = None
        state["nac"] = None
        state["encrypted"] = False
        state["algid"] = None
        state["keyid"] = None
        state["crypto_text"] = None
        state["last_payload_hash"] = None

    def _expireStateLocked(self, state, now: float):
        if not state.get("active"):
            return
        if self._stateInVoiceWindow(state, now):
            return
        if state.get("clear_sent"):
            return

        clearMeta = {
            "protocol": DsdFmeModule.META_PROTOCOL,
            "mode": state.get("mode") or "UNKNOWN",
            "clear": True,
        }
        if state.get("slot") is not None:
            clearMeta["slot"] = state["slot"]
        self._emitMeta(clearMeta)

        state["active"] = False
        state["clear_sent"] = True
        state["last_voice_ts"] = 0.0
        state["last_emit_ts"] = now
        self._clearStateValues(state)

    def _expireConversationsLocked(self, now: float):
        self._expireStateLocked(self.dmrStates["0"], now)
        self._expireStateLocked(self.dmrStates["1"], now)
        self._expireStateLocked(self.singleState, now)

    def _buildCryptoText(self, algid: str = None, keyid: str = None):
        if algid or keyid:
            parts = []
            if algid:
                parts.append("ALG {}".format(algid))
            if keyid:
                parts.append("KEY {}".format(keyid))
            return " ".join(parts)
        return "ENCRYPTED"

    def _normalizeAlgidInt(self, algid: str):
        if algid is None:
            return None
        value = str(algid).strip().lower()
        try:
            if value.startswith("0x"):
                return int(value, 16)
            return int(value, 10)
        except Exception:
            return None

    def _classifyP25Algid(self, algid: str):
        # 0x80 and 0x00 are clear according to observed DSD-FME output.
        alg = self._normalizeAlgidInt(algid)
        if alg is None:
            return "unknown"
        if alg in (0x00, 0x80):
            return "clear"
        return "encrypted"

    def _extractModeCode(self, line: str, mode: str):
        nacCc = DsdFmeModule.NAC_CC_REGEX.search(line)
        if mode == "DMR":
            colorCode = DsdFmeModule.DMR_CC_COLOR_CODE_REGEX.search(line)
            if colorCode:
                return {"cc": colorCode.group(1)}
            if nacCc:
                return {"cc": nacCc.group(1)}
            cc = DsdFmeModule.CC_REGEX.search(line)
            if cc:
                return {"cc": cc.group(1)}
            return {}
        if mode == "P25":
            nacCcDec = DsdFmeModule.P25_NAC_CC_DEC_REGEX.search(line)
            if nacCcDec:
                return {"nac": nacCcDec.group(1)}
            if nacCc and str(nacCc.group(1)).isdigit():
                return {"nac": nacCc.group(1)}
            nac = DsdFmeModule.NAC_REGEX.search(line)
            if nac:
                return {"nac": nac.group(1)}
        return {}

    def _selectDmrStateLocked(self, slot: str, now: float):
        if slot in self.dmrStates:
            return self.dmrStates[slot]
        active = [s for s in self.dmrStates.values() if self._stateInVoiceWindow(s, now)]
        if len(active) == 1:
            return active[0]
        return None

    def _applyStateUpdateLocked(
        self,
        state,
        now: float,
        mode: str,
        voice: bool,
        updates: dict,
        encryptedHit: bool,
        algid: str,
        keyid: str,
        clearEncryption: bool = False,
        forceEmit: bool = False,
    ):
        changed = False

        if mode and state.get("mode") != mode:
            state["mode"] = mode
            self._clearStateValues(state)
            changed = True

        for key, value in updates.items():
            if value is None:
                continue
            if state.get(key) != value:
                state[key] = value
                changed = True

        if clearEncryption:
            if state.get("encrypted"):
                state["encrypted"] = False
                changed = True
            if state.get("algid") is not None:
                state["algid"] = None
                changed = True
            if state.get("keyid") is not None:
                state["keyid"] = None
                changed = True
            if state.get("crypto_text"):
                state["crypto_text"] = None
                changed = True

        if encryptedHit:
            if not state.get("encrypted"):
                changed = True
            state["encrypted"] = True

        if algid is not None and state.get("algid") != algid:
            state["algid"] = algid
            changed = True

        if keyid is not None and state.get("keyid") != keyid:
            state["keyid"] = keyid
            changed = True

        if state.get("encrypted"):
            cryptoText = self._buildCryptoText(state.get("algid"), state.get("keyid"))
            if state.get("crypto_text") != cryptoText:
                state["crypto_text"] = cryptoText
                changed = True
        elif clearEncryption and state.get("crypto_text") is not None:
            state["crypto_text"] = None
            changed = True

        wasVoiceWindow = self._stateInVoiceWindow(state, now)
        startedVoice = False
        if voice:
            startedVoice = not wasVoiceWindow
            state["last_voice_ts"] = now
            state["active"] = True
            state["clear_sent"] = False

        inVoiceWindow = self._stateInVoiceWindow(state, now)
        if not state.get("active") and not changed:
            return

        meta = self._composeStateMeta(state, syncVoice=inVoiceWindow)
        payloadHash = self._statePayloadHash(meta)
        payloadChanged = payloadHash != state.get("last_payload_hash")

        emitDue = inVoiceWindow and (now - state.get("last_emit_ts", 0.0) >= DsdFmeModule.EMIT_THROTTLE_SEC)
        shouldEmit = forceEmit or startedVoice or payloadChanged or emitDue
        if not shouldEmit:
            return

        state["last_emit_ts"] = now
        state["last_payload_hash"] = payloadHash
        self._emitMeta(meta)

    def _handleDmrLineLocked(self, line: str, now: float):
        slotMatch = DsdFmeModule.DMR_BRACKET_SLOT_REGEX.search(line)
        slotRaw = slotMatch.group(1) if slotMatch else None
        bracketSlot = self._toUiDmrSlot(slotRaw) if slotRaw else None
        hasIdle = DsdFmeModule.DMR_IDLE_PIPE_REGEX.search(line) is not None
        if bracketSlot is not None and not hasIdle:
            self.dmrActiveSlot = bracketSlot

        slotForState = self.dmrActiveSlot
        source = None
        target = None
        callType = None
        forceEmit = False

        simplexHeader = DsdFmeModule.DMR_SIMPLEX_HEADER_REGEX.search(line)
        if simplexHeader is not None:
            parsedSlot = self._toUiDmrSlot(simplexHeader.group(1))
            if parsedSlot in self.dmrStates:
                slotForState = parsedSlot
                self.dmrActiveSlot = parsedSlot
            target = simplexHeader.group(2)
            source = simplexHeader.group(3)
            callTypeRaw = simplexHeader.group(4).strip().lower()
            if "group" in callTypeRaw:
                callType = "Group"
            elif "private" in callTypeRaw:
                callType = "Private"
            forceEmit = True
        else:
            slotTgtSrc = DsdFmeModule.DMR_SLOT_TGT_SRC_REGEX.search(line)
            if slotTgtSrc is not None:
                parsedSlot = self._toUiDmrSlot(slotTgtSrc.group(1))
                if parsedSlot in self.dmrStates and not hasIdle:
                    slotForState = parsedSlot
                target = slotTgtSrc.group(2)
                source = slotTgtSrc.group(3)
            else:
                sourceTarget = DsdFmeModule.DMR_SOURCE_TARGET_REGEX.search(line)
                if sourceTarget is not None:
                    source = sourceTarget.group(1)
                    target = sourceTarget.group(2)
                else:
                    targetSource = DsdFmeModule.DMR_TARGET_SOURCE_REGEX.search(line)
                    if targetSource is not None:
                        target = targetSource.group(1)
                        source = targetSource.group(2)

        if slotForState not in self.dmrStates:
            return

        state = self.dmrStates[slotForState]

        voice = (DsdFmeModule.DMR_CALL_ACTIVITY_REGEX.search(line) is not None) or forceEmit
        modeCode = self._extractModeCode(line, "DMR")
        if modeCode.get("cc") is not None:
            self.dmrLastCc[slotForState] = modeCode["cc"]
        elif self.dmrLastCc.get(slotForState) is not None:
            modeCode["cc"] = self.dmrLastCc[slotForState]
        encryptedHit = DsdFmeModule.ENCRYPTED_HIT_REGEX.search(line) is not None
        algid = None
        keyid = None
        if encryptedHit:
            algMatch = DsdFmeModule.ALGID_REGEX.search(line)
            keyMatch = DsdFmeModule.KEYID_REGEX.search(line)
            algid = algMatch.group(1) if algMatch else None
            keyid = keyMatch.group(1) if keyMatch else None

        updates = {"target": target, "source": source, "call_type": callType}
        if DsdFmeModule.DMR_SIMPLEX_SYNC_REGEX.search(line) is not None:
            updates["simplex"] = True
        updates.update(modeCode)

        # DMR IDLE should not clear metadata and should not move active slot.
        if DsdFmeModule.IDLE_REGEX.search(line) is not None:
            voice = False

        self._applyStateUpdateLocked(
            state=state,
            now=now,
            mode="DMR",
            voice=voice,
            updates=updates,
            encryptedHit=encryptedHit,
            algid=algid,
            keyid=keyid,
            forceEmit=forceEmit,
        )

    def _handleSingleLineLocked(self, line: str, mode: str, now: float):
        if mode == "P25":
            voice = DsdFmeModule.P25_SYNC_VOICE_REGEX.search(line) is not None
            modeCode = self._extractModeCode(line, mode)

            groupSource = DsdFmeModule.P25_GROUP_SOURCE_REGEX.search(line)
            target = groupSource.group(1) if groupSource else None
            source = groupSource.group(2) if groupSource else None

            algMatch = DsdFmeModule.ALGID_REGEX.search(line)
            keyMatch = DsdFmeModule.KEYID_REGEX.search(line)
            algidRaw = algMatch.group(1) if algMatch else None
            keyidRaw = keyMatch.group(1) if keyMatch else None
            algClass = self._classifyP25Algid(algidRaw)
            clearEncryption = algClass == "clear"
            encryptedHit = algClass == "encrypted"
            algid = algidRaw if encryptedHit else None
            keyid = keyidRaw if encryptedHit else None

            updates = {"target": target, "source": source}
            updates.update(modeCode)

            self._applyStateUpdateLocked(
                state=self.singleState,
                now=now,
                mode=mode,
                voice=voice,
                updates=updates,
                encryptedHit=encryptedHit,
                algid=algid,
                keyid=keyid,
                clearEncryption=clearEncryption,
            )
            return

        source = self._extractFirst(DsdFmeModule.SOURCE_REGEXES, line)
        target = self._extractFirst(DsdFmeModule.TARGET_REGEXES, line)
        modeCode = self._extractModeCode(line, mode)
        voice = self._isVoiceSync(line)
        encryptedHit = DsdFmeModule.ENCRYPTED_HIT_REGEX.search(line) is not None
        algMatch = DsdFmeModule.ALGID_REGEX.search(line)
        keyMatch = DsdFmeModule.KEYID_REGEX.search(line)
        algid = algMatch.group(1) if algMatch else None
        keyid = keyMatch.group(1) if keyMatch else None

        updates = {"target": target, "source": source}
        updates.update(modeCode)

        self._applyStateUpdateLocked(
            state=self.singleState,
            now=now,
            mode=mode,
            voice=voice,
            updates=updates,
            encryptedHit=encryptedHit,
            algid=algid,
            keyid=keyid,
        )

    def _parseStderrLine(self, line: str):
        if not line:
            return
        line = self._sanitizeStderrLine(line)
        if not line:
            return
        now = time.monotonic()

        with self.stateLock:
            if DsdFmeModule.DIAG_LOG_REGEX.search(line) is not None:
                self.lastDiagLine = line[:200]
                if now - self.lastDiagLogTs >= DsdFmeModule.DIAG_THROTTLE_SEC:
                    self.lastDiagLogTs = now
                    logger.info("DSDFME_RAW: %s", self.lastDiagLine)

            modeDetected = self._detectMode(line)
            if modeDetected is not None:
                self.lastMode = modeDetected

            mode = modeDetected if modeDetected is not None else self.lastMode
            if (
                DsdFmeModule.DMR_SYNC_VOICE_REGEX.search(line) is not None
                or DsdFmeModule.DMR_CALL_ACTIVITY_REGEX.search(line) is not None
                or DsdFmeModule.DMR_BRACKET_SLOT_REGEX.search(line) is not None
                or DsdFmeModule.DMR_SLOT_TGT_SRC_REGEX.search(line) is not None
                or DsdFmeModule.DMR_SOURCE_TARGET_REGEX.search(line) is not None
                or DsdFmeModule.DMR_TARGET_SOURCE_REGEX.search(line) is not None
            ):
                mode = "DMR"
            elif DsdFmeModule.P25_SYNC_VOICE_REGEX.search(line) is not None:
                mode = "P25"

            if mode == "DMR":
                self._handleDmrLineLocked(line, now)
            elif mode is not None:
                self._handleSingleLineLocked(line, mode, now)

            self._expireConversationsLocked(now)
