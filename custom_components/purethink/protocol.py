import logging
import random
import json
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def parse_status_packet(payload: str) -> dict:
    """상태 패킷 파싱 (전체 필드 구현)"""
    _LOGGER.debug("Parsing raw packet: %s...", payload[:24])
    try:
        return {
            "power": _parse_bits(payload[8:10], 0, 1),
            "fan_speed": _parse_bits(payload[8:10], 1, 3),
            "ai_mode": _parse_bits(payload[8:10], 4, 1),
            "sleep_mode": _parse_bits(payload[8:10], 5, 2),
            "input_occurred": _parse_bits(payload[8:10], 7, 1),

            "odor": _parse_bits(payload[10:12], 0, 2),
            "pressure_mode": _parse_bits(payload[10:12], 2, 2),
            "wifi": _parse_bits(payload[10:12], 5, 3),

            "fan_in": _parse_bits(payload[12:14], 0, 1),
            "fan_out": _parse_bits(payload[12:14], 1, 1),
            "reserved_bits": _parse_bits(payload[12:14], 2, 6),

            "fan1_alarm": _parse_bits(payload[14:16], 0, 1),
            "fan2_alarm": _parse_bits(payload[14:16], 1, 1),
            "dust_sensor_alarm": _parse_bits(payload[14:16], 2, 1),
            "co2_sensor_alarm": _parse_bits(payload[14:16], 3, 1),
            "filter_alarm": _parse_bits(payload[14:16], 4, 1),
            "heat_exchanger_alarm": _parse_bits(payload[14:16], 5, 1),

            "co2": _parse_bits(payload[16:28], 1, 13),
            "pm1": _parse_bits(payload[16:28], 14, 10),
            "pm25": _parse_bits(payload[16:28], 24, 10),
            "pm10": _parse_bits(payload[16:28], 34, 10),

            "prefilter": _parse_filter(payload[28:36], 2, 14),
            "hepafilter": _parse_filter(payload[28:36], 18, 14),
        }
    except Exception as e:
        _LOGGER.error("Packet parsing failed: %s", str(e), exc_info=True)
        raise


def _parse_bits(hex_str: str, start_bit: int, length: int) -> int:
    try:
        full_bits = bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)
        return int(full_bits[start_bit:start_bit + length], 2)
    except ValueError:
        _LOGGER.error("Bit parsing error: %s [%s:%s]", hex_str, start_bit, length)
        raise


def _parse_filter(hex_str: str, start_bit: int, length: int) -> dict:
    return {
        "reset_flag": bool(_parse_bits(hex_str, start_bit - 2, 1)),
        "hours": _parse_bits(hex_str, start_bit, length),
    }


def _get_state_for_device(device_id: str, hass) -> dict:
    domain_data = hass.data.get(DOMAIN, {})
    dev_map = domain_data.get("_devices", {})
    entry_id = dev_map.get(device_id)
    if entry_id and entry_id in domain_data:
        return domain_data[entry_id].get("state", {}) or {}
    return {}


def generate_command(device_id: str, hass, **kwargs) -> str:
    try:
        state = _get_state_for_device(device_id, hass)

        if "mode" in kwargs:
            if kwargs["mode"] in ["on", "off"]:
                kwargs["power"] = 1 if kwargs["mode"] == "on" else 0
            else:
                kwargs["device_mode"] = kwargs["mode"]
                kwargs.pop("mode")
                if "power" not in kwargs:
                    kwargs["power"] = 1

        if "device_mode" in kwargs:
            mode = kwargs["device_mode"]
            if mode == "Normal":
                kwargs["ai_mode"] = 0
                kwargs["sleep_mode"] = 0
            elif mode == "AI Mode":
                kwargs["ai_mode"] = 1
                kwargs["sleep_mode"] = 0
            elif "Sleep" in mode:
                try:
                    sleep_value = int(mode.split()[1])
                except Exception:
                    sleep_value = 1
                kwargs["ai_mode"] = 0
                kwargs["sleep_mode"] = sleep_value

        if "pressure_mode" in kwargs:
            kwargs["pressure_mode"] = {"정압": 0, "양압": 1, "음압": 2}.get(kwargs["pressure_mode"], 0)

        if "fan_mode" in kwargs:
            kwargs["fan_in"], kwargs["fan_out"] = {
                "흡기Off-배기Off": (0, 0),
                "흡기Off-배기On":  (0, 1),
                "흡기On-배기Off":  (1, 0),
                "흡기On-배기On":   (1, 1),
            }.get(kwargs["fan_mode"], (0, 0))

        combined = {**state, **kwargs}
        fan_speed = combined.get("fan_speed", 4)
        power = combined.get("power", 0)
        ai_mode = combined.get("ai_mode", 0)
        sleep_mode = combined.get("sleep_mode", 0)
        pressure_mode = combined.get("pressure_mode", 0)
        fan_in = combined.get("fan_in", 0)
        fan_out = combined.get("fan_out", 0)

        topic_id = str(random.randint(100000, 200000))

        bin_power = int(power) << 7
        bin_fan_speed = int(fan_speed) << 4
        bin_ai_mode = int(ai_mode) << 3
        bin_sleep_mode = int(sleep_mode) << 1
        b5 = bin_power | bin_fan_speed | bin_ai_mode | bin_sleep_mode | 1

        b6 = int(pressure_mode) << 4

        bin_fan_in = int(fan_in) << 7
        bin_fan_out = int(fan_out) << 6
        b7 = bin_fan_in | bin_fan_out

        b15 = b16 = b17 = b18 = 0
        if "filter_reset" in kwargs:
            reset_type = kwargs["filter_reset"]
            if reset_type == "prefilter":
                b15, b16 = 135, 208
            elif reset_type == "hepafilter":
                b17, b18 = 143, 160
            else:
                _LOGGER.error("Invalid filter reset type: %s", reset_type)
                return None

        checksum = 393 + b5 + b6 + b7 + b15 + b16 + b17 + b18

        payload = (
            f"{b5:02X}{b6:02X}{b7:02X}"
            f"{'00' * 7}"
            f"{b15:02X}{b16:02X}{b17:02X}{b18:02X}"
            f"{'00' * 3}"
            f"{checksum:04X}"
        )
        contents = f"A8A81722{payload}"

        if len(contents) != 46:
            _LOGGER.warning("[generate_command] CMD 길이 불일치: %s자 (예상: 46자)", len(contents))

        command = {"topic_id": topic_id, "type": "CMD", "contents": contents}
        _LOGGER.debug("[generate_command] 최종 CMD ▶ %s", contents)
        return json.dumps(command)

    except Exception as e:
        _LOGGER.error("[generate_command] 생성 실패: %s", e, exc_info=True)
        raise
