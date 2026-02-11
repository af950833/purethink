import logging
import json
import ssl
import paho.mqtt.client as mqtt

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import DOMAIN
from .protocol import parse_status_packet, generate_command

_LOGGER = logging.getLogger(__name__)

# MQTT Broker 정보
MQTT_BROKER = "dapt.iptime.org"
MQTT_PORT = 8885


def _create_tls_context() -> ssl.SSLContext:
    """TLS 설정 (인증서 검증 비활성화)"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _on_connect(client, userdata, flags, rc):
    """MQTT 연결 시 실행"""
    if rc == 0:
        _LOGGER.info("[MQTT] 연결 성공 (%s)", userdata.get("entry_id"))
        status_topic = userdata.get("status_topic")
        if status_topic:
            client.subscribe(status_topic)
            _LOGGER.debug("[MQTT] subscribed: %s", status_topic)
    else:
        _LOGGER.error("[MQTT] 연결 실패 (코드 %s)", rc)


def _on_message(client, userdata, msg):
    """MQTT 메시지 수신 핸들러"""
    hass: HomeAssistant = userdata.get("hass")
    entry_id: str = userdata.get("entry_id")

    if hass is None or entry_id is None:
        _LOGGER.error("[MQTT] userdata 누락: hass=%s entry_id=%s", hass, entry_id)
        return

    try:
        payload = msg.payload.decode("utf-8")
        payload_json = json.loads(payload)

        if "contents" not in payload_json:
            _LOGGER.warning("[MQTT] 잘못된 메시지 형식 (contents 없음): %s", payload_json)
            return

        payload_hex = payload_json["contents"]

        if not payload_hex.startswith("A8A81721"):
            return

        parsed = parse_status_packet(payload_hex)

        if not parsed:
            _LOGGER.error("[MQTT] 상태 패킷 파싱 실패: %s", payload_hex)
            return

        full_state = {
            **parsed,
            "prefilter_hours": parsed.get("prefilter", {}).get("hours", 0),
            "prefilter_reset": parsed.get("prefilter", {}).get("reset_flag", 0),
            "hepafilter_hours": parsed.get("hepafilter", {}).get("hours", 0),
            "hepafilter_reset": parsed.get("hepafilter", {}).get("reset_flag", 0),
        }

        hass.data[DOMAIN][entry_id]["state"] = full_state

        hass.loop.call_soon_threadsafe(
            async_dispatcher_send,
            hass,
            f"{DOMAIN}_state_update_{entry_id}",
        )

    except Exception as e:
        _LOGGER.error("[MQTT] 메시지 처리 실패: %s", e, exc_info=True)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Config Entry 설정"""
    _LOGGER.debug("Initializing entry: %s", entry.data)
    config = entry.data
    device_id = config["device_id"]

    base_topic = f"/things/{device_id}"
    status_topic = f"{base_topic}/shadow"
    command_topic = f"{base_topic}/shadow"

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN].setdefault("_devices", {})  # device_id -> entry_id

    hass.data[DOMAIN][entry.entry_id] = {
        "state": {},
        "status_topic": status_topic,
        "command_topic": command_topic,
        "device_id": device_id,
        "mqtt": None,
    }
    hass.data[DOMAIN]["_devices"][device_id] = entry.entry_id

    client = mqtt.Client()
    client.enable_logger(_LOGGER)
    client.user_data_set({"hass": hass, "entry_id": entry.entry_id, "status_topic": status_topic})
    client.on_connect = _on_connect
    client.on_message = _on_message

    try:
        client.tls_set_context(_create_tls_context())
    except Exception as e:
        _LOGGER.error("[MQTT] TLS 설정 오류: %s", e, exc_info=True)
        return False

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_start()
    except Exception as e:
        _LOGGER.error("[MQTT] 연결 실패: %s", e, exc_info=True)
        return False

    hass.data[DOMAIN][entry.entry_id]["mqtt"] = client

    await hass.config_entries.async_forward_entry_setups(entry, ["sensor", "switch", "select", "binary_sensor"])

    async def handle_reset_filter(call):
        try:
            filter_type = (call.data.get("filter_type") or "").strip().lower()
            target_device_id = (call.data.get("device_id") or "").strip()

            _LOGGER.debug("[Service] 필터 리셋 요청: filter_type=%s device_id=%s", filter_type, target_device_id)

            if target_device_id:
                target_entry_id = hass.data[DOMAIN]["_devices"].get(target_device_id)
                if not target_entry_id:
                    raise ValueError(f"Unknown device_id: {target_device_id}")
            else:
                entry_ids = [
                    k for k, v in hass.data[DOMAIN].items()
                    if isinstance(v, dict) and "command_topic" in v
                ]
                if len(entry_ids) != 1:
                    raise ValueError("Multiple devices are configured. Provide device_id in service call.")
                target_entry_id = entry_ids[0]

            entry_data = hass.data[DOMAIN][target_entry_id]
            mqtt_client = entry_data["mqtt"]
            command_topic = entry_data["command_topic"]
            device_id_local = entry_data["device_id"]

            payload = generate_command(device_id_local, hass, filter_reset=filter_type)
            if payload:
                mqtt_client.publish(command_topic, payload, qos=1)
                _LOGGER.debug("[Service] 필터 리셋 명령 전송 ▶ %s", payload)
            else:
                _LOGGER.error("[Service] 필터 리셋 명령 생성 실패")

        except Exception as e:
            _LOGGER.error("[Service] 필터 리셋 처리 중 오류 발생: %s", e, exc_info=True)
            raise

    hass.services.async_register(DOMAIN, "reset_filter", handle_reset_filter)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Config Entry 제거 시 정리"""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, ["sensor", "switch", "select", "binary_sensor"])

    entry_data = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if entry_data:
        client = entry_data.get("mqtt")
        try:
            if client:
                client.loop_stop()
                client.disconnect()
        except Exception:
            _LOGGER.debug("[MQTT] disconnect/stop 중 예외 (무시)", exc_info=True)

        dev_map = hass.data.get(DOMAIN, {}).get("_devices", {})
        device_id = entry_data.get("device_id")
        if device_id and dev_map.get(device_id) == entry.entry_id:
            dev_map.pop(device_id, None)

        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok

