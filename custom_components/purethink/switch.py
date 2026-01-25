import logging
from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from .const import DOMAIN
from .protocol import generate_command
_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass, config_entry, async_add_entities):
    """스위치 플랫폼 설정 (비동기)"""
    entry_data = hass.data[DOMAIN][config_entry.entry_id]
    switches = [
        PowerSwitch(hass, config_entry, entry_data["command_topic"])
    ]
    async_add_entities(switches)
    entry_data.setdefault("entities", []).extend(switches)

class PowerSwitch(SwitchEntity):
    """전원 스위치"""
    
    def __init__(self, hass, entry, command_topic):
        self.hass = hass
        self._entry = entry
        self._command_topic = command_topic
        config = entry.data
        self._attr_unique_id = f"{config['device_id']}_power"
        self._attr_name = f"{config['friendly_name']} Power"
        self.entity_id = f"switch.{config['base_id']}_power"
        self._attr_available = False

    async def async_added_to_hass(self):
        """상태 업데이트 신호 구독"""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{DOMAIN}_state_update_{self._entry.entry_id}",
                self._handle_update
            )
        )

    def _handle_update(self):
        """상태 업데이트"""
        state = self.hass.data[DOMAIN][self._entry.entry_id]["state"]
        self._attr_available = bool(state)
        self.schedule_update_ha_state()

    @property
    def is_on(self) -> bool:
        """현재 전원 상태 반환"""
        state = self.hass.data[DOMAIN][self._entry.entry_id]["state"]
        return bool(state.get("power", 0))

    @property
    def icon(self):
        return "mdi:power"

    async def async_turn_off(self, **kwargs):
        """전원 끄기 (현재 상태 저장, 단 켜져 있을 때만)"""
        if not self.is_on:
            _LOGGER.debug("[PowerSwitch] 이미 전원이 꺼져 있어 저장 및 전송 생략")
            return
            
        entry_data = self.hass.data[DOMAIN][self._entry.entry_id]
        state = entry_data.get("state", {})
        
        # 현재 디바이스 모드 저장
        if state.get("ai_mode") == 1:
            entry_data["last_device_mode"] = "AI Mode"
        elif state.get("sleep_mode") == 1:
            entry_data["last_device_mode"] = "Sleep 1"
        elif state.get("sleep_mode") == 2:
            entry_data["last_device_mode"] = "Sleep 2"
        elif state.get("sleep_mode") == 3:
            entry_data["last_device_mode"] = "Sleep 3"
        else:
            entry_data["last_device_mode"] = state.get("device_mode", "Normal")
        _LOGGER.debug(f"[PowerSwitch] 전원 끄기 -현재 Device Mode 저장: {entry_data['last_device_mode']}")
        
        if entry_data["last_device_mode"] == "Normal":
            current_fan_speed = state.get("fan_speed", 4)
            # Normal모드이면서 현재 팬 속도가 0이 아니면 팬속도 저장
            if current_fan_speed != 0:
                entry_data["last_fan_speed"] = current_fan_speed
            _LOGGER.debug(f"[PowerSwitch] 전원 끄기 - 현재 Fan Speed 저장: {entry_data.get('last_fan_speed')}")
    
        # 전원 끄기 명령 전송
        await self._send_command(mode="off")
    
    async def async_turn_on(self, **kwargs):
        """전원 켜기 (저장된 팬 속도와 모드 복원, 단 꺼져 있을 때만)"""
        if self.is_on:
            _LOGGER.debug("[PowerSwitch] 이미 전원이 켜져 있어 복원 동작 생략")
            return
            
        entry_data = self.hass.data[DOMAIN][self._entry.entry_id]
    
        # 저장된 디바이스 모드, 팬 속도 가져오기 (없으면 기본값 Normal, 4)
        last_device_mode = entry_data.get("last_device_mode", "Normal")
        if last_device_mode == "Normal":
            last_fan_speed = entry_data.get("last_fan_speed", 4)
            await self._send_command(mode="on", fan_speed=last_fan_speed,device_mode=last_device_mode)
            _LOGGER.debug(f"[PowerSwitch] 전원 켜짐 - 저장된 Fan Speed 복원: {last_fan_speed}, 저장된 Device Mode 복원: {last_device_mode}")
        else:
            await self._send_command(mode="on", device_mode=last_device_mode)
            _LOGGER.debug(f"[PowerSwitch] 전원 켜짐 - 저장된 Device Mode 복원: {last_device_mode}")

    async def _send_command(self, **kwargs):
        """MQTT 명령 전송"""
        try:
            payload = generate_command(
                self._entry.data["device_id"],
                self.hass,
                **kwargs
            )
            self.hass.data[DOMAIN][self._entry.entry_id]["mqtt"].publish(self._command_topic, payload, qos=1)
            _LOGGER.debug(f"[PowerSwitch] Command sent ▶ {payload}")
        except Exception as e:
            _LOGGER.error(f"[PowerSwitch] 명령 전송 실패: {e}", exc_info=True)
