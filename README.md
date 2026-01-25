# 창문형 열교환기 - Purethink

![Tmap Address Logo](images/logo.png)

[퓨어싱크](https://purethink.co.kr/) 제품을 Home Assistant 에서 제어합니다.

## 1. Purethink 사용 준비

1. Purethink 앱에서 등록할 때 기기를 발견했을 때 화면에 나오는 "DIV01-1234AB" 또는 "THESOOP-1234AB" 형태의 이름을 기억해 둡니다.
2. 설치하신지 오래 되어 기억이 안나시면 공유기에서 Purethink 제품의 MAC을 확인하시고 마지막 6자리를 메모해 둡니다.
3. "DIV01-MAC 6자리" 또는 "THESOOP-MAC 6자리" 형태로 둘 중에 하나입니다.

## 2. Home Assistant에 Purethink Ventilation 설치

### HACS 또는 Manual 설치

1. HACS를 이용하거나 수동으로 **Purethink**를 설치합니다.
2. 설치 후 Home Assistant를 재부팅합니다.

### 통합 구성 요소 추가

1. **설정 -> 기기 및 서비스 -> 통합구성요소 추가하기**에서 `Purethink Ventilation`을 추가합니다.
2. 설정 항목을 입력합니다.
   - **friendly_name**: 원하는 센서 이름을 입력합니다(Purethink 로 넣으시면 아래쪽의 Lovelace 적용시 센서 이름 변경이 필요 없음)
   - **device_id**: 사용 준비에서 구한 "DIV01-MAC6자리" 또는 "THESOOP-MAC6자리"

추가가 완료되면 총 18개의 entity_id가 추가 됩니다.
센서류는 20~30초 정도 후에 값이 올라오면서 정상으로 보이실 겁니다.

## 3. Lovelace 설정
1. 현재 리포의 images 폴더 안에 있는 purethink3.jpg 파일을 다운 받으신 후에 HA의 www 폴더 안에 올려 줍니다.
2. [Text Element Card](https://github.com/custom-cards/text-element) 를 수동으로 설치해 줍니다.
3. HACS 에서 Mushroom Card를 검색해서 설치해 줍니다.
4. lovelace.yaml 파일 안의 내용을 복사하셔서 카드를 구성합니다.
5. 구성 완료된 카드의 필터를 길게 누르고 계시면 해당 필터 사용 시간이 리셋됩니다.

## Version History
- 25/02/16 V1.0.0 초기 릴리즈
- 25/02/17 V1.5.1 HA 내장 MQTT 제거 후 제조사 서버에 직접 통신 형태로 변경
- 25/02/18 V1.5.5 Bit parsing 정리, Wifi 감도 센서 추가
- 25/02/19 V1.5.6 TVOC 명칭을 Odor(악취)로 변경, Lovelace 반영
- 25/02/19 V1.5.7 Wifi를 0 ~ 7 레벨에서 0 ~ 100% 형태로 표기 방법 변경
- 25/02/20 V1.5.8 코드 최적화, 기능 변경 없음
- 25/02/21 V1.5.9 전원이 꺼지면 모든 바이너리 센서 Off 로 변경
- 25/02/21 V1.6.1 전원 On/Off 시에 기존 설정 유지
- 25/02/23 V1.6.2 코드 최적화, 아이콘 수정
- 25/03/08 V1.6.3 팬속도 복원 최적화
- 25/03/14 V1.6.4 팬속도 복원 버그 수정
- 25/03/20 V1.6.5 AI모드, Sleep모드 전환시 흡배기 상태, 압력 모드 유지 안되는 버그 수정
- 25/04/01 V1.6.6 전원 On, Off 시 동일 상태면 무시(켜진 상태에서 자동화로 전원 On 시에 Mode, Fan Speed가 복원되는 문제 해결)
- 25/04/07 V1.6.7 Minor bug fix
- 25/07/10 V1.7.0 필터리셋 서비스 등록으로 해결
- 26/01/25 V1.8.0 멀티 기기 사용 불가 해결
