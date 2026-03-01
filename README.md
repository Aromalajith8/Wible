# Wible
"An educational ESP32 PoC demonstrating 802.11 bare-metal packet capture, FreeRTOS memory management, and BLE protocol exploration."


<p align="center">
  <img src="Wible interface.jpeg" alt="Wible Logo" width="250"/>
</p>

# Wible - ESP32 Wireless Protocol Exploration
## ⚠️ Important Legal & Ethical Disclaimer
**This project is strictly for educational and academic purposes only.** The code provided in this repository is designed to demonstrate how 802.11 and Bluetooth Low Energy (BLE) protocols function at a low level, specifically focusing on packet manipulation, promiscuous mode, and RF frame generation. 

* **Do not use this software on any network or device that you do not own or do not have explicit, documented permission to test.** Unauthorized interference with wireless networks is illegal in most jurisdictions and heavily penalized.
* The author of this repository assumes absolutely no liability and is not responsible for any misuse, damage, or legal consequences caused by utilizing this code. Use responsibly and legally.

## Overview
Wible is a proof-of-concept (PoC) written in C++ for the ESP32 microcontroller. It explores the boundaries of the ESP32's hardware capabilities, specifically utilizing the ESP-IDF framework alongside Arduino core libraries to interact directly with wireless protocols. 

The primary goal of this project is to understand how wireless frames are structured, intercepted, and generated, providing hands-on experience with bare-metal protocol analysis.

## Technical Concepts Demonstrated
This repository serves as a practical exploration of several advanced embedded systems and networking concepts:

* **802.11 Promiscuous Mode:** Utilizing `esp_wifi_set_promiscuous` to capture raw management and data frames in the air.
* **Real-Time Operating System (RTOS) Management:** Leveraging FreeRTOS tasks (`xTaskCreate`) and queues (`xQueueCreate`) to manage memory effectively and prevent watch-dog timer (WDT) resets while handling high-throughput packet captures.
* **PCAP Generation & Storage:** Parsing raw 802.11 frames, stripping corrupted hardware flags (FCS correction to prevent "Malformed Packet" errors in Wireshark), structuring them into `.pcap` format, and writing them directly to the ESP32's SPIFFS memory.
* **BLE Advertisement Manipulation:** Releasing classic Bluetooth memory (`esp_bt_controller_mem_release`) to optimize for BLE, and dynamically altering MAC addresses and advertisement payloads using the GAP API.
* **Asynchronous Web Interface:** Serving a responsive, localized HTML/JS dashboard from the ESP32 to monitor real-time packet statistics and capture states.

## Hardware Compatibility
This code was specifically developed and tested on the following chipset:
* **Chip:** ESP32-D0WD-V3
* **Cores:** 2
* **Revision:** 3

*Note: Behavior on other ESP32 variants (like the S2, S3, or C3) or older revisions is not guaranteed and may require significant modification to the Wi-Fi PHY and Bluetooth controller initialization sequences.*

## Installation
1. Open the `.ino` file in the Arduino IDE.
2. Ensure you have the ESP32 board manager installed.
3. Select your specific ESP32 board model.
4. Allocate a partition scheme that includes SPIFFS (e.g., "Default 4MB with spiffs") to ensure the PCAP files have space to save.
5. Compile and flash via USB.

## Usage
Once the ESP32 is flashed and powered on, it will broadcast its own standalone Wi-Fi network to host the control interface.

1. Open the Wi-Fi settings on your mobile phone or computer.
2. Connect to the network named **Wible-v12.0** *(Note: This is an open network; no password is required).* ::::::::if password asked write *meknowyouright*
3. Open any modern web browser (Chrome, Safari, Firefox).
4. Navigate to the default ESP32 Access Point IP address: `http://192.168.4.1/`
5. The Wible dashboard will load, allowing you to interact with the device.

**Troubleshooting:**
If the browser displays a *"This site can't be reached"* or *"No internet connection"* error:
* **Turn off your Mobile Data (Cellular Data).** Many smartphones automatically route network traffic through your cellular provider if they detect that the connected Wi-Fi network (the ESP32) does not provide internet access. Disabling mobile data forces the phone to load the local ESP32 page.
