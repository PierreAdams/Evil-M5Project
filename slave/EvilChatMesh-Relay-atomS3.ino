#include <WiFi.h>
#include <esp_now.h>
#include <Arduino.h>
#include <string.h>
#include <M5Unified.h> // Bibliothèque pour M5Stack

#define MAX_HISTORY 32
#define MSG_LEN 100

struct MeshMessage {
    char id[9];       
    char from[16];   
    char body[MSG_LEN];
};

char seenMessageIds[MAX_HISTORY][19];
int seenIndex = 0;

uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

bool hasSeenId(const char* id) {
    for (int i = 0; i < MAX_HISTORY; i++) {
        if (strncmp(seenMessageIds[i], id, 8) == 0) {
            return true;
        }
    }
    return false;
}

void rememberId(const char* id) {
    strncpy(seenMessageIds[seenIndex], id, 8);
    seenMessageIds[seenIndex][8] = '\0';
    seenIndex = (seenIndex + 1) % MAX_HISTORY;
}

uint16_t crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= ((uint16_t)data[i] << 8);
        for (int j = 0; j < 8; j++) {
            crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
        }
    }
    return crc;
}

// Fonction de réception des messages
void onDataRecv(const uint8_t *mac, const uint8_t *incomingData, int len) {
    if (len != sizeof(MeshMessage) + sizeof(uint16_t)) return;

    // Vérifier l'intégrité CRC
    uint16_t receivedCrc;
    memcpy(&receivedCrc, incomingData + sizeof(MeshMessage), sizeof(uint16_t));
    uint16_t computedCrc = crc16(incomingData, sizeof(MeshMessage));
    if (receivedCrc != computedCrc) return;

    // Extraction du message
    MeshMessage msg;
    memcpy(&msg, incomingData, sizeof(MeshMessage));

    if (hasSeenId(msg.id)) return;
    rememberId(msg.id);

    // Relai du message à tous les peers (broadcast)
    esp_now_send(broadcastAddress, incomingData, len);

    // Affichage uniquement si ce n'est pas un PING
    if (strcmp(msg.body, "PING") != 0) {
        Serial.print("Relayed message from ");
        Serial.print(msg.from);
        Serial.print(": ");
        Serial.println(msg.body);

        M5.Lcd.clear();
        M5.Lcd.setCursor(5, 10);
        M5.Lcd.setTextSize(0);
        M5.Lcd.println("== ESP-NOW Relay ==");
        M5.Lcd.printf("From: %s\n\n", msg.from);
        M5.Lcd.printf("Msg: %s\n", msg.body);
    }
}

void setup() {
    M5.begin();            // Initialiser M5Stack
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    // Initialisation ESP-NOW
    if (esp_now_init() != ESP_OK) {
        Serial.println("Erreur lors de l'initialisation d'ESP-NOW");
        return;
    }

    // Enregistrement des callbacks
    esp_now_register_recv_cb(onDataRecv);
    
    // Ajouter le peer de broadcast
    esp_now_peer_info_t peerInfo = {};
    memcpy(peerInfo.peer_addr, broadcastAddress, 6);
    peerInfo.channel = 1;  // Canal par défaut
    peerInfo.encrypt = false;
    if (!esp_now_is_peer_exist(peerInfo.peer_addr)) {
        if (esp_now_add_peer(&peerInfo) != ESP_OK) {
            Serial.println("Erreur lors de l'ajout du peer broadcast");
        }
    }

    // Affichage initial sur M5Stack
    M5.Lcd.setTextSize(0);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("ESP-NOW Relay Ready");
}

void loop() {
    // Mise à jour de M5Stack
    M5.update();
    delay(10);  // Délai de mise à jour
}
