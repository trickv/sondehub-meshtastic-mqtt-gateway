import base64
import paho.mqtt.client as mqtt
import traceback
#from meshtastic import mesh_pb2  # Meshtastic's protobuf schema

from meshtastic.protobuf.mqtt_pb2 import ServiceEnvelope
from meshtastic.protobuf.mesh_pb2 import MeshPacket, Data, HardwareModel
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # whoa make sure that guy's code is GPL or something yo
import os
import sys
import base64

#MQTT_BROKER = "mqtt.meshtastic.org"
MQTT_BROKER = "litecoin"
#TOPIC = "msh/US/2/e/LongFast/!1fa06c00"
TOPIC = "msh/#"

def on_connect(client, userdata, flags, rc):
    print("Connected with result code", rc)
    client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    try:
        print(f"\n--- New Message ---\nTopic: {msg.topic}")
        print("raw msg:")
        print(msg.payload)
        print("end raw msg")
        envelope = ServiceEnvelope()
        envelope.ParseFromString(msg.payload)
        packet: MeshPacket = envelope.packet
        mesh_packet=packet
        key_bytes = base64.b64decode('1PG7OiApB1nwvP+rz05pAQ=='.encode('ascii'))
        nonce_packet_id = getattr(mesh_packet, "id").to_bytes(8, "little")
        nonce_from_node = getattr(mesh_packet, "from").to_bytes(8, "little")
        nonce = nonce_packet_id + nonce_from_node
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(mesh_packet, "encrypted")) + decryptor.finalize()
        data = Data()
        data.ParseFromString(decrypted_bytes)
        print(data)
        mesh_packet.decoded.CopyFrom(data)

        print(mesh_packet)

    except Exception as e:
#           print("Error decoding message:", e, file=sys.stderr)
        print(traceback.format_exc())

client = mqtt.Client(client_id="live-decoder2")
client.username_pw_set("meshdev", "large4cats")
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, 1883, 60)
client.loop_forever()
