import base64
import paho.mqtt.client as mqtt
import traceback
import threading
import datetime
#from meshtastic import mesh_pb2  # Meshtastic's protobuf schema

from meshtastic.protobuf.mqtt_pb2 import ServiceEnvelope
from meshtastic.protobuf.mesh_pb2 import MeshPacket, Data, HardwareModel, Position, User
from meshtastic.protobuf.telemetry_pb2 import Telemetry
from meshtastic.protobuf.portnums_pb2 import PortNum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # whoa make sure that guy's code is GPL or something yo
import os
import sys
import base64

from sondehub.amateur import Uploader

MQTT_BROKER = "mqtt.meshtastic.org"
#MQTT_BROKER = "litecoin"
#TOPIC = "msh/US/2/e/LongFast/!1fa06c00"
TOPIC = "msh/US/#"
BALLOON_USER_IDS = (131047185, 530607104)

uploader = Uploader("KD9PRC Meshtastic MQTT gateway", software_name="KD9PRC Mestastic MQTT gateway", software_version="0.0.1")

nodeinfo_db = {}
nodeinfo_db_lock = threading.Lock()
node_position_db = {}
node_position_db_lock = threading.Lock()

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
        mesh_packet.decoded.CopyFrom(data)

        print("mesh_packet:")
        print(mesh_packet)
        print()
        print(repr(mesh_packet.decoded))
        portnum = mesh_packet.decoded.portnum
        payload = mesh_packet.decoded.payload
        from_user = int(getattr(mesh_packet, "from"))
        if portnum == PortNum.POSITION_APP:
            print("== POSITION_APP protobuf: ==")
            position = Position()
            position.ParseFromString(payload)
            print(position)
            
            with node_position_db_lock:
                node_position_db[from_user] = position

            if from_user in nodeinfo_db:
                with nodeinfo_db_lock:
                    user = nodeinfo_db[from_user]
                print(f"lat/lon from {from_user}: id {user.id} long {user.long_name} lat {position.latitude_i} lon {position.longitude_i} alt {position.altitude}")
                if from_user in BALLOON_USER_IDS:
                    print("This is a balloon! put it to sondehub!")
                    print("Receiver information:")
                    receiver_id_hex = msg.topic.split("/")[-1]
                    receiver_id_number = int(receiver_id_hex[1:], 16)
                    latitude = position.latitude_i / 1e7
                    longitude = position.longitude_i / 1e7
                    uploader_position = [None,None,None]
                    if receiver_id_number in node_position_db:
                        with node_position_db_lock:
                            uploader_position = [
                                node_position_db[receiver_id_number].latitude_i / 1e7,
                                node_position_db[receiver_id_number].longitude_i / 1e7,
                                node_position_db[receiver_id_number].altitude
                                ]
                    if receiver_id_number in nodeinfo_db:
                        callsign = f"{receiver_id_hex} {nodeinfo_db[receiver_id_number].long_name}"
                    else:
                        callsign = receiver_id_hex
                    print(f"Receiver info: {receiver_id_hex} {uploader_position}")
                    #33int(f"Uploader info: {user.long_name}, pos: {uploader_position}")
                    uploader.add_telemetry(
                        user.long_name,
                        datetime.datetime.fromtimestamp(position.time),
                        latitude,
                        longitude,
                        position.altitude,
                        modulation="Meshtastic",
                        uploader_callsign=callsign,
                        )
                    uploader.upload_station_position(
                        callsign,
                        uploader_position,
                        uploader_radio="KD9PRC Meshtastic MQTT gateway",
                        )
                    print("uploaded")
            else:
                print(f"Not in nodeinfo_db: {from_user}")

        elif portnum == PortNum.TELEMETRY_APP:
            print("== TELEMETRY_APP protobuf: ==")
            telemetry = Telemetry()
            telemetry.ParseFromString(payload)
            print(telemetry)
        elif portnum == PortNum.NODEINFO_APP:
            print("== NODEINFO_APP protobuf: ==")
            user = User()
            user.ParseFromString(payload)
            print(user)
            with nodeinfo_db_lock:
                nodeinfo_db[from_user] = user

        print(f"In-memory DBs: nodeinfo {len(nodeinfo_db)} position {len(node_position_db)}")

            

    except Exception as e:
#           print("Error decoding message:", e, file=sys.stderr)
        print(traceback.format_exc())

client = mqtt.Client(client_id="live-decoder2")
client.username_pw_set("meshdev", "large4cats")
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, 1883, 60)
client.loop_forever()
