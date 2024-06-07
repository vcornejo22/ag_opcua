import asyncio
from asyncua import Client, ua
from asyncua.crypto import security_policies
import os
from itertools import product
from datetime import datetime
import pandas as pd 
import psutil
import time
from dotenv import load_dotenv

load_dotenv()
UA_URL = os.getenv("UA_URL")
UA_URI = os.getenv("UA_URI")
UA_USER = os.getenv("UA_USER")
UA_PASSWORD = os.getenv("UA_PASSWORD")
# UA_CERT="./opcua/certs/cert-prosys.der"
# UA_KEY="./opcua/certs/key-prosys.pem"
# UA_CERT="./opcua"
# UA_KEY="./opcua"

# Rango de nodes a suscribir del servidor UA
nodes_id = [f'ns=3;i={i}' for i in range(1001,1607)] 
nodes_dict = {
    "Constant": "ns=3;i=1001",
    "Counter": "ns=3;i=1002",
    "Random": "ns=3;i=1003",
    "Sawtooth": "ns=3;i=1004",
    "Sinusoid": "ns=3;i=1005",
    "Square": "ns=3;i=1006",
    "Triangle": "ns=3;i=1007",
}
global connection_time
global read_time
TIMEOUT = 300
watchdog_intervall = 2
async def read_process(csv_filename):
    pid = 9165  
    p = psutil.Process(pid)
    df = pd.DataFrame()
    flag = True
    count = 0
    try:
        while count < TIMEOUT + 20:
            # Obtener el uso de CPU como porcentaje
            cpu_usage = p.cpu_percent(interval=0)
            # Obtener el uso de memoria
            memory_info = p.memory_info()
            memory_usage = memory_info.rss  # Resident Set Size
            memory_usage = memory_usage / (1024 * 1024)
            # print(f"Time: {datetime.now()} CPU Usage: {cpu_usage}% - Memory Usage: {memory_usage} MB")
            current_time = datetime.now()
            aux = pd.DataFrame.from_dict([{'timestamp': current_time, 'cpu_usage': cpu_usage, 'memory_usage': memory_usage}])
            if flag:
                df = aux   
                flag = False 
            else:
                df = pd.concat([df, aux])
            await asyncio.sleep(0.2) 
            count += 0.2
            
    except TypeError:
        pass
    finally:
        # Tienes que crear la carpeta dataset
        df.to_csv(f"dataset/{csv_filename}.csv", index=False)
    return datetime.now()

def get_key_by_value(search_value):
    for key, value in nodes_dict.items():
        if value == search_value:
            return key
    return None

class SubHandler(object):
    """
    Subscription Handler. To receive events from server for a subscription
    """
    async def datachange_notification(self, node, val, data):
        # print("Python: New data change event", node, val)
        pass
        # key = get_key_by_value(str(node))

    def event_notification(self, event):
        print("Python: New event", event)

async def connect_ua(UA_CERT, UA_KEY):
    await asyncio.sleep(5)
    init_time = datetime.now().timestamp()
    ua_client = Client(url=UA_URL)
    ua_client.set_user(UA_USER)
    ua_client.set_password(UA_PASSWORD)
    
    # ua_client._watchdog_intervall = 1.0
    # ua_client.secure_channel_timeout = TIMEOUT / 2
    # ua_client.session_timeout = TIMEOUT / 2
    await ua_client.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        certificate=UA_CERT,
        private_key=UA_KEY,
        mode=ua.MessageSecurityMode.SignAndEncrypt
    )
    ua_client.application_uri = UA_URI
    try:
        await ua_client.connect()
        end_time = datetime.now().timestamp()
        connection_time = end_time - init_time
        print(f"Time connection: {end_time - init_time}")
        print("Root children are", await ua_client.nodes.root.get_children())
        
        var_list = [ua_client.get_node(i) for i in range(1001,1607)]
        handler = SubHandler()
        sub = await ua_client.create_subscription(1000, handler)
        handle = await sub.subscribe_data_change(var_list)
        read_time = datetime.now().timestamp() - init_time
        # while True:
        await asyncio.sleep(TIMEOUT)
    except KeyboardInterrupt:
        pass
    finally:
        await ua_client.disconnect()
        
    return connection_time, read_time, datetime.now()

async def main():
    cert_configs = {
        "rsa_bits": [1024, 2048, 3072, 4096],
        "signature_algorithm": ["Sha1", "Sha224", "Sha256", "Sha384", "Sha512"]
    }
    combinations = list(product(cert_configs["rsa_bits"], cert_configs["signature_algorithm"]))
    flag = True
    
    df = pd.DataFrame()
    for combo in combinations:
        print(f"{combo[0]}_{combo[1]}")
        # Tienes que crear la carpeta opcua
        UA_KEY = f"opcua/{combo[0]}_{combo[1]}/{combo[0]}_{combo[1]}_private_key.pem"
        UA_CERT = f"opcua/{combo[0]}_{combo[1]}/{combo[0]}_{combo[1]}_certificate.pem"
        
        rsa = f"{combo[0]}_{combo[1]}"
        result  = await asyncio.gather(connect_ua(UA_CERT, UA_KEY), read_process(rsa))
        print(result)
        c_time, r_time = result[0][0], result[0][1]
        
        aux = pd.DataFrame.from_dict([{'timestamp': datetime.now(),'rsa': rsa, 'connect_time': c_time, 'read_time': r_time}])
        if flag:
            df = aux
            flag = False
        else:
            df = pd.concat([df, aux])
        await asyncio.sleep(60)
    df.to_csv(f"dataset/time_connections.csv", index=False)
        

if __name__ == "__main__":
    asyncio.run(main())