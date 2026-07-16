Files:
1. sensor_pipeline.py            -> victim
2. dvwa_traffic_remote.py     -> attacker
3. config.json                      -> victim

Move config.json into the NTLFlowLyzer directory:
mv config.json NTLFlowLyzer/

install(in server):
1. DVWA
2. NTLFlowLyzer
git clone https://github.com/ahlashkari/NTLFlowLyzer

modify sensor_pipeline.py:
INTERFACE = "ens33"
UPLOAD_URL = "http://IP:5000/upload"

start capture / upload:
sudo python3 sensor_pipeline.py <server_ip>

start attack:
sudo python3 dvwa_traffic_remote.py <server_ip> <server_ip> all

example:
sudo python3 sensor_pipeline.py 192.168.0.30
sudo python3 dvwa_traffic_remote.py 192.168.0.30 192.168.0.30 all