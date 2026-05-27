import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export async function runLocalNetworkSweep(targetIp) {
  try {
    const target = targetIp || '192.168.1.1/24';
    const { stdout } = await execAsync(`python ../ml_service/real_wifi_scanner.py -t ${target}`);
    
    // Parse the output from real_wifi_scanner.py
    const lines = stdout.split('\n');
    const devices = [];
    let parsing = false;
    
    for (const line of lines) {
      if (line.includes('IP Address') && line.includes('MAC')) {
        parsing = true;
        continue;
      }
      if (parsing && line.includes('=')) continue; // skip borders
      if (parsing && line.includes('-')) continue; // skip separators
      if (parsing && line.includes('Total')) break;
      if (parsing && line.includes('No devices')) continue; // skip 'No devices found' message
      if (parsing && line.trim()) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          devices.push({
            ip: parts[0],
            mac: parts[1],
            type: 'Live Device',
          });
        }
      }
    }
    
    return devices;
  } catch (error) {
    console.error('Network sweep failed:', error.message);
    return [];
  }
}

export async function runLiveNetworkSniffer() {
  try {
    const { stdout } = await execAsync(`python ../ml_service/real_network_sniffer.py -c 5`);
    const lines = stdout.split('\n');
    const packets = [];
    
    for (const line of lines) {
      if (line.includes('Packet:')) {
        packets.push(line.trim());
      }
    }
    
    return packets;
  } catch (error) {
    console.error('Network sniff failed:', error.message);
    return [];
  }
}
