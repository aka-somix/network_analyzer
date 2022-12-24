import { Device } from "../models/network";
import { invoke } from '@tauri-apps/api/tauri'

export class TauriAPI {
  static async getAllDevices (): Promise<Device[]> {
    // const devicesFromBE = invoke('get_all_devices');

    // TODO This is a mock. Replace with real data
    const fakeDevices = [
      {
        name: 'Device 1',
        ipv4Address: "10.10.0.1",
        netmask: "255.255.255.0",
      },
      {
        name: 'Device 2',
        ipv4Address: "10.10.0.2",
        netmask: "255.255.255.0",
      },
      {
        name: 'Device 3',
        ipv4Address: "10.10.0.2",
        netmask: "255.255.255.0",
      }
    ];
    
    return [];
  }
} 