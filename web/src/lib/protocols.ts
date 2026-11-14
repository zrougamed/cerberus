/** Display names for the industrial protocol keys used by the API. */
export const protocolNames: Record<string, string> = {
  modbus: 'Modbus/TCP',
  s7comm: 'S7comm',
  s7comm_plus: 'S7comm-plus',
  dnp3: 'DNP3',
  enip: 'EtherNet/IP',
  bacnet: 'BACnet/IP',
  iec104: 'IEC 60870-5-104',
  opcua: 'OPC UA',
  mqtt: 'MQTT',
}
