/**
 * Type definitions mirror electron/services/dns (canonical runtime implementation).
 */
export type DnsStatus =
  | 'HEALTHY'
  | 'FILTERING_INACTIVE'
  | 'CLEANBROWSING_UNREACHABLE'
  | 'NETWORK_ERROR'
  | 'TAMPERING_SUSPECTED';

export interface DnsAuditEvent {
  timestamp: string;
  networkName: string;
  status: DnsStatus;
  details: string;
  meta?: Record<string, unknown>;
}

export interface DnsHealthReport {
  timestamp: number;
  status: DnsStatus;
  healthy: boolean;
  details: string;
  networkName: string;
}
