/** @typedef {'HEALTHY' | 'HEALTHY_WITH_PROVIDER_MISSES' | 'DEGRADED' | 'FILTERING_INACTIVE' | 'CLEANBROWSING_UNREACHABLE' | 'NETWORK_ERROR' | 'TAMPERING_SUSPECTED' | 'FAILED'} DnsStatus */



const DnsStatus = {

  HEALTHY: 'HEALTHY',

  HEALTHY_WITH_PROVIDER_MISSES: 'HEALTHY_WITH_PROVIDER_MISSES',

  DEGRADED: 'DEGRADED',

  FAILED: 'FAILED',

  FILTERING_INACTIVE: 'FILTERING_INACTIVE',

  CLEANBROWSING_UNREACHABLE: 'CLEANBROWSING_UNREACHABLE',

  NETWORK_ERROR: 'NETWORK_ERROR',

  TAMPERING_SUSPECTED: 'TAMPERING_SUSPECTED',

};



const FINAL_STATUS_TO_DNS = {

  healthy: DnsStatus.HEALTHY,

  healthy_with_provider_misses: DnsStatus.HEALTHY_WITH_PROVIDER_MISSES,

  degraded: DnsStatus.DEGRADED,

  failed: DnsStatus.FAILED,

};



const ACTIVE_STATUSES = new Set([

  DnsStatus.HEALTHY,

  DnsStatus.HEALTHY_WITH_PROVIDER_MISSES,

  DnsStatus.DEGRADED,

]);



const RESTORE_STATUSES = new Set([

  DnsStatus.FILTERING_INACTIVE,

  DnsStatus.TAMPERING_SUSPECTED,

  DnsStatus.FAILED,

  DnsStatus.CLEANBROWSING_UNREACHABLE,

]);



function mapFinalStatusToDnsStatus(finalStatus) {

  return FINAL_STATUS_TO_DNS[finalStatus] || DnsStatus.FAILED;

}



function isProtectionActive(status) {

  return ACTIVE_STATUSES.has(status);

}



function isProtectionWithWarnings(status) {

  return (

    status === DnsStatus.HEALTHY_WITH_PROVIDER_MISSES || status === DnsStatus.DEGRADED

  );

}



function shouldAttemptRestore(status) {

  return RESTORE_STATUSES.has(status);

}



function protectionLabelFromStatus(status, warnings = []) {

  if (status === DnsStatus.HEALTHY && warnings.length === 0) return 'Protected';

  if (isProtectionActive(status)) return 'Protected with warnings';

  return 'Not protected';

}



module.exports = {

  DnsStatus,

  mapFinalStatusToDnsStatus,

  isProtectionActive,

  isProtectionWithWarnings,

  shouldAttemptRestore,

  protectionLabelFromStatus,

};

