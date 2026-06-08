/** CleanBrowsing Family Filter — blocks adult, VPN/proxy, mixed content; enforces SafeSearch. */
const DNS = {
  filter: 'family',
  ipv4: { primary: '185.228.168.168', secondary: '185.228.169.168' },
  ipv6: { primary: '2a0d:2a00:1::', secondary: '2a0d:2a00:2::' },
  dohTemplate: 'https://doh.cleanbrowsing.org/doh/family-filter/',
};

const ALLOWED_IPV4_DNS = new Set([DNS.ipv4.primary, DNS.ipv4.secondary]);
const ALLOWED_IPV6_DNS = new Set([DNS.ipv6.primary, DNS.ipv6.secondary]);

module.exports = { DNS, ALLOWED_IPV4_DNS, ALLOWED_IPV6_DNS };
