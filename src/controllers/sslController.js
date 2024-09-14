const SslChecker = require('ssl-checker');
const { validateSslRequest } = require('../validators/sslValidator');
const forge = require('node-forge');
const { URL } = require('url');
const tls = require('tls');
const axios = require('axios')


const getSslInfo = async (req, res) => {
    const { error } = validateSslRequest(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
      }
  const extractCrlUrl = (cert) => {
    const crlDistributionPoints = cert.extensions.find(ext => ext.id === '2.5.29.37');
    
    if (!crlDistributionPoints) {
      console.log('No CRL Distribution Points found');
      return null;
    }
  
    // Extract CRL URLs from the distribution points
    const crlUrls = crlDistributionPoints.value
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.startsWith('URI:'))
      .map(line => line.substring(4)); // Remove 'URI:' prefix
  
    return crlUrls.length ? crlUrls[0] : null; // Return the first CRL URL if available
  };
  
  const isRevoked = async (certPem) => {
    try {
      // Parse the certificate using forge
      const cert = forge.pki.certificateFromPem(certPem);
  
      // Extract the CRL URL from the certificate's CRL Distribution Points (2.5.29.31)
      let crlUrl = extractCrlUrl(cert);
  
      // If no CRL URL is found, return "Unknown"
      if (!crlUrl) {
        return 'Unknown'; // No CRL URL provided
      }
  
      // Ensure URL has the correct protocol (default to HTTPS)
      crlUrl = crlUrl.startsWith('http') ? crlUrl : `https://${crlUrl}`;
  
      // Fetch the CRL data from the extracted CRL URL
      const response = await axios.get(crlUrl, { responseType: 'arraybuffer' });
      const crl = forge.pki.crl.fromAsn1(forge.asn1.fromDer(response.data.toString('binary')));
  
      // Compare serial numbers of revoked certificates with the provided certificate's serial number
      const certRevoked = crl.revokedCerts.some(revokedCert => 
        revokedCert.serialNumber === cert.serialNumber
      );
  
      return certRevoked ? 'Revoked' : 'Not Revoked';
    } catch (error) {
      console.error('Error checking revocation:', error.message || error);
      return 'Unknown';
    }
  };
  


  function getCrlUrls(cert) {
    const crlUrls = [];
    const extensions = cert.extensions;
  
    for (let ext of extensions) {
      if (ext.name === 'crlDistributionPoints') {
        for (let dp of ext.crlDistributionPoints) {
          crlUrls.push(dp.uri);
        }
      }
    }
    
    return crlUrls;
  }
  const getSslDetails = async (domain) => {
    return new Promise((resolve, reject) => {
      try {
        // Create a TLS connection to retrieve the certificate
        const url = new URL(`https://${domain}`);
        const port = url.port || 443;
        const options = {
            host: domain,
            port: port,
            rejectUnauthorized: false, // Disable validation for testing purposes
          };
        const socket = tls.connect(options, () => {
          const cert = socket.getPeerCertificate(true);
  
          if (cert.raw) {
            // Parse the certificate using node-forge
            const certificate = forge.pki.certificateFromAsn1(
              forge.asn1.fromDer(Buffer.from(cert.raw).toString('binary'))
            );
            const certPem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(cert.raw.toString('binary'))));
            const parsedCert = forge.pki.certificateFromPem(certPem);
           const crlUrls = getCrlUrls(parsedCert);
  
            // Extract SSL certificate details
            const caValidity = certificate.issuer.attributes.some(attr => attr.shortName === 'CN' && attr.value === certificate.subject.getField('CN').value) ? 'Invalid' : 'Valid'; // Simplified         

            isRevoked(certPem)
              .then(revoked => {
                const details = {
                  validity: {
                    valid: certificate.validity.notBefore <= new Date() && certificate.validity.notAfter >= new Date() ? 'Valid' : 'Invalid',
                    validFrom: certificate.validity.notBefore.toISOString(),
                    validTo: certificate.validity.notAfter.toISOString(),
                  },
                  issuer: certificate.issuer.attributes.map(attr => `${attr.shortName}: ${attr.value}`).join(', '),
                  subject: certificate.subject.attributes.map(attr => `${attr.shortName}: ${attr.value}`).join(', '),
                  validForDomain: certificate.subject.getField('CN').value === domain ? 'Yes' : 'No',
                  caValid: caValidity,
                  selfSigned: certificate.issuer.attributes.some(attr => attr.shortName === 'CN' && attr.value === certificate.subject.getField('CN').value) ? 'Yes' : 'No',
                  revoked: revoked,
                  daysRemaining: Math.floor((certificate.validity.notAfter - new Date()) / (1000 * 60 * 60 * 24)) // Days remaining until expiration
                };
  
                // Close the socket
                socket.end();
                
                resolve(details);
              })
              .catch(err => {
                reject(new Error(`Error checking revocation: ${err.message}`));
              });
          } else {
            reject(new Error('No certificate found'));
          }
        });
  
        // Handle socket errors
        socket.on('error', (err) => {
          reject(new Error(`Socket error: ${err.message}`));
        });
  
      } catch (error) {
        reject(new Error(`Error fetching SSL details: ${error.message}`));
      }
    });
  };

 

  const { domain } = req.body;

  try {
    const sslInfo = await getSslDetails(domain);
    
    res.json(sslInfo);
  } catch (err) {
    res.status(500).send(`Error: ${err.message}`);
  }

};


module.exports = {
  getSslInfo,
};
