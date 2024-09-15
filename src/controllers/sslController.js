const SslChecker = require('ssl-checker');
const { validateSslRequest } = require('../validators/sslValidator');
const forge = require('node-forge');
const { URL } = require('url');
const tls = require('tls');
const { getCertStatus } = require('easy-ocsp');


const getSslInfo = async (req, res) => {
    const { error } = validateSslRequest(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
      }

  
  const isRevoked = async (certPem) => {
    try {
      // Parse the certificate using forge
      const ocspResult = await getCertStatus(certPem);
      const { status }= ocspResult
    return status === 'good'? 'Not Revoked': 'Revoked'
    } catch (error) {
      console.error('Error checking revocation:', error.message || error);
    
    // Handle specific error for expired certificates
    if (error.message && error.message.includes('The certificate is already expired')) {
      return 'Certificate already expired';
    }

    // For other errors, return a generic message
    return 'Error checking revocation';
    }
  };
  


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
                  revoked: revoked, // crl_ocsp status
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
