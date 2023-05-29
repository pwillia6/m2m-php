<?php

require_once 'SoapHelper.php';
require_once 'AUSKey.php';

/*
 * This file contains the code neccessary to perform a USI validation.
 *
 * If you want to do other USI operations your are on your own.  
 */
class VanguardClient extends SoapHelper
{
    const ACTION_ISSUE = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue';
    const ACTION_ISSUE_VERIFY = 'http://usi.gov.au/2022/ws/VerifyUSI';

    const USIRUL_PROD = 'https://portal.usi.gov.au/service/v5/usiservice.svc';
    const VANURL_PROD = 'https://softwareauthorisations.ato.gov.au/R3.0/S007v1.3/service.svc';

    const USIRUL_TEST = 'https://3pt.https://portal.usi.gov.au/service/v5/usiservice.svc';
    const VANURL_TEST = 'https://softwareauthorisations.acc.ato.gov.au/R3.0/S007v1.3/service.svc';

    private $auskey;
    private $atoUrl;
    private $usiUrl;
    private $orgCode;
    private $usi;
    private $first;
    private $family;
    private $dob;

    public function __construct($env /* PROD or TEST */, $auskey, 
                                $password /* for auskey */, 
                                $auskey_id /* auskey identity from key file */,
                                $dump_path = null /* path to dump XML from requests */)
    {
        parent::__construct();
        $this->atoUrl = $env=='PROD' ? self::VANURL_PROD : self::VANURL_TEST;
        $this->usiUrl = $env=='PROD' ? self::USIRUL_PROD : self::USIRUL_TEST;

        $this->loadAuskey($auskey, $password, $auskey_id);
        $this->dumpPath = $dump_path;
    }

    public function expireDate() {
        $cred = $this->auskey->getCredential();
        $expires = "$cred->notAfter";
        return $expires;
    }

    public function hasExpired() {

	$expires = $this->expireDate();
        
        $now = new DateTime();
        $now->setTimezone(new DateTimeZone('UTC'));
        $now = $now->format('c');
        
        return $now > $expires;
    }

    /* Dump contents of doc to file */
    private function debug($name) {
        if (!empty($this->dumpPath)) {
            $this->doc->save($this->dumpPath .  '/' . $name, FILE_APPEND);
        }
    }

    /**
     * @param $url to get token for
     * @return mixed
     * @throws Exception
     */
    public function requestToken()
    {
        try {
            $xml = $this->buildRSTdocument();
        } catch (Exception $ex) {
            throw $ex;
        }
        try {
            $response = $this->sendSoapRequest(self::ACTION_ISSUE, $xml, $this->atoUrl);
        } catch (Exception $ex) {
            throw $ex;
        }

        try {
            $response = $this->checkForFault($response);
        } catch (Exception $ex) {
            throw $ex;
        }

        return $response;
    }

    public function verifyUSI($orgCode, $usi, $first, $family, $dob)
    {
        /* The original version had this in the constructor */
        $this->orgCode = $orgCode;
        $this->usi = $usi;
        $this->first = $first;
        $this->family = $family;
        $this->dob = $dob;

        $tokenResponse = $this->requestToken();
        try {
            $xmlRequest = $this->buildVerifyRequest($tokenResponse);
        } catch (Exception $ex) {
            throw $ex;
        }

        try {
            $response = $this->sendSoapRequest(self::ACTION_ISSUE_VERIFY, $xmlRequest, $this->usiUrl);
        } catch (Exception $ex) {
            throw $ex;
        }

        try {
            $response = $this->checkForFault($response);
        } catch (Exception $ex) {
            throw $ex;
        }

        $xml = new SimpleXMLElement($response); //, 0, FALSE, 'http://usi.gov.au/2022/ws');
        $xml->registerXPathNamespace("ws", "http://usi.gov.au/2022/ws");
        $response = $xml->xpath("//ws:VerifyUSIResponse")[0];

        /* Convert result into an array instead of simpleXMLElement */
        $output = array();
        foreach ($response as $name => $value) {
            $output[$name] = "$value";
        }

        return $output;
    }

    private function buildRSTdocument()
    {
        $envelope = $this->doc->createElementNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':Envelope');

        $this->doc->appendChild($envelope);

        try {
            $header = $this->buildSoapHeader();
        } catch (Exception $ex) {
            throw $ex;
        }

        $envelope->appendChild($header);
        $envelope->appendChild($this->buildSoapBody($this->usiUrl));

        $xml = $this->doc->saveXML();
        $this->debug('request.xml');

        return $this->canonicalize($xml);
    }

    private function buildVerifyRequest($rawMASResp)
    {
        $this->doc = new DOMDocument('1.0', 'UTF-8');

        $envelope = $this->doc->createElementNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':Envelope');

        $this->doc->appendChild($envelope);

        try {
            $header = $this->buildSoapHeader($rawMASResp);
        } catch (Exception $ex) {
            throw $ex;
        }

        $envelope->appendChild($header);
        $envelope->appendChild($this->buildSoapBodyUSI());

        $xml = $this->doc->saveXML();
        $this->debug('request-usi.xml');

        return $this->canonicalize($xml);
    }

    private function buildSoapHeader($rawMASResp = null)
    {
        $header = $this->doc->createElementNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':Header');

        if ($rawMASResp) {
            $action = $this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':Action', self::ACTION_ISSUE_VERIFY);
            $url = $this->usiUrl;
        } else {
            $action = $this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':Action', self::ACTION_ISSUE);
            $url = $this->atoUrl;
        }
        $action->setAttributeNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':mustUnderstand', 1);
        $header->appendChild($action);

        $header->appendChild($this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':MessageID', $this->message_id));

        $replyto = $this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':ReplyTo');
        $replyto->appendChild($this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':Address', 'http://www.w3.org/2005/08/addressing/anonymous'));
        $header->appendChild($replyto);

        $header->appendChild($this->buildTo($url));

        try {
            $sh = $this->buildSecurityHeader($rawMASResp);
        } catch (Exception $ex) {
            throw $ex;
        }
        $header->appendChild($sh);

        return $header;
    }

    private function buildSecurityHeader($rawMASResp = null)
    {
        $s = $this->doc->createElementNS(self::NS_SEC, self::NS_SEC_PREFIX . ':Security');
        $s->setAttributeNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':mustUnderstand', 1);

        $s->appendChild($this->buildTimestampHeader());

        $signature = null;
        if ($rawMASResp) {
            try {
                $dom = new DOMDocument();
                $dom->loadXML($rawMASResp);
                $encryptedData = $dom->getElementsByTagName('EncryptedData')->item(0);
                $s->appendChild($this->doc->importNode($encryptedData, true));
                $signature = $this->buildSignatureUSI($rawMASResp);

            } catch (Exception $exception) {
                echo $exception->getMessage();
            }
        } else {
            $bst = $this->doc->createElementNS(self::NS_SEC, self::NS_SEC_PREFIX . ':BinarySecurityToken', $this->getBinarySecurityToken());
            $bst->setAttributeNS(self::NS_WSU, self::NS_WSU_PREFIX . ':Id', $this->token_id);
            $bst->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
            $bst->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary');
            $s->appendChild($bst);
            try {
                $signature = $this->buildSignature();
            } catch (Exception $e) {
                echo $e->getMessage();
            }
        }
        $s->appendChild($signature);
        return $s;
    }

    private function buildSoapBody($url)
    {
        $body = $this->doc->createElementNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':Body');

        $rst = $this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':RequestSecurityToken');
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':RequestType', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'));
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':TokenType', 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1'));

        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':KeyType', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey'));
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':KeySize', '256'));

        $clms = $this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':Claims');
        $clms->setAttribute('Dialect', 'http://schemas.xmlsoap.org/ws/2005/05/identity');
        $clms->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:i', 'http://schemas.xmlsoap.org/ws/2005/05/identity');


        $clm = $this->doc->createElementNS('http://schemas.xmlsoap.org/ws/2005/05/identity', 'i:ClaimType');
        $clm->setAttribute('Uri', 'http://vanguard.ebusiness.gov.au/2008/06/identity/claims/abn');
        $clms->appendChild($clm);

        $clm = $this->doc->createElementNS('http://schemas.xmlsoap.org/ws/2005/05/identity', 'i:ClaimType');
        $clm->setAttribute('Uri', 'http://vanguard.ebusiness.gov.au/2008/06/identity/claims/credentialtype');
        $clms->appendChild($clm);

        $rst->appendChild($clms);

        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':KeyWrapAlgorithm', 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'));
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':EncryptWith', 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'));
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':SignWith', 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'));
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':CanonicalizationAlgorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#'));
        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':EncryptionAlgorithm', 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'));

        $appliesto = $this->doc->createElementNS(self::NS_WSP, self::NS_WSP_PREFIX . ':AppliesTo');
        $epr = $this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':EndpointReference');
        $epr->appendChild($this->doc->createElementNS(self::NS_ADDR, self::NS_ADDR_PREFIX . ':Address', $url));
        $appliesto->appendChild($epr);

        $rst->appendChild($appliesto);

        $rst->appendChild($this->doc->createElementNS(self::NS_WST, self::NS_WST_PREFIX . ':ComputedKeyAlgorithm', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1'));

        $body->appendChild($rst);

        return $body;
    }

    private function buildSoapBodyUSI()
    {
        $body = $this->doc->createElementNS(self::NS_SOAP, self::NS_SOAP_PREFIX . ':Body');

        $verifyUSI = $this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':VerifyUSI');
        $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':OrgCode', $this->orgCode));
        $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':USI', $this->usi));
        if (empty($this->family)) {
            $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':SingleName', $this->first));
        } elseif (empty($this->first)) {
            $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':SingleName', $this->family));
        } else {
            $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':FirstName', $this->first));
            $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':FamilyName', $this->family));
        }

        $verifyUSI->appendChild($this->doc->createElementNS(self::NS_USI, self::NS_USI_PREFIX . ':DateOfBirth', $this->dob));

        $body->appendChild($verifyUSI);

        return $body;
    }

    public function loadAuskey($path, $password = '', $id)
    {
        if (!file_exists($path)) {
            throw new Exception("AUSKey not found at the path specified in Settings.");
        }

        $xml = file_get_contents($path);
        try {
            $this->setAuskey($xml, $password, $id);
        } catch (Exception $ex) {
            throw $ex;
        }
    }

    public function setAuskey($xml, $password = '', $id)
    {
        try {
            $this->auskey = new AUSKey($xml, $password, $id);
        } catch (Exception $ex) {
            throw $ex;
        }
    }

    /**
     * @returns AUSKey
     */
    public function getAuskey()
    {
        return $this->auskey;
    }

    private function buildSignature()
    {
        $signedinfo = $this->buildSignedInfo();
//        $signedinfo = $this->buildSignedInfoSha1();

        try {
            $signature = $this->getSignatureHash($signedinfo);
        } catch (Exception $ex) {
            throw $ex;
        }

        $s = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Signature');

        $s->appendChild($signedinfo);

        $sv = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':SignatureValue', $signature);
        $s->appendChild($sv);

        $keyinfo = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':KeyInfo');
        $str = $this->doc->createElementNS(self::NS_SEC, self::NS_SEC_PREFIX . ':SecurityTokenReference');
        $ref = $this->doc->createElementNS(self::NS_SEC, self::NS_SEC_PREFIX . ':Reference');
        $ref->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $ref->setAttribute('URI', '#' . $this->token_id);
        $str->appendChild($ref);
        $keyinfo->appendChild($str);
        $s->appendChild($keyinfo);

        return $s;
    }

    private function buildSignatureUSI($rawMASResp)
    {
        $signedinfo = $this->buildSignedInfoUSI();
        $dom = new DOMDocument();
        $dom->loadXML($rawMASResp);

        try {
            $binarySecret = $dom->getElementsByTagName('BinarySecret')->item(0);
            $signature = $this->getSignatureHmacSha1($signedinfo, base64_decode($binarySecret->nodeValue));
        } catch (Exception $ex) {
            throw $ex;
        }

        $s = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Signature');
        $s->appendChild($signedinfo);

        $sv = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':SignatureValue', $signature);
        $s->appendChild($sv);

        $keyInfo = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':KeyInfo');

        $securityTokenRef = $dom->getElementsByTagName('SecurityTokenReference')->item(1);
        $tokenRef = $this->doc->importNode($securityTokenRef, true);
        $keyInfo->appendChild($tokenRef);
        $s->appendChild($keyInfo);

        return $s;
    }

    private function buildSignedInfo()
    {
        $this->buf1 = $this->doc->saveXML($this->buildTimestampHeader());
        $this->cbuf1 = $this->canonicalize($this->buf1);
        $this->hbuf1 = hash('sha256', $this->cbuf1, true);
        $this->digest1 = base64_encode($this->hbuf1);

        $this->buf2 = $this->doc->saveXML($this->buildTo($this->atoUrl));
        $this->cbuf2 = $this->canonicalize($this->buf2);
        $this->hbuf2 = hash('sha256', $this->cbuf2, true);
        $this->digest2 = base64_encode($this->hbuf2);

        $buf = $this->doc->saveXML($this->buildTimestampHeader());
        $digest1 = base64_encode(hash('sha256', $this->canonicalize($buf), true));

        $buf = $this->doc->saveXML($this->buildTo($this->atoUrl));
        $digest2 = base64_encode(hash('sha256', $this->canonicalize($buf), true));

        $si = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':SignedInfo');

        $cm = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':CanonicalizationMethod');
        $cm->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $si->appendChild($cm);

        $sm = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':SignatureMethod');
        $sm->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        $si->appendChild($sm);

        $transforms = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Transforms');
        $transform = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Transform');
        $transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $transforms->appendChild($transform);
        $digestmethod = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':DigestMethod');
        $digestmethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');

        $digestvalue = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':DigestValue', $digest1);
        $ref1 = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Reference');
        $ref1->setAttribute('URI', '#_0');
        $ref1->appendChild($transforms);
        $ref1->appendChild($digestmethod);
        $ref1->appendChild($digestvalue);
        $si->appendChild($ref1);

        $transforms = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Transforms');
        $transform = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Transform');
        $transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $transforms->appendChild($transform);
        $digestmethod = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':DigestMethod');
        $digestmethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');

        $digestvalue = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':DigestValue', $digest2);
        $ref2 = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Reference');
        $ref2->setAttribute('URI', '#_1');
        $ref2->appendChild($transforms);
        $ref2->appendChild($digestmethod);
        $ref2->appendChild($digestvalue);

        return $si;
    }


    private function buildSignedInfoUSI()
    {
        $buf = $this->doc->saveXML($this->buildTimestampHeader());
        $digest1 = base64_encode(hash('sha1', $this->canonicalize($buf), true));

        $si = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':SignedInfo');

        $cm = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':CanonicalizationMethod');
        $cm->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $si->appendChild($cm);

        $sm = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':SignatureMethod');
        $sm->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#hmac-sha1');
        $si->appendChild($sm);

        $transforms = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Transforms');
        $transform = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Transform');
        $transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $transforms->appendChild($transform);
        $digestMethod = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');

        $digestvalue = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':DigestValue', $digest1);
        $ref1 = $this->doc->createElementNS(self::NS_SIGN, self::NS_SIGN_PREFIX . ':Reference');
        $ref1->setAttribute('URI', '#_0');
        $ref1->appendChild($transforms);
        $ref1->appendChild($digestMethod);
        $ref1->appendChild($digestvalue);
        $si->appendChild($ref1);

        return $si;
    }


    private function checkForFault(&$response)
    {
        try {
            $xml = new SimpleXMLElement($response);
        } catch (Exception $ex) {
            throw $ex;
        }

        $ns = $xml->getNamespaces(true);
        if (isset($ns['soap'])) {
            $soap = $xml->children($ns['soap']);
    
            if (!empty($soap->Body->Fault)) {
                $fault = $soap->Body->Fault->children($ns['soap']);
                throw new Exception(reset($fault->Reason->Text));
            }
        }

        return $response;
    }

    private function getBinarySecurityToken()
    {
        /* An insanely barbaric way to get a public cert out of PKCS7 chain
         * which we have inside an AUSkey file.
         * Apparently, you can't do it any other way with native PHP functions!
         *
         * NOTE: PHP7 has a supported function
         */

        // First, we have to dump PKCS7 "publicCertificate" part into a temp file.
        $certIn = "-----BEGIN PKCS7-----\n";
        $certIn .= $this->getAuskey()->getCredential()->publicCertificate . "\n";
        $certIn .= "-----END PKCS7-----";
        
        $descriptorspec = array(
           0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
           1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
           2 => array("file", "/dev/null", "w") // stderr is a file to write to
        );
        
        $cwd = '/tmp';
        $env = array();
        $process = proc_open('openssl pkcs7 -print_certs', $descriptorspec, $pipes, $cwd, $env);
        
        if (is_resource($process)) {
            fwrite($pipes[0], $certIn);
            fclose($pipes[0]);
        
            $certs = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
        
            // It is important that you close any pipes before calling
            // proc_close in order to avoid a deadlock
            $return_value = proc_close($process);
        }
        
        if (empty($certs)) {
            return null;
        }

        // Then we parse the response (should be 3 PEM certs there).
        $matches = null;
        preg_match_all('/-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----/mUs', $certs, $matches);
        if (empty($matches)) {
            return null;
        }

        /* We have 3 certs here:
         *
         * 1) Signature Algorithm: sha1WithRSAEncryption
         * 2) Signature Algorithm: sha256WithRSAEncryption
         * 3) Signature Algorithm: sha512WithRSAEncryption
         *
         * We need the first one (index 0 in $matches[1]).
         * Clean it up and return.
         */

        $search = array("\n", "\r",);
        $bst = str_replace($search, '', $matches[1][0]);

        return $bst;
    }

    public function getPrivateKeyPEM()
    {
        $key = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
        $key .= $this->getAuskey()->getCredential()->protectedPrivateKey . "\n";
        $key .= "-----END ENCRYPTED PRIVATE KEY-----";

        return $key;
    }

    private function getSignatureHash($signedinfo, $sha1 = false)
    {

        $pk = openssl_pkey_get_private($this->getPrivateKeyPEM(), $this->getAuskey()->getPassword());
        if (!$pk) {
            throw new Exception('Unable to access Private Key.');
        }

        $xml = $this->canonicalize($this->doc->saveXML($signedinfo));
        $signature = ''; // to be filled below

        if ($sha1) {
            $signed = openssl_sign($xml, $signature, $pk);
        } else {
            $signed = openssl_sign($xml, $signature, $pk, OPENSSL_ALGO_SHA256);
        }

        if (!$signed) {
            throw new Exception('Unable to sign the request using this Private Key.');
        }
        openssl_free_key($pk);

        return base64_encode($signature);
    }

    private function getSignatureHmacSha1($signedInfo, $key)
    {
        $xml = $this->canonicalize($this->doc->saveXML($signedInfo));
        return base64_encode(hash_hmac('sha1', $xml, $key, true));
    }

}


